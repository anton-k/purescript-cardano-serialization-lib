module Lib where

import Data.Char
import Data.Set (Set)
import Data.Set qualified as Set
import Data.List as L
import Data.List.Split (splitOn)
import Data.List.Extra (trim)
import Data.Maybe (mapMaybe)
import Data.Text qualified as T
import Data.Text.Manipulate qualified as T (toCamel, upperHead, lowerHead)

someFunc :: IO ()
someFunc = putStrLn "someFunc"

standardTypes :: Set String
standardTypes = Set.fromList
  [ "String"
  , "Boolean"
  , "Int"
  , "Effect"
  , "Number"
  , "Unit"
  , "Bytes"
  ]

file = "../cardano-serialization-lib/rust/pkg/cardano_serialization_lib.js.flow"

toFunParts :: String -> [String]
toFunParts = splitOn "\n\n"

funPrefix = "declare export function "

isFun :: String -> Bool
isFun str = length (splitOn funPrefix str) == 2

funs :: String -> [Fun]
funs = mapMaybe parseFun . toFunParts

data Arg = Arg
  { arg'name :: String
  , arg'type :: String
  }
  deriving (Show)

data Fun = Fun
  { fun'name :: String
  , fun'args :: [Arg]
  , fun'res  :: String
  }
  deriving (Show)

data Class = Class
  { class'name :: String
  , class'methods :: [Method]
  }
  deriving (Show)

data MethodType = StaticMethod | ObjectMethod
  deriving (Show)

data Method = Method
  { method'type :: MethodType
  , method'fun :: Fun
  }
  deriving (Show)

postProcTypes :: [String] -> [String]
postProcTypes = filter (not . flip Set.member standardTypes) . L.sort . L.nub

funsTypes :: [Fun] -> [String]
funsTypes fs = (\Fun{..} -> filter (all isAlphaNum) $ fun'res : (arg'type <$> fun'args)) =<< fs

classTypes :: [Class] -> [String]
classTypes xs = postProcTypes $ fromClass =<< xs
  where
    fromClass Class{..} = class'name : (funsTypes $ method'fun <$> class'methods)

typePurs :: String -> String
typePurs ty =
  unwords
    [ "foreign import data"
    , toType ty
    , ":: Type"
    ]

funPurs :: Fun -> String
funPurs (Fun name args res) =
  unwords
    [ "foreign import"
    , toName name
    , "::"
    , L.intercalate " -> " (toType . arg'type <$> args)
    , "->"
    , toType res
    ]

data FunSpec = FunSpec
  { funSpec'parent    :: String
  , funSpec'skipFirst :: Bool
  , funSpec'prefix    :: String
  , funSpec'pure     :: Bool
  }

funJs :: Fun -> String
funJs f = funJsBy (FunSpec "CSL" False "" (isPure "" f)) f

funJsBy :: FunSpec -> Fun -> String
funJsBy (FunSpec parent isSkipFirst prefix pureFun) (Fun name args res) =
  unwords
  [ "export const"
  , prefix <> toName name
  , if L.null argNames
      then "="
      else "= " <> L.intercalate " => " argNames <> " =>"
  , mconcat [parent, ".", name, "(", if L.null jsArgs then "" else (L.intercalate ", " jsArgs) ,");"]
  ]
  where
    argNames = (if pureFun then id else (<> ["()"])) argNamesIn
    argNamesIn = fmap (filter (/= '?')) $ arg'name <$> args
    jsArgs = (if isSkipFirst then tail else id) argNamesIn

classPurs :: Class -> String
classPurs (Class name ms) =
  unlines
    [ intro
    , methodDefs
    , classDef
    , valDef
    ]
  where
    intro = unlines
      [ replicate 85 '-'
      , "-- " <> toName name
      ]

    valDef = unlines
      [ unwords [valName, "::", valClassName]
      , unwords [valName, "= {", L.intercalate "," (fmap (\m -> psMethodName m <> ": " <> jsMethodName m) ms), "}"]
      ]

    classDef = (unwords
      ["type"
      , valClassName
      , "="
      , "{"
      , L.intercalate "," (fmap (\m -> psMethodName m <> " :: " <> psSig m) ms)
      , "}"
      ]) <> "\n"

    methodDefs = unlines $ fmap toDef ms
      where
        toDef m = unwords ["foreign import", jsMethodName m, "::", psSig m]

    psMethodName Method{..} = toName (fun'name method'fun)
    jsMethodName Method{..} = methodName name (fun'name method'fun)

    psSig m@Method{..} = unwords [ if L.null argTys then "" else (L.intercalate " -> " argTys <> " ->"), resTy]
      where
        argTys = (if not isObj then id else (toType name :)) $ fmap (handleVoid True . arg'type) $ fun'args $ method'fun
        resTy =
          let pureFun = isPure name method'fun
          in (if pureFun then id else ("Effect " <>)) $ handleVoid pureFun (fun'res $ method'fun)
        handleVoid pureFun str
          | isSuffixOf "| void" str = (if pureFun then id else \a -> "(" <> a <> ")") $ "Maybe " <> (toType $ head $ splitOn "|" str)
          | otherwise               = toType str

        isObj = case method'type of
          ObjectMethod -> True
          _ -> False

    valName = toTypePrefix name
    valClassName = toType name <> "Class"

indent :: String -> String
indent str = "  " <> str

classJs :: Class -> String
classJs (Class name ms) =
  unlines $ pre : (methodJs name <$> ms)
  where
    pre = "// " <> name

methodJs :: String -> Method -> String
methodJs className m = toFun m
  where
    toFun (Method ty f)
      | fun'name f == "new" = funJsBy (FunSpec ("CSL." <> className) False pre (isPure className f)) f
      | otherwise = case ty of
          StaticMethod -> funJsBy (FunSpec ("CSL." <> className) False pre (isPure className f)) f
          ObjectMethod -> funJsBy (FunSpec "self" True pre (isPure className f)) (f { fun'args = Arg "self" className : fun'args f })
    pre = toTypePrefix className <> "_"

methodName className name = toTypePrefix className <> "_" <> toName name

toTypePrefix :: String -> String
toTypePrefix = lowerHead . subst . upperHead . toCamel

toType :: String -> String
toType = subst . upperHead . toCamel

toName :: String -> String
toName = substFirst . subst . toCamel

subst :: String -> String
subst = replacesBy replace
  [("Transaction", "Tx")
  , ("Input", "In")
  , ("Output", "Out")
  , ("Uint8Array", "Bytes")
  , ("Void", "Unit")
  , ("JSON", "Js")
  ]

substFirst :: String -> String
substFirst = replacesBy replaceFirst
  [("transaction", "tx")
  , ("input", "in")
  , ("output", "out")
  ]

replaceFirst :: String -> String -> String -> String
replaceFirst from to str
  | L.isPrefixOf from str = to <> drop (length from) str
  | otherwise = str

replacesBy :: (String -> String -> String -> String) -> [(String, String)] -> String -> String
replacesBy repl = L.foldl' (\res a -> res . uncurry repl a) id

replace :: String -> String -> String -> String
replace from to = T.unpack . T.replace (T.pack from) (T.pack to) . T.pack

toCamel :: String -> String
toCamel = T.unpack . T.toCamel . T.pack

upperHead :: String -> String
upperHead = T.unpack . T.upperHead . T.pack

lowerHead :: String -> String
lowerHead = T.unpack . T.lowerHead . T.pack

parseFun :: String -> Maybe Fun
parseFun str =
  case splitOn funPrefix str of
    [_, content] -> funBody content
    _ -> Nothing

funBody :: String -> Maybe Fun
funBody content = do
  (name, rest1) <- split2 "(" content
  (args, rest2) <- split2 "):" rest1
  (res, _) <- split2 ";" rest2
  pure $ Fun (trim name) (parseArgs args) (trim res)

split2 :: String -> String -> Maybe (String, String)
split2 delim str = case splitOn delim str of
  [a, b] -> Just (a, b)
  _      -> Nothing

parseArgs :: String -> [Arg]
parseArgs str = mapMaybe parseArg $ splitOn "," str

parseArg :: String -> Maybe Arg
parseArg str =
  case splitOn ":" str of
    [a, b] -> Just $ Arg (trim a) (trim b)
    _ -> Nothing

classPrefix = "declare export class "

toClassParts = tail . splitOn classPrefix

parseClass :: String -> Class
parseClass str = Class (trim name) ms
  where
    name : rest1 = splitOn " {" (removeComments str)
    body : _ = splitOn "}" (mconcat rest1)
    ms = mapMaybe parseMethods $ fmap (<> ";") $ splitOn ";" body

parseMethods :: String -> Maybe Method
parseMethods str = toMethod <$> funBody str
  where
    toMethod x
      | L.isPrefixOf "static " (fun'name x) = Method StaticMethod (rmStaticPrefix x)
      | otherwise                           = Method ObjectMethod x

    rmStaticPrefix x = x { fun'name = drop 7 $ fun'name x }

isPure :: String -> Fun -> Bool
isPure className Fun{..} =
   fun'res /= "void" && not (dirtyMethods (className, fun'name))

dirtyMethods :: (String, String) -> Bool
dirtyMethods a = case a of
  ("TransactionBuilder", "new") -> True
  _                             -> False

removeComments :: String -> String
removeComments str = mconcat $
  case splitOn "/*" str of
    [] -> []
    a:[] -> [a]
    a:rest -> a : fmap (mconcat . tail . splitOn "*/") rest


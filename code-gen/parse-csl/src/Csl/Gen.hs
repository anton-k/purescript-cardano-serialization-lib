module Csl.Gen where

import Control.Monad (guard)
import Data.Char (isAlphaNum, isUpper, toLower)
import Data.Map (Map)
import Data.Map qualified as Map
import Data.Set (Set)
import Data.Set qualified as Set
import Data.Functor ((<&>))
import Data.List as L
import Data.List.Split (splitOn)
import Data.Maybe (mapMaybe, Maybe(Just, Nothing), listToMaybe, catMaybes)
import Data.Text qualified as T (pack, unpack, replace)
import Data.Text.Manipulate qualified as T (toCamel, upperHead, lowerHead, toTitle, toTrain)
import Data.List.Extra (trim)

import Csl.Parse
import Csl.Types

standardTypes :: Set String
standardTypes = Set.fromList
  [ "String"
  , "Boolean"
  , "Int"
  , "Effect"
  , "Number"
  , "Unit"
  , "ByteArray"
  , "Uint32Array"
  , "This"
  ]

extraExport :: [String]
extraExport =
  [ "ForeignErrorable"
  , "module X"
  ]

exportListPurs :: [Fun] -> [Class] -> String
exportListPurs funs cls =
  L.intercalate "\n  , " $
  extraExport ++
  (classMethods =<< cls) ++
  (toName . fun'name <$> funs) ++
  (fromType =<< classTypes cls)
  where
    fromType ty = [ty]
    classMethods :: Class -> [String]
    classMethods (Class name ms) = map (mappend (toTypePrefix name <> "_") . toName . fun'name . method'fun) (filter (not . isCommon . method'fun) ms)
    hasNoClass = flip Set.member hasNoClassSet
    hasNoClassSet = Set.fromList ["This", "Uint32Array"]

postProcTypes :: [String] -> [String]
postProcTypes = filter (not . flip Set.member standardTypes) . fmap toType . L.sort . L.nub

funsTypes :: [Fun] -> [String]
funsTypes fs = (\Fun{..} -> filter (all isAlphaNum) $ fun'res : (arg'type <$> fun'args)) =<< fs

classTypes :: [Class] -> [String]
classTypes xs = postProcTypes $ fromClass =<< xs
  where
    fromClass Class{..} = class'name : (funsTypes $ method'fun <$> class'methods)

typePurs :: String -> String
typePurs ty =
  unlines
    [ typeDefPurs ty
    ]

typeDefPurs :: String -> String
typeDefPurs ty
  | isJsonType ty = unwords [ "type", ty, "= Json"]
  | otherwise = unwords [ "foreign import data", ty, ":: Type" ]

isJsonType :: String -> Bool
isJsonType ty = isSuffixOf "Json" ty

funPurs :: Fun -> String
funPurs fun@(Fun name args res) =
  unlines
    [ preFunComment fun
    , unwords
        [ "foreign import"
        , funName
        , "::"
        , L.intercalate " -> " argTypeNames
        , "->"
        , toType res
        ]
    ]
  where
    funName = toName name
    argTypeNames = toType . arg'type <$> args

preFunComment = funCommentBy preComment

funCommentBy title f =
  L.intercalate "\n"
    [ title (funTitleComment f)
    , codeComment (funCodeComment f)
    ]

funTitleComment Fun{..} = toTitle fun'name
funCodeComment Fun{..} = unwords [toName fun'name, unwords argNames]
  where
    argNames = toName . arg'name <$> fun'args

codeComment :: String -> String
codeComment str = "-- > " <> str

preComment :: String -> String
preComment str = "-- | " <> str

postComment :: String -> String
postComment str = "-- ^ " <> str


data FunSpec = FunSpec
  { funSpec'parent    :: String
  , funSpec'skipFirst :: Bool
  , funSpec'prefix    :: String
  , funSpec'pureness  :: Pureness
  }

isCommon :: Fun -> Bool
isCommon (Fun "free" _ _) = True
isCommon (Fun "to_bytes" _ _) = True
isCommon (Fun "from_bytes" _ _) = True
isCommon (Fun "to_hex" _ _) = True
isCommon (Fun "from_hex" _ _) = True
isCommon (Fun "to_json" _ _) = True
isCommon (Fun "from_json" _ _) = True
isCommon (Fun "to_js_value" _ _) = True
isCommon (Fun "from_js_value" _ _) = True
-- sometimes these are with prefixes, sometimes not. they resist abstraction
-- isCommon (Fun "from_bech32" _ _) = True
-- isCommon (Fun "to_bech32" _ _) = True
isCommon (Fun "len" _ _) = True
isCommon (Fun "add" _ _) = True
isCommon (Fun "insert" _ _) = True
isCommon (Fun "get" _ _) = True
isCommon (Fun "keys" _ _) = True
isCommon (Fun _ _ _) = False

isListContainer :: Class -> Maybe String
isListContainer (Class _ methods) = do
  guard $ all (`elem` methodNames) [ "add", "len", "get" ]
  listToMaybe $ mapMaybe getElement methods
  where
    methodNames = fun'name . method'fun <$> methods
    getElement :: Method -> Maybe String
    getElement (Method _ (Fun "add" [Arg _ elemType] _)) = Just elemType
    getElement _ = Nothing

isMapContainer :: Class -> Maybe (String, String)
isMapContainer (Class _ methods) = do
  guard $ all (`elem` methodNames) [ "insert", "get", "len", "keys" ]
  listToMaybe $ mapMaybe getKeyValue methods
  where
    methodNames = fun'name . method'fun <$> methods
    getKeyValue :: Method -> Maybe (String, String)
    getKeyValue (Method _ (Fun "insert" [Arg _ keyType, Arg _ valueType] _)) =
      Just (keyType, valueType)
    getKeyValue _ = Nothing

-- process standalone functions
funJs :: Fun -> String
funJs f = funJsBy (FunSpec "CSL" False "" (getPureness "" f)) f

funJsBy :: FunSpec -> Fun -> String
funJsBy (FunSpec parent isSkipFirst prefix pureness) (Fun name args res) =
  unwords
  [ "export const"
  , prefix <> toName name
  , if L.null argNames
      then "="
      else "= " <> L.intercalate " => " argNames <> " =>"
  , withSemicolon $ mconcat $
    if pureness == Throwing
    then
      -- errorableToPurs(CSL.foo, arg1, arg2)
      [ "errorableToPurs("
      , parent
      , "."
      , name
      , ", "
      , L.intercalate ", " jsArgs
      , ")"
      ]
    else
      -- CSL.foo(arg1, arg2)
      [ parent
      , "."
      , name
      , "("
      , L.intercalate ", " jsArgs
      , ")"
      ]
  ]
  where
    -- if a function is mutating, we add another function wrapper that represents
    -- PureScript's `Effect` at runtime
    argNames = (if pureness == Mutating then (<> ["()"]) else id) argNamesIn
    argNamesIn = fmap (filter (/= '?')) $ arg'name <$> args
    jsArgs = (if isSkipFirst then tail else id) argNamesIn

withSemicolon :: String -> String
withSemicolon = flip mappend ";"

data HandleNulls = UseNullable | UseMaybe

commonInstances :: Class -> String
commonInstances (Class name methods) = unlines $
  [ "instance IsCsl " <> name <> " where\n  className _ = \"" <> name <> "\"" ] <>
  (if hasInstanceMethod "to_bytes" && hasInstanceMethod "from_bytes"
   then [ "instance IsBytes " <> name ]
   else []) <>
  (if hasInstanceMethod "to_json" && hasInstanceMethod "from_json"
   then [ "instance IsJson " <> name
        , "instance EncodeAeson " <> name <> " where encodeAeson = cslToAeson"
        , "instance DecodeAeson " <> name <> " where decodeAeson = cslFromAeson"
        ]
   else [])
  where
    hasInstanceMethod str = Set.member str methodNameSet
    methodNameSet = Set.fromList $ fun'name . method'fun <$> methods

containerInstances :: Class -> Maybe String
containerInstances cls@(Class name _) =
  fmap unlines $
  notEmptyList $
  catMaybes
  [ isListContainer cls <&> \elemType ->
    "instance IsListContainer " <> unwords [ name, elemType ]
  , isMapContainer cls <&> \(keyType, valueType) ->
      "instance IsMapContainer " <> unwords [ name, keyType, valueType ]
  ]
  where
    notEmptyList :: [a] -> Maybe [a]
    notEmptyList [] = Nothing
    notEmptyList xs = Just xs

classPurs :: Class -> String
classPurs cls@(Class name ms) = mappend "\n" $
  L.intercalate "\n\n" $ fmap trim
    [ intro
    , typePurs name
    , methodDefs
    , instances
    ]
  where
    filteredClass = Class name $ filter (not . isCommon . method'fun) ms
    isNullType ty = elem '?' ty || isSuffixOf "| void" ty

    intro = unlines
      [ replicate 85 '-'
      , "-- " <> toTitle name
      ]

    valDef = unlines
      [ preComment $ unwords [toTitle name, "class API"]
      , unwords [valName, "::", valClassName]
      , unwords [valName, "="]
      , recordDef (fmap (\m -> psMethodName m <> ": " <> valMethodDef m) ms)
      ]
      where
        valMethodDef m
          | hasMaybes m = jsMaybeMethodName m
          | hasThrow m  = jsThrowMethodName m
          | otherwise   = jsMethodName m

        hasThrow Method{..} = canThrow name (fun'name method'fun)

        hasMaybes Method{..} = any isNullType types
          where
            types = fun'res method'fun : (arg'type <$> fun'args method'fun)

    methodComment m@Method{..} body = L.intercalate "\n"
      [ body
      , indent $ indent $ trim $ mapLines (indent . indent) $ postFunComment (withSelf name m)
      ]

    classDef =
      unlines
        [ preComment $ unwords [toTitle name, "class"]
        , unwords ["type", valClassName, "="]
        , recordDef (fmap (\m -> methodComment m $ psMethodName m <> " :: " <> psSig UseNullable m) ms)
        ]

    recordDef = \case
      [] -> "{}"
      a:as -> unlines [indent $ "{ " <> a, unlines (fmap (indent . (", " <>)) as) <> indent "}" ]

    methodDefs = unlines $ fmap toDef $ filter (not . isCommon . method'fun) ms
      where
        toDef m = unwords ["foreign import", jsMethodName m, "::", psSig UseNullable m]

    psMethodName Method{..} = toName (fun'name method'fun)
    jsMethodName Method{..} = methodName name (fun'name method'fun)

    jsMaybeMethodName m@Method{..} = toLam (toArgName <$> args) res
      where
        toArgName (n, _) = 'a' : show n
        res = fromNullableRes (fun'res method'fun) $ unwords $ jsMethodName m : fmap fromArg args
        args = zip [1..] $ addOnObj $ fun'args method'fun

        addOnObj
          | isObj m   = (Arg (toName name) (toType name) :)
          | otherwise = id

        isPureMethod = isPure name method'fun
        isDirtyMethod = not isPureMethod

        fromNullableRes resTy
          | isNullType resTy && isPureMethod  = mappend "Nullable.toMaybe $ "
          | isNullType resTy && isDirtyMethod = mappend "Nullable.toMaybe <$> "
          | otherwise                         = id

        fromArg arg@(_, Arg{..})
          | isNullType arg'type = "(" <> "Nullable.toNullable " <> toArgName arg <> ")"
          | otherwise           = toArgName arg

    jsThrowMethodName m@Method{..} = toLam (toArgName <$> args) res
      where
        toArgName (n, _) = 'a' : show n
        args = zip [1..] $ addOnObj $ fun'args method'fun

        addOnObj
          | isObj m   = (Arg (toName name) (toType name) :)
          | otherwise = id

        res = fromThrowRes (fun'res method'fun) $ unwords $ jsMethodName m : fmap toArgName args
        isPureMethod = isPure name method'fun

        fromThrowRes resTy
          | isPureMethod = mappend "runForeignMaybe $ "
          | otherwise    = mappend "runForeignMaybe <$> "

    psSig nullType m@Method{..} = trim $ unwords [ if L.null argTys then "" else (L.intercalate " -> " argTys <> " ->"), resTy]
      where
        addTypePrefix pref x
          | length (words x) > 1 = unwords [pref, "(" <> x <> ")"]
          | otherwise            = unwords [pref, x]

        argTys = handleNumArgs $ (if not (isObj m) then id else (toType name :)) $ fmap (handleVoid True . arg'type) $ fun'args $ method'fun
        resTy =
          let pureFun = isPure name method'fun
          in (if pureFun then id else addTypePrefix "Effect") $ handleThrows $ handleVoid pureFun $ handleNumRes (fun'res $ method'fun)

        handleThrows
          | canThrow name (fun'name method'fun) = addTypePrefix ty
          | otherwise                           = id
          where
            ty = case nullType of
              UseNullable -> "Nullable"
              _           -> "Maybe"

        fromNullType = \case
          UseNullable -> "Nullable"
          UseMaybe -> "Maybe"

        handleVoid pureFun str
          | isSuffixOf "| void" str = (if pureFun then id else \a -> "(" <> a <> ")") $ fromNullType nullType <> " " <> (toType $ head $ splitOn "|" str)
          | otherwise               = toType str

        handleNumArgs =
          case Map.lookup (name, fun'name method'fun) intPos of
            Just subs -> substIntArgs subs . zip [0..]
            Nothing -> id

        handleNumRes =
          case Map.lookup (name, fun'name method'fun) intPos of
            Just subs -> substIntRes subs
            Nothing   -> id

    isObj Method{..} = case method'type of
      ObjectMethod -> True
      _ -> False

    valName = toTypePrefix name
    valClassName = toType name <> "Class"

    instances
      | name == "Int" = ""
      | otherwise = unlines $ catMaybes $
        [ Just $ commonInstances cls
        , containerInstances cls
        ]

    proxyMethod str = unwords [str, "=", valName <> "." <> str]

    hasInstanceMethod str = Set.member str methodNameSet

      -- | hasInstanceMethod "to_str" = with "to_str"
      -- | hasInstanceMethod "to_hex" = with "to_hex"
      -- | hasInstanceMethod "to_bech32" && getArgNum "to_bech32" == Just 0 = with "to_bech32"
      -- | otherwise = Nothing
      -- where
      --   with name =Just $ toInst "Show" [instMethod "show" name]


    mutListInst :: Maybe String
    mutListInst = fmap go $ Map.lookup name listTypeMap
      where
        go key =
          unlines
            [ toInst2 "MutableList" (toType key)
                [ instMethod "addItem" "add"
                , instMethod "getItem" "get"
                , instMethod "emptyList" "new"
                ]
            , toInst "MutableLen" [ instMethod "getLen" "len" ]
            ]

    instMethod :: String -> String -> String
    instMethod name1 name2 = unwords [toName name1, "=", valName <> "_" <> toName name2]

    toJsValueInst
      | hasInstanceMethod "to_js_value" = Just $ toInst "ToJsValue" [proxyMethod $ toName "to_js_value"]
      | otherwise = Nothing

    getArgNum name = fmap (length . fun'args) $ L.find ((== name) . fun'name) $ method'fun <$> ms


    methodNameSet = Set.fromList $ fun'name . method'fun <$> ms

    toInst cls funs = unlines $
      (unwords ["instance", cls, toType name, "where"]) : fmap indent funs

    toInst2 cls name2 funs = unlines $
      (unwords ["instance", cls, toType name, toType name2, "where"]) : fmap indent funs


toLam :: [String] -> String -> String
toLam args res = "\\" <> unwords args <> " -> " <> res

-- | We assume that subst and args are sorted
substIntArgs :: [SigPos] -> [(Int, String)] -> [String]
substIntArgs ps args =
  case ps of
    [] -> fmap snd args
    ResPos : _ -> fmap snd args
    ArgPos n : restPos ->
      case args of
        [] -> []
        (m, arg) : restArgs | n == m -> substInt arg : substIntArgs restPos restArgs
        (_, arg) : restArgs -> arg : substIntArgs (ArgPos n : restPos) restArgs


substIntRes :: [SigPos] -> String -> String
substIntRes = \case
  [] -> id
  ResPos : _ -> substInt
  _ : rest -> substIntRes rest

substInt :: String -> String
substInt = replace "Number" "Int" . replace "number" "int"

mapLines f = unlines . map f . lines

indent :: String -> String
indent str = "  " <> str

classJs :: Class -> String
classJs (Class name ms) =
  unlines $ pre : (methodJs name <$> filter (not . isCommon . method'fun) ms)
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

withSelf :: String -> Method -> Fun
withSelf className Method{..} = case method'type of
  StaticMethod -> method'fun
  ObjectMethod -> method'fun { fun'args = Arg "self" className : fun'args method'fun }

methodName className name = toTypePrefix className <> "_" <> toName name

toTypePrefix :: String -> String
toTypePrefix = lowerHead . subst . upperHead . toCamel

toType :: String -> String
toType = subst . upperHead . toCamel

toName :: String -> String
toName = lowerHead . substFirst . subst . toCamel

subst :: String -> String
subst = replacesBy replace
  [ ("Uint8Array", "ByteArray")
  , ("Void", "Unit")
  , ("JSON", "Json")
  ]

substFirst :: String -> String
substFirst = replacesBy replaceFirst
  [
  ]

replaceFirst :: String -> String -> String -> String
replaceFirst from to str
  | L.isPrefixOf from str = to <> drop (length from) str
  | otherwise = str

replacesBy :: (String -> String -> String -> String) -> [(String, String)] -> String -> String
replacesBy repl = L.foldl' (\res a -> res . uncurry repl a) id

replace :: String -> String -> String -> String
replace from to = T.unpack . T.replace (T.pack from) (T.pack to) . T.pack

wrapText f = T.unpack . f . T.pack

toTitle = unwords . go . words . wrapText T.toTitle
  where
    go = \case
      [] -> []
      a:as -> a : fmap lowerHead as

toCamel :: String -> String
toCamel = wrapText T.toCamel

upperHead :: String -> String
upperHead = wrapText T.upperHead

lowerHead :: String -> String
lowerHead str
  | L.null post = fmap toLower str
  | otherwise =
    case pre of
        [] -> wrapText T.lowerHead post
        [a] -> toLower a : post
        _  -> map toLower (init pre) <> [last pre] <> post
  where
    (pre, post) = span isUpper str

isPure :: String -> Fun -> Bool
isPure className Fun{..} =
   fun'res /= "void" && not (dirtyClass className || dirtyMethods (className, fun'name))
   || isConvertor fun'name
   where
    isConvertor a = Set.member a convertorSet

convertorSet = Set.fromList $ (\x -> fmap (<> x ) ["to_", "from_"]) =<<
  ["hex", "string", "bytes", "bech32", "json", "js_value"]

dirtyMethods :: (String, String) -> Bool
dirtyMethods a = Set.member a dirties

dirtyClass a = Set.member a dirtyClassSet

dirtyClassSet :: Set String
dirtyClassSet = Set.fromList
  [ "TransactionBuilder"
  , "TransactionWitnessSet"
  , "TransactionWitnessSets"
  , "TxInputsBuilder"
  ]

listTypeMap :: Map String String
listTypeMap = Map.fromList listTypes

listTypes :: [(String, String)]
listTypes =
    [ ("AssetNames", "AssetName")
    , ("BootstrapWitnesses", "BootstrapWitness")
    , ("Certificates", "Certificate")
    , ("GenesisHashes", "GenesisHash")
    , ("Languages", "Language")
    , ("MetadataList", "TransactionMetadatum")
    , ("NativeScripts", "NativeScript")
    , ("PlutusList", "PlutusData")
    , ("PlutusScripts", "PlutusScript")
    , ("PlutusWitnesses", "PlutusWitness")
    , ("Redeemers", "Redeemer")
    , ("Relays", "Relay")
    , ("RewardAddresses", "RewardAddress")
    , ("ScriptHashes", "ScriptHash")
    , ("StakeCredentials", "StakeCredential")
    , ("Strings", "String")
    , ("TransactionBodies", "TransactionBody")
    , ("TransactionInputs", "TransactionInput")
    , ("TransactionOutputs", "TransactionOutput")
    , ("TransactionUnspentOutputs", "TransactionUnspentOutput")
    , ("TransactionMetadatumLabels", "BigNum")
    , ("Vkeys", "Vkey")
    , ("Vkeywitnesses", "Vkeywitness")
    ]

dirties :: Set (String, String)
dirties =
  mconcat $
    [ keys "Assets"
    , inClass "TransactionBuilder" ["new"]
    , inClass "AuxiliaryData" ["new", "native_scripts", "plutus_scripts"]
    , inClass "AuxiliaryDataSet" ["new", "insert", "get", "indices"]
    , newSetGet "CostModel"
    , keys "Costmdls"
    , keys "GeneralTransactionMetadata"
    , keys "MIRToStakeCredentials"
    , inClass "MetadataMap" ["new", "insert", "insert_str", "insert_i32", "get", "get_str", "get_i32", "has", "keys"]
    , keys "Mint" <> inClass "Mint" ["new_from_entry", "as_positive_multiasset", "as_negative_multiasset"]
    , keys "MintAssets"
    , inClass "MultiAsset" ["new", "len", "inset", "get", "get_asset", "set_asset", "keys", "sub"]
    , keys "PlutusMap"
    , keys "ProposedProtocolParameterUpdates"
    , keys "Withdrawals"
    ] ++ map (list . fst) listTypes
  where
    inClass name ms = Set.fromList $ fmap (name, ) ms
    list name = inClass name ["new", "get", "add", "len"]
    newSetGet name = inClass name ["new", "set", "get", "len"]
    keys name = inClass name ["new", "insert", "get", "keys", "len"]

-- | Position of the type in the signature
data SigPos = ResPos | ArgPos Int

instance Num SigPos where
  fromInteger = ArgPos . fromInteger

-- | Which numbers should be treated as Int's.
-- Position is in the Purs signature (with extended object methods)
intPos :: Map (String, String) [SigPos]
intPos =
  mconcat $
    [ inClass "BigNum"
        [ ("compare", [ResPos])
        ]
    , len "Assets"
    , lenGetInsert "AuxiliaryDataSet"
    , len "CostModel"
    , lenSetGet "CostModel"
    , len "Costmdls"
    , len "GeneralTransactionMetadata"
    , inClass "HeaderBody"
        [ resPos "block_number"
        , resPos "slot"
        , resPos "block_body_size"
        , ("new", [0, 1, 6])
        , ("new_header_body", [0, 6])
        ]
    , len "MetadataMap"
    , len "Mint"
    , len "MintAssets"
    , len "MultiAsset"
    , len "PlutusMap"
    , len "ProposedProtocolParameterUpdates"
    , inClass "TransactionBuilderConfigBuilder" [argPos "max_value_size" 1, argPos "max_tx_size" 1]
    , len "Withdrawals"
    , inClass "Value" [resPos "compare"]
    , inClass "Address" [resPos "network_id"]
    , inClass "ByronAddress" [resPos "network_id"]
    ] ++ map (list . fst) listTypes
  where
    resPos name = (name, [ResPos])
    argPos name n = (name, [ArgPos n])

    inClass name ms = Map.fromList $ fmap (\(a, b) -> ((name, a), b)) ms

    len name =
      inClass name
        [ ("len", [ResPos])
        ]

    list name =
      inClass name
        [ ("get", [1])
        , ("len", [ResPos])
        ]

    lenGetInsert name =
      inClass name
        [ ("insert", [1])
        , ("get", [1])
        , ("len", [ResPos])
        ]
    lenSetGet name =
      inClass name
        [ ("len", [ResPos])
        , ("set", [1])
        , ("get", [1])
        ]

-- | Is function pure and can throw (in this case we can catch it to Maybe on purs side)
-- if it's global function use empty name for class
canThrow :: String -> String -> Bool
canThrow _className methodName = Set.member methodName froms
  where
    froms = Set.fromList ["from_hex", "from_bytes", "from_bech32", "from_json", "from_str"]

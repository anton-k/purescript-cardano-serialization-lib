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
    classMethods cls@(Class name ms) =
      map (mappend (toTypePrefix name <> "_") . toName . fun'name . method'fun)
        $ filterMethods cls
    hasNoClass = flip Set.member hasNoClassSet
    hasNoClassSet = Set.fromList ["This", "Uint32Array"]

-- Remove standard types and transform case
postProcTypes :: [String] -> [String]
postProcTypes = filter (not . flip Set.member standardTypes) . fmap toType . L.sort . L.nub

funsTypes :: [Fun] -> [String]
funsTypes fs = (\Fun{..} -> filter (all isAlphaNum) $ fun'res : (arg'type <$> fun'args)) =<< fs

classTypes :: [Class] -> [String]
classTypes xs = postProcTypes $ fromClass =<< xs
  where
    fromClass Class{..} = [class'name]

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
      , if parent == "self" then ".bind(self)" else ""
      , ", "
      , L.intercalate ", " jsArgs
      , ")"
      ]
    else
      -- CSL.foo(arg1, arg2)
      [ parent
      , "."
      , name
      , if parent == "self" then ".bind(self)" else ""
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
  (if hasBytes
   then [ "instance IsBytes " <> name ]
   else []) <>
  (if hasJson
   then
      [ "instance IsJson " <> name
      , "instance EncodeAeson " <> name <> " where encodeAeson = cslToAeson"
      , "instance DecodeAeson " <> name <> " where decodeAeson = cslFromAeson"
      , "instance Show " <> name <> " where show = showViaJson"
      ]
   else
     if hasBytes
     then
       [ "instance EncodeAeson " <> name <> " where encodeAeson = cslToAesonViaBytes"
       , "instance DecodeAeson " <> name <> " where decodeAeson = cslFromAesonViaBytes"
       , "instance Show " <> name <> " where show = showViaBytes"
       ]
     else []
  )
  where
    hasBytes =  hasInstanceMethod "to_bytes" && hasInstanceMethod "from_bytes"
    hasJson = hasInstanceMethod "to_json" && hasInstanceMethod "from_json"
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

classPurs :: Class -> String
classPurs cls@(Class name ms) = mappend "\n" $
  L.intercalate "\n\n" $ fmap trim
    [ intro
    , typePurs name
    , methodDefs
    , instances
    ]
  where
    filteredMethods = filterMethods cls
    filteredClass = Class name filteredMethods
    isNullType ty = elem '?' ty || isSuffixOf "| void" ty

    intro = unlines
      [ replicate 85 '-'
      , "-- " <> toTitle name
      ]

    recordDef = \case
      [] -> "{}"
      a:as -> unlines [indent $ "{ " <> a, unlines (fmap (indent . (", " <>)) as) <> indent "}" ]

    methodDefs = unlines $ fmap toDef $ filteredMethods
      where
        toDef m = unwords ["foreign import", jsMethodName m, "::", psSig UseNullable m]

    jsMethodName Method{..} = methodName name (fun'name method'fun)

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
          in (case getPureness name method'fun of
                Pure -> id
                Mutating -> addTypePrefix "Effect"
                Throwing -> addTypePrefix "Nullable"
             ) $ handleVoid pureFun $ handleNumRes (fun'res $ method'fun)

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

    instances = unlines $ catMaybes $
      [ Just $ commonInstances cls
      , containerInstances cls
      ]

    proxyMethod str = unwords [str, "=", valName <> "." <> str]

    hasInstanceMethod str = Set.member str methodNameSet

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

filterMethods :: Class -> [Method]
filterMethods (Class name ms)
  | name `elem` ["PublicKey", "PrivateKey"] = ms -- these types need special handling
  | otherwise = filter (not . isCommon . method'fun) ms

classJs :: Class -> String
classJs cls@(Class name ms) =
  unlines $ pre : (methodJs name <$> filterMethods cls)
  where
    pre = "// " <> name

methodJs :: String -> Method -> String
methodJs className m = toFun m
  where
    toFun (Method ty f) = case ty of
      StaticMethod ->
        funJsBy (FunSpec ("CSL." <> className) False pre (getPureness className f)) f
      ObjectMethod ->
        funJsBy (FunSpec "self" True pre (getPureness className f)) (f { fun'args = Arg "self" className : fun'args f })
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

data Pureness = Pure | Mutating | Throwing
  deriving (Eq, Show)

getPureness :: String -> Fun -> Pureness
getPureness className Fun{..}
  | isConvertor fun'name = Pure
  | take 4 fun'name == "set_" = Mutating
  | fun'res == "void" = Throwing
  | isMutating && not isThrowing = Mutating
  | not isMutating && not isThrowing = Pure
  | otherwise = Throwing
   where
     isMutating = dirtyClass className || mutatingMethods (className, fun'name)
     isThrowing = Set.member (className, fun'name) throwingSet || isCommonThrowingMethod fun'name
     isConvertor a = Set.member a convertorSet

isPure :: String -> Fun -> Bool
isPure className fun =
  getPureness className fun == Pure

convertorSet = Set.fromList $ (\x -> fmap (<> x ) ["to_"]) =<<
  ["hex", "string", "bytes", "bech32", "json", "js_value"]

mutatingMethods :: (String, String) -> Bool
mutatingMethods a = Set.member a mutating

dirtyClass a = Set.member a mutatingClassSet

mutatingClassSet :: Set String
mutatingClassSet = Set.fromList
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

throwingSet :: Set (String, String)
throwingSet = mconcat $
  [ inClass "BigNum"
    [ "checked_mul"
    , "checked_add"
    , "checked_sub"
    ]
  , inClass "Value"
    [ "checked_add"
    , "checked_sub"
    ]
  , inClass "PublicKey"
    [ "from_bytes" ]
  , inClass "PrivateKey"
    [ "from_normal_bytes" ]
  , inClass "ByronAddress"
    [ "from_base58" ]
  ]
  where
    inClass name ms = Set.fromList $ fmap (name, ) ms

mutating :: Set (String, String)
mutating =
  mconcat $
    [ keys "Assets"
    , inClass "TransactionBuilder" ["new"]
    , inClass "AuxiliaryData"
      [ "new", "set_native_scripts", "set_plutus_scripts", "set_metadata", "set_prefer_alonzo_format" ]
    , inClass "AuxiliaryDataSet" ["new", "insert", "get", "indices"]
    , newSetGet "CostModel"
    , keys "Costmdls"
    , keys "GeneralTransactionMetadata"
    , keys "MIRToStakeCredentials"
    , inClass "MetadataMap" ["new", "insert", "insert_str", "insert_i32", "get", "get_str", "get_i32", "has", "keys"]
    , keys "Mint" <> inClass "Mint" ["new_from_entry", "as_positive_multiasset", "as_negative_multiasset"]
    , keys "MintAssets"
    , inClass "MultiAsset" ["new", "len", "inset", "get", "get_asset", "set_asset", "keys", "sub"]
    , inClass "Value" ["set_multiasset"]
    , inClass "TransactionOutput" ["set_data_hash", "set_plutus_data", "set_script_ref"]
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
intPos = mempty

-- | Is function pure and can throw (in this case we can catch it to Maybe on purs side)
-- if it's global function use empty name for class
isCommonThrowingMethod :: String -> Bool
isCommonThrowingMethod methodName = Set.member methodName froms
  where
    froms = Set.fromList
      [ "from_hex"
      , "from_bytes"
      , "from_normal_bytes"
      , "from_extended_bytes"
      , "from_bech32"
      , "from_json"
      , "from_str"
      ]

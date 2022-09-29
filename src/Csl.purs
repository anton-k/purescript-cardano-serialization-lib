-- | Common CSL types and functions that can be work as if they are pure
--
-- Missing parts
--  * generate standard instances: fromHex toHex etc
--  * define Bytes interchangeable with Uint8Array
--  * generate JSON types and convertions
--  * should we use safer versions with Maybe for partial functions?
--  * inspect functions for Effectrful ones
module Csl where

import Prelude
import Data.Int (floor)
import Data.ArrayBuffer.Types (Uint8Array)
import Effect (Effect)
import Data.Maybe (Maybe)

----------------------------------------------------------------------------
-- utils

type Bytes = Uint8Array

fromCompare :: Number -> Ordering
fromCompare n
  | n < 0.0 = LT
  | n > 0.0 = GT
  | otherwise = EQ

----------------------------------------------------------------------------
-- classes

class IsHex a where
  toHex :: a -> String
  fromHex :: String -> a

class IsBech32 a where
  toBech32 :: a -> String
  fromBech32 :: String -> a

class IsJson a where
  toJson :: a -> String
  fromJson :: String -> a

class ToJsValue a b | a -> b where
  toJsValue :: a -> b

class IsBytes a where
  toBytes :: a -> Bytes
  fromBytes :: Bytes -> a

----------------------------------------------------------------------------
-- numbers

-- BigNum

instance Show BigNum where
  show = bigNum.toStr

instance IsHex BigNum where
  toHex = bigNum.toHex
  fromHex = bigNum.fromHex

instance Semiring BigNum where
  add = bigNum.checkedAdd
  mul = bigNum.checkedMul
  one = bigNum.one
  zero = bigNum.zero

instance Ring BigNum where
  sub = bigNum.checkedSub

instance CommutativeRing BigNum

instance Eq BigNum where
  eq a b = floor (bigNum.compare a b) == 0

instance Ord BigNum where
  compare a b = fromCompare (bigNum.compare a b)

-- BigInt

instance Show BigInt where
  show = bigInt.toStr

instance IsHex BigInt where
  toHex = bigInt.toHex
  fromHex = bigInt.fromHex

instance Semiring BigInt where
  add = bigInt.add
  mul = bigInt.mul
  one = bigInt.one
  zero = bigInt.fromHex "zero undefined"

----------------------------------------------------------------------------
-- functions

foreign import minFee :: Tx -> LinearFee -> BigNum
foreign import calculateExUnitsCeilCost :: ExUnits -> ExUnitPrices -> BigNum
foreign import minScriptFee :: Tx -> ExUnitPrices -> BigNum
foreign import encryptWithPassword :: String -> String -> String -> String -> String
foreign import decryptWithPassword :: String -> String -> String
foreign import makeDaedalusBootstrapWitness :: TxHash -> ByronAddress -> LegacyDaedalusPrivateKey -> BootstrapWitness
foreign import makeIcarusBootstrapWitness :: TxHash -> ByronAddress -> Bip32PrivateKey -> BootstrapWitness
foreign import makeVkeyWitness :: TxHash -> PrivateKey -> Vkeywitness
foreign import hashAuxiliaryData :: AuxiliaryData -> AuxiliaryDataHash
foreign import hashTx :: TxBody -> TxHash
foreign import hashPlutusData :: PlutusData -> DataHash
foreign import hashScriptData :: Redeemers -> Costmdls -> PlutusList -> ScriptDataHash
foreign import getImplicitIn :: TxBody -> BigNum -> BigNum -> Value
foreign import getDeposit :: TxBody -> BigNum -> BigNum -> BigNum
foreign import minAdaForOut :: TxOut -> DataCost -> BigNum
foreign import minAdaRequired :: Value -> Boolean -> BigNum -> BigNum
foreign import encodeJsonStrToNativeScript :: String -> String -> Number -> NativeScript
foreign import encodeJsonStrToPlutusDatum :: String -> Number -> PlutusData
foreign import decodePlutusDatumToJsonStr :: PlutusData -> Number -> String
foreign import encodeArbitraryBytesAsMetadatum :: Bytes -> TxMetadatum
foreign import decodeArbitraryBytesFromMetadatum :: TxMetadatum -> Bytes
foreign import encodeJsonStrToMetadatum :: String -> Number -> TxMetadatum
foreign import decodeMetadatumToJsonStr :: TxMetadatum -> Number -> String

----------------------------------------------------------------------------
-- types / classes

foreign import data Address :: Type
foreign import data AddressJs :: Type
foreign import data AssetName :: Type
foreign import data AssetNameJs :: Type
foreign import data AssetNames :: Type
foreign import data AssetNamesJs :: Type
foreign import data Assets :: Type
foreign import data AssetsJs :: Type
foreign import data AuxiliaryData :: Type
foreign import data AuxiliaryDataHash :: Type
foreign import data AuxiliaryDataJs :: Type
foreign import data AuxiliaryDataSet :: Type
foreign import data BaseAddress :: Type
foreign import data BigInt :: Type
foreign import data BigIntJs :: Type
foreign import data BigNum :: Type
foreign import data BigNumJs :: Type
foreign import data Bip32PrivateKey :: Type
foreign import data Bip32PublicKey :: Type
foreign import data Block :: Type
foreign import data BlockHash :: Type
foreign import data BlockJs :: Type
foreign import data BootstrapWitness :: Type
foreign import data BootstrapWitnessJs :: Type
foreign import data BootstrapWitnesses :: Type
foreign import data ByronAddress :: Type
foreign import data Certificate :: Type
foreign import data CertificateJs :: Type
foreign import data Certificates :: Type
foreign import data CertificatesJs :: Type
foreign import data ConstrPlutusData :: Type
foreign import data ConstrPlutusDataJs :: Type
foreign import data CostModel :: Type
foreign import data CostModelJs :: Type
foreign import data Costmdls :: Type
foreign import data CostmdlsJs :: Type
foreign import data DNSRecordAorAAAA :: Type
foreign import data DNSRecordAorAAAAJs :: Type
foreign import data DNSRecordSRV :: Type
foreign import data DNSRecordSRVJs :: Type
foreign import data DataCost :: Type
foreign import data DataHash :: Type
foreign import data DatumSource :: Type
foreign import data Ed25519KeyHash :: Type
foreign import data Ed25519KeyHashes :: Type
foreign import data Ed25519KeyHashesJs :: Type
foreign import data Ed25519Signature :: Type
foreign import data EnterpriseAddress :: Type
foreign import data ExUnitPrices :: Type
foreign import data ExUnitPricesJs :: Type
foreign import data ExUnits :: Type
foreign import data ExUnitsJs :: Type
foreign import data GeneralTxMetadata :: Type
foreign import data GeneralTxMetadataJs :: Type
foreign import data GenesisDelegateHash :: Type
foreign import data GenesisHash :: Type
foreign import data GenesisHashes :: Type
foreign import data GenesisHashesJs :: Type
foreign import data GenesisKeyDelegation :: Type
foreign import data GenesisKeyDelegationJs :: Type
foreign import data Header :: Type
foreign import data HeaderBody :: Type
foreign import data HeaderBodyJs :: Type
foreign import data HeaderJs :: Type
foreign import data IntJs :: Type
foreign import data Ipv4 :: Type
foreign import data Ipv4Js :: Type
foreign import data Ipv6 :: Type
foreign import data Ipv6Js :: Type
foreign import data KESSignature :: Type
foreign import data KESVKey :: Type
foreign import data Language :: Type
foreign import data LanguageJs :: Type
foreign import data Languages :: Type
foreign import data LegacyDaedalusPrivateKey :: Type
foreign import data LinearFee :: Type
foreign import data MIRToStakeCredentials :: Type
foreign import data MIRToStakeCredentialsJs :: Type
foreign import data MetadataList :: Type
foreign import data MetadataMap :: Type
foreign import data Mint :: Type
foreign import data MintAssets :: Type
foreign import data MintJs :: Type
foreign import data MoveInstantaneousReward :: Type
foreign import data MoveInstantaneousRewardJs :: Type
foreign import data MoveInstantaneousRewardsCert :: Type
foreign import data MoveInstantaneousRewardsCertJs :: Type
foreign import data MultiAsset :: Type
foreign import data MultiAssetJs :: Type
foreign import data MultiHostName :: Type
foreign import data MultiHostNameJs :: Type
foreign import data NativeScript :: Type
foreign import data NativeScriptJs :: Type
foreign import data NativeScripts :: Type
foreign import data NetworkId :: Type
foreign import data NetworkIdJs :: Type
foreign import data NetworkInfo :: Type
foreign import data Nonce :: Type
foreign import data NonceJs :: Type
foreign import data OperationalCert :: Type
foreign import data OperationalCertJs :: Type
foreign import data PlutusData :: Type
foreign import data PlutusDataJs :: Type
foreign import data PlutusList :: Type
foreign import data PlutusListJs :: Type
foreign import data PlutusMap :: Type
foreign import data PlutusMapJs :: Type
foreign import data PlutusScript :: Type
foreign import data PlutusScriptSource :: Type
foreign import data PlutusScripts :: Type
foreign import data PlutusScriptsJs :: Type
foreign import data PlutusWitness :: Type
foreign import data PlutusWitnesses :: Type
foreign import data Pointer :: Type
foreign import data PointerAddress :: Type
foreign import data PoolMetadata :: Type
foreign import data PoolMetadataHash :: Type
foreign import data PoolMetadataJs :: Type
foreign import data PoolParams :: Type
foreign import data PoolParamsJs :: Type
foreign import data PoolRegistration :: Type
foreign import data PoolRegistrationJs :: Type
foreign import data PoolRetirement :: Type
foreign import data PoolRetirementJs :: Type
foreign import data PrivateKey :: Type
foreign import data ProposedProtocolParameterUpdates :: Type
foreign import data ProposedProtocolParameterUpdatesJs :: Type
foreign import data ProtocolParamUpdate :: Type
foreign import data ProtocolParamUpdateJs :: Type
foreign import data ProtocolVersion :: Type
foreign import data ProtocolVersionJs :: Type
foreign import data PublicKey :: Type
foreign import data PublicKeys :: Type
foreign import data Redeemer :: Type
foreign import data RedeemerJs :: Type
foreign import data RedeemerTag :: Type
foreign import data RedeemerTagJs :: Type
foreign import data Redeemers :: Type
foreign import data RedeemersJs :: Type
foreign import data Relay :: Type
foreign import data RelayJs :: Type
foreign import data Relays :: Type
foreign import data RelaysJs :: Type
foreign import data RewardAddress :: Type
foreign import data RewardAddresses :: Type
foreign import data RewardAddressesJs :: Type
foreign import data ScriptAll :: Type
foreign import data ScriptAllJs :: Type
foreign import data ScriptAny :: Type
foreign import data ScriptAnyJs :: Type
foreign import data ScriptDataHash :: Type
foreign import data ScriptHash :: Type
foreign import data ScriptHashes :: Type
foreign import data ScriptHashesJs :: Type
foreign import data ScriptNOfK :: Type
foreign import data ScriptNOfKJs :: Type
foreign import data ScriptPubkey :: Type
foreign import data ScriptPubkeyJs :: Type
foreign import data ScriptRef :: Type
foreign import data ScriptRefJs :: Type
foreign import data SingleHostAddr :: Type
foreign import data SingleHostAddrJs :: Type
foreign import data SingleHostName :: Type
foreign import data SingleHostNameJs :: Type
foreign import data StakeCredential :: Type
foreign import data StakeCredentialJs :: Type
foreign import data StakeCredentials :: Type
foreign import data StakeCredentialsJs :: Type
foreign import data StakeDelegation :: Type
foreign import data StakeDelegationJs :: Type
foreign import data StakeDeregistration :: Type
foreign import data StakeDeregistrationJs :: Type
foreign import data StakeRegistration :: Type
foreign import data StakeRegistrationJs :: Type
foreign import data Strings :: Type
foreign import data TimelockExpiry :: Type
foreign import data TimelockExpiryJs :: Type
foreign import data TimelockStart :: Type
foreign import data TimelockStartJs :: Type
foreign import data Tx :: Type
foreign import data TxBodies :: Type
foreign import data TxBodiesJs :: Type
foreign import data TxBody :: Type
foreign import data TxBodyJs :: Type
foreign import data TxBuilder :: Type
foreign import data TxBuilderConfig :: Type
foreign import data TxBuilderConfigBuilder :: Type
foreign import data TxHash :: Type
foreign import data TxIn :: Type
foreign import data TxInJs :: Type
foreign import data TxIns :: Type
foreign import data TxInsJs :: Type
foreign import data TxJs :: Type
foreign import data TxMetadatum :: Type
foreign import data TxMetadatumLabels :: Type
foreign import data TxOut :: Type
foreign import data TxOutAmountBuilder :: Type
foreign import data TxOutBuilder :: Type
foreign import data TxOutJs :: Type
foreign import data TxOuts :: Type
foreign import data TxOutsJs :: Type
foreign import data TxUnspentOut :: Type
foreign import data TxUnspentOutJs :: Type
foreign import data TxUnspentOuts :: Type
foreign import data TxUnspentOutsJs :: Type
foreign import data TxWitnessSet :: Type
foreign import data TxWitnessSetJs :: Type
foreign import data TxWitnessSets :: Type
foreign import data TxWitnessSetsJs :: Type
foreign import data TxBuilderConstants :: Type
foreign import data TxInsBuilder :: Type
foreign import data URL :: Type
foreign import data URLJs :: Type
foreign import data Uint32Array :: Type
foreign import data UnitInterval :: Type
foreign import data UnitIntervalJs :: Type
foreign import data Update :: Type
foreign import data UpdateJs :: Type
foreign import data VRFCert :: Type
foreign import data VRFCertJs :: Type
foreign import data VRFKeyHash :: Type
foreign import data VRFVKey :: Type
foreign import data Value :: Type
foreign import data ValueJs :: Type
foreign import data Vkey :: Type
foreign import data VkeyJs :: Type
foreign import data Vkeys :: Type
foreign import data Vkeywitness :: Type
foreign import data VkeywitnessJs :: Type
foreign import data Vkeywitnesses :: Type
foreign import data Withdrawals :: Type
foreign import data WithdrawalsJs :: Type
foreign import data This :: Type

-------------------------------------------------------------------------------------
-- address

foreign import address_free :: Address -> Effect Unit
foreign import address_fromBytes :: Bytes -> Address
foreign import address_toJson :: Address -> String
foreign import address_toJsValue :: Address -> AddressJs
foreign import address_fromJson :: String -> Address
foreign import address_toHex :: Address -> String
foreign import address_fromHex :: String -> Address
foreign import address_toBytes :: Address -> Bytes
foreign import address_toBech32 :: Address -> String -> String
foreign import address_fromBech32 :: String -> Address
foreign import address_networkId :: Address -> Number

type AddressClass = { free :: Address -> Effect Unit, fromBytes :: Bytes -> Address, toJson :: Address -> String, toJsValue :: Address -> AddressJs, fromJson :: String -> Address, toHex :: Address -> String, fromHex :: String -> Address, toBytes :: Address -> Bytes, toBech32 :: Address -> String -> String, fromBech32 :: String -> Address, networkId :: Address -> Number }

address :: AddressClass
address = { free: address_free, fromBytes: address_fromBytes, toJson: address_toJson, toJsValue: address_toJsValue, fromJson: address_fromJson, toHex: address_toHex, fromHex: address_fromHex, toBytes: address_toBytes, toBech32: address_toBech32, fromBech32: address_fromBech32, networkId: address_networkId }

-------------------------------------------------------------------------------------
-- assetName

foreign import assetName_free :: AssetName -> Effect Unit
foreign import assetName_toBytes :: AssetName -> Bytes
foreign import assetName_fromBytes :: Bytes -> AssetName
foreign import assetName_toHex :: AssetName -> String
foreign import assetName_fromHex :: String -> AssetName
foreign import assetName_toJson :: AssetName -> String
foreign import assetName_toJsValue :: AssetName -> AssetNameJs
foreign import assetName_fromJson :: String -> AssetName
foreign import assetName_new :: Bytes -> AssetName
foreign import assetName_name :: AssetName -> Bytes

type AssetNameClass = { free :: AssetName -> Effect Unit, toBytes :: AssetName -> Bytes, fromBytes :: Bytes -> AssetName, toHex :: AssetName -> String, fromHex :: String -> AssetName, toJson :: AssetName -> String, toJsValue :: AssetName -> AssetNameJs, fromJson :: String -> AssetName, new :: Bytes -> AssetName, name :: AssetName -> Bytes }

assetName :: AssetNameClass
assetName = { free: assetName_free, toBytes: assetName_toBytes, fromBytes: assetName_fromBytes, toHex: assetName_toHex, fromHex: assetName_fromHex, toJson: assetName_toJson, toJsValue: assetName_toJsValue, fromJson: assetName_fromJson, new: assetName_new, name: assetName_name }

-------------------------------------------------------------------------------------
-- assetNames

foreign import assetNames_free :: AssetNames -> Effect Unit
foreign import assetNames_toBytes :: AssetNames -> Bytes
foreign import assetNames_fromBytes :: Bytes -> AssetNames
foreign import assetNames_toHex :: AssetNames -> String
foreign import assetNames_fromHex :: String -> AssetNames
foreign import assetNames_toJson :: AssetNames -> String
foreign import assetNames_toJsValue :: AssetNames -> AssetNamesJs
foreign import assetNames_fromJson :: String -> AssetNames
foreign import assetNames_new :: AssetNames
foreign import assetNames_len :: AssetNames -> Number
foreign import assetNames_get :: AssetNames -> Number -> AssetName
foreign import assetNames_add :: AssetNames -> AssetName -> Effect Unit

type AssetNamesClass = { free :: AssetNames -> Effect Unit, toBytes :: AssetNames -> Bytes, fromBytes :: Bytes -> AssetNames, toHex :: AssetNames -> String, fromHex :: String -> AssetNames, toJson :: AssetNames -> String, toJsValue :: AssetNames -> AssetNamesJs, fromJson :: String -> AssetNames, new :: AssetNames, len :: AssetNames -> Number, get :: AssetNames -> Number -> AssetName, add :: AssetNames -> AssetName -> Effect Unit }

assetNames :: AssetNamesClass
assetNames = { free: assetNames_free, toBytes: assetNames_toBytes, fromBytes: assetNames_fromBytes, toHex: assetNames_toHex, fromHex: assetNames_fromHex, toJson: assetNames_toJson, toJsValue: assetNames_toJsValue, fromJson: assetNames_fromJson, new: assetNames_new, len: assetNames_len, get: assetNames_get, add: assetNames_add }

-------------------------------------------------------------------------------------
-- assets

foreign import assets_free :: Assets -> Effect Unit
foreign import assets_toBytes :: Assets -> Bytes
foreign import assets_fromBytes :: Bytes -> Assets
foreign import assets_toHex :: Assets -> String
foreign import assets_fromHex :: String -> Assets
foreign import assets_toJson :: Assets -> String
foreign import assets_toJsValue :: Assets -> AssetsJs
foreign import assets_fromJson :: String -> Assets
foreign import assets_new :: Assets
foreign import assets_len :: Assets -> Number
foreign import assets_insert :: Assets -> AssetName -> BigNum -> Maybe BigNum
foreign import assets_get :: Assets -> AssetName -> Maybe BigNum
foreign import assets_keys :: Assets -> AssetNames

type AssetsClass = { free :: Assets -> Effect Unit, toBytes :: Assets -> Bytes, fromBytes :: Bytes -> Assets, toHex :: Assets -> String, fromHex :: String -> Assets, toJson :: Assets -> String, toJsValue :: Assets -> AssetsJs, fromJson :: String -> Assets, new :: Assets, len :: Assets -> Number, insert :: Assets -> AssetName -> BigNum -> Maybe BigNum, get :: Assets -> AssetName -> Maybe BigNum, keys :: Assets -> AssetNames }

assets :: AssetsClass
assets = { free: assets_free, toBytes: assets_toBytes, fromBytes: assets_fromBytes, toHex: assets_toHex, fromHex: assets_fromHex, toJson: assets_toJson, toJsValue: assets_toJsValue, fromJson: assets_fromJson, new: assets_new, len: assets_len, insert: assets_insert, get: assets_get, keys: assets_keys }

-------------------------------------------------------------------------------------
-- auxiliaryData

foreign import auxiliaryData_free :: AuxiliaryData -> Effect Unit
foreign import auxiliaryData_toBytes :: AuxiliaryData -> Bytes
foreign import auxiliaryData_fromBytes :: Bytes -> AuxiliaryData
foreign import auxiliaryData_toHex :: AuxiliaryData -> String
foreign import auxiliaryData_fromHex :: String -> AuxiliaryData
foreign import auxiliaryData_toJson :: AuxiliaryData -> String
foreign import auxiliaryData_toJsValue :: AuxiliaryData -> AuxiliaryDataJs
foreign import auxiliaryData_fromJson :: String -> AuxiliaryData
foreign import auxiliaryData_new :: AuxiliaryData
foreign import auxiliaryData_metadata :: AuxiliaryData -> Maybe GeneralTxMetadata
foreign import auxiliaryData_setMetadata :: AuxiliaryData -> GeneralTxMetadata -> Effect Unit
foreign import auxiliaryData_nativeScripts :: AuxiliaryData -> Maybe NativeScripts
foreign import auxiliaryData_setNativeScripts :: AuxiliaryData -> NativeScripts -> Effect Unit
foreign import auxiliaryData_plutusScripts :: AuxiliaryData -> Maybe PlutusScripts
foreign import auxiliaryData_setPlutusScripts :: AuxiliaryData -> PlutusScripts -> Effect Unit

type AuxiliaryDataClass = { free :: AuxiliaryData -> Effect Unit, toBytes :: AuxiliaryData -> Bytes, fromBytes :: Bytes -> AuxiliaryData, toHex :: AuxiliaryData -> String, fromHex :: String -> AuxiliaryData, toJson :: AuxiliaryData -> String, toJsValue :: AuxiliaryData -> AuxiliaryDataJs, fromJson :: String -> AuxiliaryData, new :: AuxiliaryData, metadata :: AuxiliaryData -> Maybe GeneralTxMetadata, setMetadata :: AuxiliaryData -> GeneralTxMetadata -> Effect Unit, nativeScripts :: AuxiliaryData -> Maybe NativeScripts, setNativeScripts :: AuxiliaryData -> NativeScripts -> Effect Unit, plutusScripts :: AuxiliaryData -> Maybe PlutusScripts, setPlutusScripts :: AuxiliaryData -> PlutusScripts -> Effect Unit }

auxiliaryData :: AuxiliaryDataClass
auxiliaryData = { free: auxiliaryData_free, toBytes: auxiliaryData_toBytes, fromBytes: auxiliaryData_fromBytes, toHex: auxiliaryData_toHex, fromHex: auxiliaryData_fromHex, toJson: auxiliaryData_toJson, toJsValue: auxiliaryData_toJsValue, fromJson: auxiliaryData_fromJson, new: auxiliaryData_new, metadata: auxiliaryData_metadata, setMetadata: auxiliaryData_setMetadata, nativeScripts: auxiliaryData_nativeScripts, setNativeScripts: auxiliaryData_setNativeScripts, plutusScripts: auxiliaryData_plutusScripts, setPlutusScripts: auxiliaryData_setPlutusScripts }

-------------------------------------------------------------------------------------
-- auxiliaryDataHash

foreign import auxiliaryDataHash_free :: AuxiliaryDataHash -> Effect Unit
foreign import auxiliaryDataHash_fromBytes :: Bytes -> AuxiliaryDataHash
foreign import auxiliaryDataHash_toBytes :: AuxiliaryDataHash -> Bytes
foreign import auxiliaryDataHash_toBech32 :: AuxiliaryDataHash -> String -> String
foreign import auxiliaryDataHash_fromBech32 :: String -> AuxiliaryDataHash
foreign import auxiliaryDataHash_toHex :: AuxiliaryDataHash -> String
foreign import auxiliaryDataHash_fromHex :: String -> AuxiliaryDataHash

type AuxiliaryDataHashClass = { free :: AuxiliaryDataHash -> Effect Unit, fromBytes :: Bytes -> AuxiliaryDataHash, toBytes :: AuxiliaryDataHash -> Bytes, toBech32 :: AuxiliaryDataHash -> String -> String, fromBech32 :: String -> AuxiliaryDataHash, toHex :: AuxiliaryDataHash -> String, fromHex :: String -> AuxiliaryDataHash }

auxiliaryDataHash :: AuxiliaryDataHashClass
auxiliaryDataHash = { free: auxiliaryDataHash_free, fromBytes: auxiliaryDataHash_fromBytes, toBytes: auxiliaryDataHash_toBytes, toBech32: auxiliaryDataHash_toBech32, fromBech32: auxiliaryDataHash_fromBech32, toHex: auxiliaryDataHash_toHex, fromHex: auxiliaryDataHash_fromHex }

-------------------------------------------------------------------------------------
-- auxiliaryDataSet

foreign import auxiliaryDataSet_free :: AuxiliaryDataSet -> Effect Unit
foreign import auxiliaryDataSet_new :: AuxiliaryDataSet
foreign import auxiliaryDataSet_len :: AuxiliaryDataSet -> Number
foreign import auxiliaryDataSet_insert :: AuxiliaryDataSet -> Number -> AuxiliaryData -> Maybe AuxiliaryData
foreign import auxiliaryDataSet_get :: AuxiliaryDataSet -> Number -> Maybe AuxiliaryData
foreign import auxiliaryDataSet_indices :: AuxiliaryDataSet -> Uint32Array

type AuxiliaryDataSetClass = { free :: AuxiliaryDataSet -> Effect Unit, new :: AuxiliaryDataSet, len :: AuxiliaryDataSet -> Number, insert :: AuxiliaryDataSet -> Number -> AuxiliaryData -> Maybe AuxiliaryData, get :: AuxiliaryDataSet -> Number -> Maybe AuxiliaryData, indices :: AuxiliaryDataSet -> Uint32Array }

auxiliaryDataSet :: AuxiliaryDataSetClass
auxiliaryDataSet = { free: auxiliaryDataSet_free, new: auxiliaryDataSet_new, len: auxiliaryDataSet_len, insert: auxiliaryDataSet_insert, get: auxiliaryDataSet_get, indices: auxiliaryDataSet_indices }

-------------------------------------------------------------------------------------
-- baseAddress

foreign import baseAddress_free :: BaseAddress -> Effect Unit
foreign import baseAddress_new :: Number -> StakeCredential -> StakeCredential -> BaseAddress
foreign import baseAddress_paymentCred :: BaseAddress -> StakeCredential
foreign import baseAddress_stakeCred :: BaseAddress -> StakeCredential
foreign import baseAddress_toAddress :: BaseAddress -> Address
foreign import baseAddress_fromAddress :: Address -> Maybe BaseAddress

type BaseAddressClass = { free :: BaseAddress -> Effect Unit, new :: Number -> StakeCredential -> StakeCredential -> BaseAddress, paymentCred :: BaseAddress -> StakeCredential, stakeCred :: BaseAddress -> StakeCredential, toAddress :: BaseAddress -> Address, fromAddress :: Address -> Maybe BaseAddress }

baseAddress :: BaseAddressClass
baseAddress = { free: baseAddress_free, new: baseAddress_new, paymentCred: baseAddress_paymentCred, stakeCred: baseAddress_stakeCred, toAddress: baseAddress_toAddress, fromAddress: baseAddress_fromAddress }

-------------------------------------------------------------------------------------
-- bigInt

foreign import bigInt_free :: BigInt -> Effect Unit
foreign import bigInt_toBytes :: BigInt -> Bytes
foreign import bigInt_fromBytes :: Bytes -> BigInt
foreign import bigInt_toHex :: BigInt -> String
foreign import bigInt_fromHex :: String -> BigInt
foreign import bigInt_toJson :: BigInt -> String
foreign import bigInt_toJsValue :: BigInt -> BigIntJs
foreign import bigInt_fromJson :: String -> BigInt
foreign import bigInt_isZero :: BigInt -> Boolean
foreign import bigInt_asU64 :: BigInt -> Maybe BigNum
foreign import bigInt_asInt :: BigInt -> Maybe Int
foreign import bigInt_fromStr :: String -> BigInt
foreign import bigInt_toStr :: BigInt -> String
foreign import bigInt_add :: BigInt -> BigInt -> BigInt
foreign import bigInt_mul :: BigInt -> BigInt -> BigInt
foreign import bigInt_one :: BigInt
foreign import bigInt_increment :: BigInt -> BigInt
foreign import bigInt_divCeil :: BigInt -> BigInt -> BigInt

type BigIntClass = { free :: BigInt -> Effect Unit, toBytes :: BigInt -> Bytes, fromBytes :: Bytes -> BigInt, toHex :: BigInt -> String, fromHex :: String -> BigInt, toJson :: BigInt -> String, toJsValue :: BigInt -> BigIntJs, fromJson :: String -> BigInt, isZero :: BigInt -> Boolean, asU64 :: BigInt -> Maybe BigNum, asInt :: BigInt -> Maybe Int, fromStr :: String -> BigInt, toStr :: BigInt -> String, add :: BigInt -> BigInt -> BigInt, mul :: BigInt -> BigInt -> BigInt, one :: BigInt, increment :: BigInt -> BigInt, divCeil :: BigInt -> BigInt -> BigInt }

bigInt :: BigIntClass
bigInt = { free: bigInt_free, toBytes: bigInt_toBytes, fromBytes: bigInt_fromBytes, toHex: bigInt_toHex, fromHex: bigInt_fromHex, toJson: bigInt_toJson, toJsValue: bigInt_toJsValue, fromJson: bigInt_fromJson, isZero: bigInt_isZero, asU64: bigInt_asU64, asInt: bigInt_asInt, fromStr: bigInt_fromStr, toStr: bigInt_toStr, add: bigInt_add, mul: bigInt_mul, one: bigInt_one, increment: bigInt_increment, divCeil: bigInt_divCeil }

-------------------------------------------------------------------------------------
-- bigNum

foreign import bigNum_free :: BigNum -> Effect Unit
foreign import bigNum_toBytes :: BigNum -> Bytes
foreign import bigNum_fromBytes :: Bytes -> BigNum
foreign import bigNum_toHex :: BigNum -> String
foreign import bigNum_fromHex :: String -> BigNum
foreign import bigNum_toJson :: BigNum -> String
foreign import bigNum_toJsValue :: BigNum -> BigNumJs
foreign import bigNum_fromJson :: String -> BigNum
foreign import bigNum_fromStr :: String -> BigNum
foreign import bigNum_toStr :: BigNum -> String
foreign import bigNum_zero :: BigNum
foreign import bigNum_one :: BigNum
foreign import bigNum_isZero :: BigNum -> Boolean
foreign import bigNum_divFloor :: BigNum -> BigNum -> BigNum
foreign import bigNum_checkedMul :: BigNum -> BigNum -> BigNum
foreign import bigNum_checkedAdd :: BigNum -> BigNum -> BigNum
foreign import bigNum_checkedSub :: BigNum -> BigNum -> BigNum
foreign import bigNum_clampedSub :: BigNum -> BigNum -> BigNum
foreign import bigNum_compare :: BigNum -> BigNum -> Number
foreign import bigNum_lessThan :: BigNum -> BigNum -> Boolean
foreign import bigNum_max :: BigNum -> BigNum -> BigNum

type BigNumClass = { free :: BigNum -> Effect Unit, toBytes :: BigNum -> Bytes, fromBytes :: Bytes -> BigNum, toHex :: BigNum -> String, fromHex :: String -> BigNum, toJson :: BigNum -> String, toJsValue :: BigNum -> BigNumJs, fromJson :: String -> BigNum, fromStr :: String -> BigNum, toStr :: BigNum -> String, zero :: BigNum, one :: BigNum, isZero :: BigNum -> Boolean, divFloor :: BigNum -> BigNum -> BigNum, checkedMul :: BigNum -> BigNum -> BigNum, checkedAdd :: BigNum -> BigNum -> BigNum, checkedSub :: BigNum -> BigNum -> BigNum, clampedSub :: BigNum -> BigNum -> BigNum, compare :: BigNum -> BigNum -> Number, lessThan :: BigNum -> BigNum -> Boolean, max :: BigNum -> BigNum -> BigNum }

bigNum :: BigNumClass
bigNum = { free: bigNum_free, toBytes: bigNum_toBytes, fromBytes: bigNum_fromBytes, toHex: bigNum_toHex, fromHex: bigNum_fromHex, toJson: bigNum_toJson, toJsValue: bigNum_toJsValue, fromJson: bigNum_fromJson, fromStr: bigNum_fromStr, toStr: bigNum_toStr, zero: bigNum_zero, one: bigNum_one, isZero: bigNum_isZero, divFloor: bigNum_divFloor, checkedMul: bigNum_checkedMul, checkedAdd: bigNum_checkedAdd, checkedSub: bigNum_checkedSub, clampedSub: bigNum_clampedSub, compare: bigNum_compare, lessThan: bigNum_lessThan, max: bigNum_max }

-------------------------------------------------------------------------------------
-- bip32PrivateKey

foreign import bip32PrivateKey_free :: Bip32PrivateKey -> Effect Unit
foreign import bip32PrivateKey_derive :: Bip32PrivateKey -> Number -> Bip32PrivateKey
foreign import bip32PrivateKey_from128Xprv :: Bytes -> Bip32PrivateKey
foreign import bip32PrivateKey_to128Xprv :: Bip32PrivateKey -> Bytes
foreign import bip32PrivateKey_generateEd25519Bip32 :: Bip32PrivateKey
foreign import bip32PrivateKey_toRawKey :: Bip32PrivateKey -> PrivateKey
foreign import bip32PrivateKey_toPublic :: Bip32PrivateKey -> Bip32PublicKey
foreign import bip32PrivateKey_fromBytes :: Bytes -> Bip32PrivateKey
foreign import bip32PrivateKey_asBytes :: Bip32PrivateKey -> Bytes
foreign import bip32PrivateKey_fromBech32 :: String -> Bip32PrivateKey
foreign import bip32PrivateKey_toBech32 :: Bip32PrivateKey -> String
foreign import bip32PrivateKey_fromBip39Entropy :: Bytes -> Bytes -> Bip32PrivateKey
foreign import bip32PrivateKey_chaincode :: Bip32PrivateKey -> Bytes
foreign import bip32PrivateKey_toHex :: Bip32PrivateKey -> String
foreign import bip32PrivateKey_fromHex :: String -> Bip32PrivateKey

type Bip32PrivateKeyClass = { free :: Bip32PrivateKey -> Effect Unit, derive :: Bip32PrivateKey -> Number -> Bip32PrivateKey, from128Xprv :: Bytes -> Bip32PrivateKey, to128Xprv :: Bip32PrivateKey -> Bytes, generateEd25519Bip32 :: Bip32PrivateKey, toRawKey :: Bip32PrivateKey -> PrivateKey, toPublic :: Bip32PrivateKey -> Bip32PublicKey, fromBytes :: Bytes -> Bip32PrivateKey, asBytes :: Bip32PrivateKey -> Bytes, fromBech32 :: String -> Bip32PrivateKey, toBech32 :: Bip32PrivateKey -> String, fromBip39Entropy :: Bytes -> Bytes -> Bip32PrivateKey, chaincode :: Bip32PrivateKey -> Bytes, toHex :: Bip32PrivateKey -> String, fromHex :: String -> Bip32PrivateKey }

bip32PrivateKey :: Bip32PrivateKeyClass
bip32PrivateKey = { free: bip32PrivateKey_free, derive: bip32PrivateKey_derive, from128Xprv: bip32PrivateKey_from128Xprv, to128Xprv: bip32PrivateKey_to128Xprv, generateEd25519Bip32: bip32PrivateKey_generateEd25519Bip32, toRawKey: bip32PrivateKey_toRawKey, toPublic: bip32PrivateKey_toPublic, fromBytes: bip32PrivateKey_fromBytes, asBytes: bip32PrivateKey_asBytes, fromBech32: bip32PrivateKey_fromBech32, toBech32: bip32PrivateKey_toBech32, fromBip39Entropy: bip32PrivateKey_fromBip39Entropy, chaincode: bip32PrivateKey_chaincode, toHex: bip32PrivateKey_toHex, fromHex: bip32PrivateKey_fromHex }

-------------------------------------------------------------------------------------
-- bip32PublicKey

foreign import bip32PublicKey_free :: Bip32PublicKey -> Effect Unit
foreign import bip32PublicKey_derive :: Bip32PublicKey -> Number -> Bip32PublicKey
foreign import bip32PublicKey_toRawKey :: Bip32PublicKey -> PublicKey
foreign import bip32PublicKey_fromBytes :: Bytes -> Bip32PublicKey
foreign import bip32PublicKey_asBytes :: Bip32PublicKey -> Bytes
foreign import bip32PublicKey_fromBech32 :: String -> Bip32PublicKey
foreign import bip32PublicKey_toBech32 :: Bip32PublicKey -> String
foreign import bip32PublicKey_chaincode :: Bip32PublicKey -> Bytes
foreign import bip32PublicKey_toHex :: Bip32PublicKey -> String
foreign import bip32PublicKey_fromHex :: String -> Bip32PublicKey

type Bip32PublicKeyClass = { free :: Bip32PublicKey -> Effect Unit, derive :: Bip32PublicKey -> Number -> Bip32PublicKey, toRawKey :: Bip32PublicKey -> PublicKey, fromBytes :: Bytes -> Bip32PublicKey, asBytes :: Bip32PublicKey -> Bytes, fromBech32 :: String -> Bip32PublicKey, toBech32 :: Bip32PublicKey -> String, chaincode :: Bip32PublicKey -> Bytes, toHex :: Bip32PublicKey -> String, fromHex :: String -> Bip32PublicKey }

bip32PublicKey :: Bip32PublicKeyClass
bip32PublicKey = { free: bip32PublicKey_free, derive: bip32PublicKey_derive, toRawKey: bip32PublicKey_toRawKey, fromBytes: bip32PublicKey_fromBytes, asBytes: bip32PublicKey_asBytes, fromBech32: bip32PublicKey_fromBech32, toBech32: bip32PublicKey_toBech32, chaincode: bip32PublicKey_chaincode, toHex: bip32PublicKey_toHex, fromHex: bip32PublicKey_fromHex }

-------------------------------------------------------------------------------------
-- block

foreign import block_free :: Block -> Effect Unit
foreign import block_toBytes :: Block -> Bytes
foreign import block_fromBytes :: Bytes -> Block
foreign import block_toHex :: Block -> String
foreign import block_fromHex :: String -> Block
foreign import block_toJson :: Block -> String
foreign import block_toJsValue :: Block -> BlockJs
foreign import block_fromJson :: String -> Block
foreign import block_header :: Block -> Header
foreign import block_txBodies :: Block -> TxBodies
foreign import block_txWitnessSets :: Block -> TxWitnessSets
foreign import block_auxiliaryDataSet :: Block -> AuxiliaryDataSet
foreign import block_invalidTxs :: Block -> Uint32Array
foreign import block_new :: Header -> TxBodies -> TxWitnessSets -> AuxiliaryDataSet -> Uint32Array -> Block

type BlockClass = { free :: Block -> Effect Unit, toBytes :: Block -> Bytes, fromBytes :: Bytes -> Block, toHex :: Block -> String, fromHex :: String -> Block, toJson :: Block -> String, toJsValue :: Block -> BlockJs, fromJson :: String -> Block, header :: Block -> Header, txBodies :: Block -> TxBodies, txWitnessSets :: Block -> TxWitnessSets, auxiliaryDataSet :: Block -> AuxiliaryDataSet, invalidTxs :: Block -> Uint32Array, new :: Header -> TxBodies -> TxWitnessSets -> AuxiliaryDataSet -> Uint32Array -> Block }

block :: BlockClass
block = { free: block_free, toBytes: block_toBytes, fromBytes: block_fromBytes, toHex: block_toHex, fromHex: block_fromHex, toJson: block_toJson, toJsValue: block_toJsValue, fromJson: block_fromJson, header: block_header, txBodies: block_txBodies, txWitnessSets: block_txWitnessSets, auxiliaryDataSet: block_auxiliaryDataSet, invalidTxs: block_invalidTxs, new: block_new }

-------------------------------------------------------------------------------------
-- blockHash

foreign import blockHash_free :: BlockHash -> Effect Unit
foreign import blockHash_fromBytes :: Bytes -> BlockHash
foreign import blockHash_toBytes :: BlockHash -> Bytes
foreign import blockHash_toBech32 :: BlockHash -> String -> String
foreign import blockHash_fromBech32 :: String -> BlockHash
foreign import blockHash_toHex :: BlockHash -> String
foreign import blockHash_fromHex :: String -> BlockHash

type BlockHashClass = { free :: BlockHash -> Effect Unit, fromBytes :: Bytes -> BlockHash, toBytes :: BlockHash -> Bytes, toBech32 :: BlockHash -> String -> String, fromBech32 :: String -> BlockHash, toHex :: BlockHash -> String, fromHex :: String -> BlockHash }

blockHash :: BlockHashClass
blockHash = { free: blockHash_free, fromBytes: blockHash_fromBytes, toBytes: blockHash_toBytes, toBech32: blockHash_toBech32, fromBech32: blockHash_fromBech32, toHex: blockHash_toHex, fromHex: blockHash_fromHex }

-------------------------------------------------------------------------------------
-- bootstrapWitness

foreign import bootstrapWitness_free :: BootstrapWitness -> Effect Unit
foreign import bootstrapWitness_toBytes :: BootstrapWitness -> Bytes
foreign import bootstrapWitness_fromBytes :: Bytes -> BootstrapWitness
foreign import bootstrapWitness_toHex :: BootstrapWitness -> String
foreign import bootstrapWitness_fromHex :: String -> BootstrapWitness
foreign import bootstrapWitness_toJson :: BootstrapWitness -> String
foreign import bootstrapWitness_toJsValue :: BootstrapWitness -> BootstrapWitnessJs
foreign import bootstrapWitness_fromJson :: String -> BootstrapWitness
foreign import bootstrapWitness_vkey :: BootstrapWitness -> Vkey
foreign import bootstrapWitness_signature :: BootstrapWitness -> Ed25519Signature
foreign import bootstrapWitness_chainCode :: BootstrapWitness -> Bytes
foreign import bootstrapWitness_attributes :: BootstrapWitness -> Bytes
foreign import bootstrapWitness_new :: Vkey -> Ed25519Signature -> Bytes -> Bytes -> BootstrapWitness

type BootstrapWitnessClass = { free :: BootstrapWitness -> Effect Unit, toBytes :: BootstrapWitness -> Bytes, fromBytes :: Bytes -> BootstrapWitness, toHex :: BootstrapWitness -> String, fromHex :: String -> BootstrapWitness, toJson :: BootstrapWitness -> String, toJsValue :: BootstrapWitness -> BootstrapWitnessJs, fromJson :: String -> BootstrapWitness, vkey :: BootstrapWitness -> Vkey, signature :: BootstrapWitness -> Ed25519Signature, chainCode :: BootstrapWitness -> Bytes, attributes :: BootstrapWitness -> Bytes, new :: Vkey -> Ed25519Signature -> Bytes -> Bytes -> BootstrapWitness }

bootstrapWitness :: BootstrapWitnessClass
bootstrapWitness = { free: bootstrapWitness_free, toBytes: bootstrapWitness_toBytes, fromBytes: bootstrapWitness_fromBytes, toHex: bootstrapWitness_toHex, fromHex: bootstrapWitness_fromHex, toJson: bootstrapWitness_toJson, toJsValue: bootstrapWitness_toJsValue, fromJson: bootstrapWitness_fromJson, vkey: bootstrapWitness_vkey, signature: bootstrapWitness_signature, chainCode: bootstrapWitness_chainCode, attributes: bootstrapWitness_attributes, new: bootstrapWitness_new }

-------------------------------------------------------------------------------------
-- bootstrapWitnesses

foreign import bootstrapWitnesses_free :: BootstrapWitnesses -> Effect Unit
foreign import bootstrapWitnesses_new :: BootstrapWitnesses
foreign import bootstrapWitnesses_len :: BootstrapWitnesses -> Number
foreign import bootstrapWitnesses_get :: BootstrapWitnesses -> Number -> BootstrapWitness
foreign import bootstrapWitnesses_add :: BootstrapWitnesses -> BootstrapWitness -> Effect Unit

type BootstrapWitnessesClass = { free :: BootstrapWitnesses -> Effect Unit, new :: BootstrapWitnesses, len :: BootstrapWitnesses -> Number, get :: BootstrapWitnesses -> Number -> BootstrapWitness, add :: BootstrapWitnesses -> BootstrapWitness -> Effect Unit }

bootstrapWitnesses :: BootstrapWitnessesClass
bootstrapWitnesses = { free: bootstrapWitnesses_free, new: bootstrapWitnesses_new, len: bootstrapWitnesses_len, get: bootstrapWitnesses_get, add: bootstrapWitnesses_add }

-------------------------------------------------------------------------------------
-- byronAddress

foreign import byronAddress_free :: ByronAddress -> Effect Unit
foreign import byronAddress_toBase58 :: ByronAddress -> String
foreign import byronAddress_toBytes :: ByronAddress -> Bytes
foreign import byronAddress_fromBytes :: Bytes -> ByronAddress
foreign import byronAddress_byronProtocolMagic :: ByronAddress -> Number
foreign import byronAddress_attributes :: ByronAddress -> Bytes
foreign import byronAddress_networkId :: ByronAddress -> Number
foreign import byronAddress_fromBase58 :: String -> ByronAddress
foreign import byronAddress_icarusFromKey :: Bip32PublicKey -> Number -> ByronAddress
foreign import byronAddress_isValid :: String -> Boolean
foreign import byronAddress_toAddress :: ByronAddress -> Address
foreign import byronAddress_fromAddress :: Address -> Maybe ByronAddress

type ByronAddressClass = { free :: ByronAddress -> Effect Unit, toBase58 :: ByronAddress -> String, toBytes :: ByronAddress -> Bytes, fromBytes :: Bytes -> ByronAddress, byronProtocolMagic :: ByronAddress -> Number, attributes :: ByronAddress -> Bytes, networkId :: ByronAddress -> Number, fromBase58 :: String -> ByronAddress, icarusFromKey :: Bip32PublicKey -> Number -> ByronAddress, isValid :: String -> Boolean, toAddress :: ByronAddress -> Address, fromAddress :: Address -> Maybe ByronAddress }

byronAddress :: ByronAddressClass
byronAddress = { free: byronAddress_free, toBase58: byronAddress_toBase58, toBytes: byronAddress_toBytes, fromBytes: byronAddress_fromBytes, byronProtocolMagic: byronAddress_byronProtocolMagic, attributes: byronAddress_attributes, networkId: byronAddress_networkId, fromBase58: byronAddress_fromBase58, icarusFromKey: byronAddress_icarusFromKey, isValid: byronAddress_isValid, toAddress: byronAddress_toAddress, fromAddress: byronAddress_fromAddress }

-------------------------------------------------------------------------------------
-- certificate

foreign import certificate_free :: Certificate -> Effect Unit
foreign import certificate_toBytes :: Certificate -> Bytes
foreign import certificate_fromBytes :: Bytes -> Certificate
foreign import certificate_toHex :: Certificate -> String
foreign import certificate_fromHex :: String -> Certificate
foreign import certificate_toJson :: Certificate -> String
foreign import certificate_toJsValue :: Certificate -> CertificateJs
foreign import certificate_fromJson :: String -> Certificate
foreign import certificate_newStakeRegistration :: StakeRegistration -> Certificate
foreign import certificate_newStakeDeregistration :: StakeDeregistration -> Certificate
foreign import certificate_newStakeDelegation :: StakeDelegation -> Certificate
foreign import certificate_newPoolRegistration :: PoolRegistration -> Certificate
foreign import certificate_newPoolRetirement :: PoolRetirement -> Certificate
foreign import certificate_newGenesisKeyDelegation :: GenesisKeyDelegation -> Certificate
foreign import certificate_newMoveInstantaneousRewardsCert :: MoveInstantaneousRewardsCert -> Certificate
foreign import certificate_kind :: Certificate -> Number
foreign import certificate_asStakeRegistration :: Certificate -> Maybe StakeRegistration
foreign import certificate_asStakeDeregistration :: Certificate -> Maybe StakeDeregistration
foreign import certificate_asStakeDelegation :: Certificate -> Maybe StakeDelegation
foreign import certificate_asPoolRegistration :: Certificate -> Maybe PoolRegistration
foreign import certificate_asPoolRetirement :: Certificate -> Maybe PoolRetirement
foreign import certificate_asGenesisKeyDelegation :: Certificate -> Maybe GenesisKeyDelegation
foreign import certificate_asMoveInstantaneousRewardsCert :: Certificate -> Maybe MoveInstantaneousRewardsCert

type CertificateClass = { free :: Certificate -> Effect Unit, toBytes :: Certificate -> Bytes, fromBytes :: Bytes -> Certificate, toHex :: Certificate -> String, fromHex :: String -> Certificate, toJson :: Certificate -> String, toJsValue :: Certificate -> CertificateJs, fromJson :: String -> Certificate, newStakeRegistration :: StakeRegistration -> Certificate, newStakeDeregistration :: StakeDeregistration -> Certificate, newStakeDelegation :: StakeDelegation -> Certificate, newPoolRegistration :: PoolRegistration -> Certificate, newPoolRetirement :: PoolRetirement -> Certificate, newGenesisKeyDelegation :: GenesisKeyDelegation -> Certificate, newMoveInstantaneousRewardsCert :: MoveInstantaneousRewardsCert -> Certificate, kind :: Certificate -> Number, asStakeRegistration :: Certificate -> Maybe StakeRegistration, asStakeDeregistration :: Certificate -> Maybe StakeDeregistration, asStakeDelegation :: Certificate -> Maybe StakeDelegation, asPoolRegistration :: Certificate -> Maybe PoolRegistration, asPoolRetirement :: Certificate -> Maybe PoolRetirement, asGenesisKeyDelegation :: Certificate -> Maybe GenesisKeyDelegation, asMoveInstantaneousRewardsCert :: Certificate -> Maybe MoveInstantaneousRewardsCert }

certificate :: CertificateClass
certificate = { free: certificate_free, toBytes: certificate_toBytes, fromBytes: certificate_fromBytes, toHex: certificate_toHex, fromHex: certificate_fromHex, toJson: certificate_toJson, toJsValue: certificate_toJsValue, fromJson: certificate_fromJson, newStakeRegistration: certificate_newStakeRegistration, newStakeDeregistration: certificate_newStakeDeregistration, newStakeDelegation: certificate_newStakeDelegation, newPoolRegistration: certificate_newPoolRegistration, newPoolRetirement: certificate_newPoolRetirement, newGenesisKeyDelegation: certificate_newGenesisKeyDelegation, newMoveInstantaneousRewardsCert: certificate_newMoveInstantaneousRewardsCert, kind: certificate_kind, asStakeRegistration: certificate_asStakeRegistration, asStakeDeregistration: certificate_asStakeDeregistration, asStakeDelegation: certificate_asStakeDelegation, asPoolRegistration: certificate_asPoolRegistration, asPoolRetirement: certificate_asPoolRetirement, asGenesisKeyDelegation: certificate_asGenesisKeyDelegation, asMoveInstantaneousRewardsCert: certificate_asMoveInstantaneousRewardsCert }

-------------------------------------------------------------------------------------
-- certificates

foreign import certificates_free :: Certificates -> Effect Unit
foreign import certificates_toBytes :: Certificates -> Bytes
foreign import certificates_fromBytes :: Bytes -> Certificates
foreign import certificates_toHex :: Certificates -> String
foreign import certificates_fromHex :: String -> Certificates
foreign import certificates_toJson :: Certificates -> String
foreign import certificates_toJsValue :: Certificates -> CertificatesJs
foreign import certificates_fromJson :: String -> Certificates
foreign import certificates_new :: Certificates
foreign import certificates_len :: Certificates -> Number
foreign import certificates_get :: Certificates -> Number -> Certificate
foreign import certificates_add :: Certificates -> Certificate -> Effect Unit

type CertificatesClass = { free :: Certificates -> Effect Unit, toBytes :: Certificates -> Bytes, fromBytes :: Bytes -> Certificates, toHex :: Certificates -> String, fromHex :: String -> Certificates, toJson :: Certificates -> String, toJsValue :: Certificates -> CertificatesJs, fromJson :: String -> Certificates, new :: Certificates, len :: Certificates -> Number, get :: Certificates -> Number -> Certificate, add :: Certificates -> Certificate -> Effect Unit }

certificates :: CertificatesClass
certificates = { free: certificates_free, toBytes: certificates_toBytes, fromBytes: certificates_fromBytes, toHex: certificates_toHex, fromHex: certificates_fromHex, toJson: certificates_toJson, toJsValue: certificates_toJsValue, fromJson: certificates_fromJson, new: certificates_new, len: certificates_len, get: certificates_get, add: certificates_add }

-------------------------------------------------------------------------------------
-- constrPlutusData

foreign import constrPlutusData_free :: ConstrPlutusData -> Effect Unit
foreign import constrPlutusData_toBytes :: ConstrPlutusData -> Bytes
foreign import constrPlutusData_fromBytes :: Bytes -> ConstrPlutusData
foreign import constrPlutusData_toHex :: ConstrPlutusData -> String
foreign import constrPlutusData_fromHex :: String -> ConstrPlutusData
foreign import constrPlutusData_toJson :: ConstrPlutusData -> String
foreign import constrPlutusData_toJsValue :: ConstrPlutusData -> ConstrPlutusDataJs
foreign import constrPlutusData_fromJson :: String -> ConstrPlutusData
foreign import constrPlutusData_alternative :: ConstrPlutusData -> BigNum
foreign import constrPlutusData_data :: ConstrPlutusData -> PlutusList
foreign import constrPlutusData_new :: BigNum -> PlutusList -> ConstrPlutusData

type ConstrPlutusDataClass = { free :: ConstrPlutusData -> Effect Unit, toBytes :: ConstrPlutusData -> Bytes, fromBytes :: Bytes -> ConstrPlutusData, toHex :: ConstrPlutusData -> String, fromHex :: String -> ConstrPlutusData, toJson :: ConstrPlutusData -> String, toJsValue :: ConstrPlutusData -> ConstrPlutusDataJs, fromJson :: String -> ConstrPlutusData, alternative :: ConstrPlutusData -> BigNum, data :: ConstrPlutusData -> PlutusList, new :: BigNum -> PlutusList -> ConstrPlutusData }

constrPlutusData :: ConstrPlutusDataClass
constrPlutusData = { free: constrPlutusData_free, toBytes: constrPlutusData_toBytes, fromBytes: constrPlutusData_fromBytes, toHex: constrPlutusData_toHex, fromHex: constrPlutusData_fromHex, toJson: constrPlutusData_toJson, toJsValue: constrPlutusData_toJsValue, fromJson: constrPlutusData_fromJson, alternative: constrPlutusData_alternative, data: constrPlutusData_data, new: constrPlutusData_new }

-------------------------------------------------------------------------------------
-- costModel

foreign import costModel_free :: CostModel -> Effect Unit
foreign import costModel_toBytes :: CostModel -> Bytes
foreign import costModel_fromBytes :: Bytes -> CostModel
foreign import costModel_toHex :: CostModel -> String
foreign import costModel_fromHex :: String -> CostModel
foreign import costModel_toJson :: CostModel -> String
foreign import costModel_toJsValue :: CostModel -> CostModelJs
foreign import costModel_fromJson :: String -> CostModel
foreign import costModel_new :: CostModel
foreign import costModel_set :: CostModel -> Number -> Int -> Int
foreign import costModel_get :: CostModel -> Number -> Int
foreign import costModel_len :: CostModel -> Number

type CostModelClass = { free :: CostModel -> Effect Unit, toBytes :: CostModel -> Bytes, fromBytes :: Bytes -> CostModel, toHex :: CostModel -> String, fromHex :: String -> CostModel, toJson :: CostModel -> String, toJsValue :: CostModel -> CostModelJs, fromJson :: String -> CostModel, new :: CostModel, set :: CostModel -> Number -> Int -> Int, get :: CostModel -> Number -> Int, len :: CostModel -> Number }

costModel :: CostModelClass
costModel = { free: costModel_free, toBytes: costModel_toBytes, fromBytes: costModel_fromBytes, toHex: costModel_toHex, fromHex: costModel_fromHex, toJson: costModel_toJson, toJsValue: costModel_toJsValue, fromJson: costModel_fromJson, new: costModel_new, set: costModel_set, get: costModel_get, len: costModel_len }

-------------------------------------------------------------------------------------
-- costmdls

foreign import costmdls_free :: Costmdls -> Effect Unit
foreign import costmdls_toBytes :: Costmdls -> Bytes
foreign import costmdls_fromBytes :: Bytes -> Costmdls
foreign import costmdls_toHex :: Costmdls -> String
foreign import costmdls_fromHex :: String -> Costmdls
foreign import costmdls_toJson :: Costmdls -> String
foreign import costmdls_toJsValue :: Costmdls -> CostmdlsJs
foreign import costmdls_fromJson :: String -> Costmdls
foreign import costmdls_new :: Costmdls
foreign import costmdls_len :: Costmdls -> Number
foreign import costmdls_insert :: Costmdls -> Language -> CostModel -> Maybe CostModel
foreign import costmdls_get :: Costmdls -> Language -> Maybe CostModel
foreign import costmdls_keys :: Costmdls -> Languages
foreign import costmdls_retainLanguageVersions :: Costmdls -> Languages -> Costmdls

type CostmdlsClass = { free :: Costmdls -> Effect Unit, toBytes :: Costmdls -> Bytes, fromBytes :: Bytes -> Costmdls, toHex :: Costmdls -> String, fromHex :: String -> Costmdls, toJson :: Costmdls -> String, toJsValue :: Costmdls -> CostmdlsJs, fromJson :: String -> Costmdls, new :: Costmdls, len :: Costmdls -> Number, insert :: Costmdls -> Language -> CostModel -> Maybe CostModel, get :: Costmdls -> Language -> Maybe CostModel, keys :: Costmdls -> Languages, retainLanguageVersions :: Costmdls -> Languages -> Costmdls }

costmdls :: CostmdlsClass
costmdls = { free: costmdls_free, toBytes: costmdls_toBytes, fromBytes: costmdls_fromBytes, toHex: costmdls_toHex, fromHex: costmdls_fromHex, toJson: costmdls_toJson, toJsValue: costmdls_toJsValue, fromJson: costmdls_fromJson, new: costmdls_new, len: costmdls_len, insert: costmdls_insert, get: costmdls_get, keys: costmdls_keys, retainLanguageVersions: costmdls_retainLanguageVersions }

-------------------------------------------------------------------------------------
-- dNSRecordAorAAAA

foreign import dNSRecordAorAAAA_free :: DNSRecordAorAAAA -> Effect Unit
foreign import dNSRecordAorAAAA_toBytes :: DNSRecordAorAAAA -> Bytes
foreign import dNSRecordAorAAAA_fromBytes :: Bytes -> DNSRecordAorAAAA
foreign import dNSRecordAorAAAA_toHex :: DNSRecordAorAAAA -> String
foreign import dNSRecordAorAAAA_fromHex :: String -> DNSRecordAorAAAA
foreign import dNSRecordAorAAAA_toJson :: DNSRecordAorAAAA -> String
foreign import dNSRecordAorAAAA_toJsValue :: DNSRecordAorAAAA -> DNSRecordAorAAAAJs
foreign import dNSRecordAorAAAA_fromJson :: String -> DNSRecordAorAAAA
foreign import dNSRecordAorAAAA_new :: String -> DNSRecordAorAAAA
foreign import dNSRecordAorAAAA_record :: DNSRecordAorAAAA -> String

type DNSRecordAorAAAAClass = { free :: DNSRecordAorAAAA -> Effect Unit, toBytes :: DNSRecordAorAAAA -> Bytes, fromBytes :: Bytes -> DNSRecordAorAAAA, toHex :: DNSRecordAorAAAA -> String, fromHex :: String -> DNSRecordAorAAAA, toJson :: DNSRecordAorAAAA -> String, toJsValue :: DNSRecordAorAAAA -> DNSRecordAorAAAAJs, fromJson :: String -> DNSRecordAorAAAA, new :: String -> DNSRecordAorAAAA, record :: DNSRecordAorAAAA -> String }

dNSRecordAorAAAA :: DNSRecordAorAAAAClass
dNSRecordAorAAAA = { free: dNSRecordAorAAAA_free, toBytes: dNSRecordAorAAAA_toBytes, fromBytes: dNSRecordAorAAAA_fromBytes, toHex: dNSRecordAorAAAA_toHex, fromHex: dNSRecordAorAAAA_fromHex, toJson: dNSRecordAorAAAA_toJson, toJsValue: dNSRecordAorAAAA_toJsValue, fromJson: dNSRecordAorAAAA_fromJson, new: dNSRecordAorAAAA_new, record: dNSRecordAorAAAA_record }

-------------------------------------------------------------------------------------
-- dNSRecordSRV

foreign import dNSRecordSRV_free :: DNSRecordSRV -> Effect Unit
foreign import dNSRecordSRV_toBytes :: DNSRecordSRV -> Bytes
foreign import dNSRecordSRV_fromBytes :: Bytes -> DNSRecordSRV
foreign import dNSRecordSRV_toHex :: DNSRecordSRV -> String
foreign import dNSRecordSRV_fromHex :: String -> DNSRecordSRV
foreign import dNSRecordSRV_toJson :: DNSRecordSRV -> String
foreign import dNSRecordSRV_toJsValue :: DNSRecordSRV -> DNSRecordSRVJs
foreign import dNSRecordSRV_fromJson :: String -> DNSRecordSRV
foreign import dNSRecordSRV_new :: String -> DNSRecordSRV
foreign import dNSRecordSRV_record :: DNSRecordSRV -> String

type DNSRecordSRVClass = { free :: DNSRecordSRV -> Effect Unit, toBytes :: DNSRecordSRV -> Bytes, fromBytes :: Bytes -> DNSRecordSRV, toHex :: DNSRecordSRV -> String, fromHex :: String -> DNSRecordSRV, toJson :: DNSRecordSRV -> String, toJsValue :: DNSRecordSRV -> DNSRecordSRVJs, fromJson :: String -> DNSRecordSRV, new :: String -> DNSRecordSRV, record :: DNSRecordSRV -> String }

dNSRecordSRV :: DNSRecordSRVClass
dNSRecordSRV = { free: dNSRecordSRV_free, toBytes: dNSRecordSRV_toBytes, fromBytes: dNSRecordSRV_fromBytes, toHex: dNSRecordSRV_toHex, fromHex: dNSRecordSRV_fromHex, toJson: dNSRecordSRV_toJson, toJsValue: dNSRecordSRV_toJsValue, fromJson: dNSRecordSRV_fromJson, new: dNSRecordSRV_new, record: dNSRecordSRV_record }

-------------------------------------------------------------------------------------
-- dataCost

foreign import dataCost_free :: DataCost -> Effect Unit
foreign import dataCost_newCoinsPerWord :: BigNum -> DataCost
foreign import dataCost_newCoinsPerByte :: BigNum -> DataCost
foreign import dataCost_coinsPerByte :: DataCost -> BigNum

type DataCostClass = { free :: DataCost -> Effect Unit, newCoinsPerWord :: BigNum -> DataCost, newCoinsPerByte :: BigNum -> DataCost, coinsPerByte :: DataCost -> BigNum }

dataCost :: DataCostClass
dataCost = { free: dataCost_free, newCoinsPerWord: dataCost_newCoinsPerWord, newCoinsPerByte: dataCost_newCoinsPerByte, coinsPerByte: dataCost_coinsPerByte }

-------------------------------------------------------------------------------------
-- dataHash

foreign import dataHash_free :: DataHash -> Effect Unit
foreign import dataHash_fromBytes :: Bytes -> DataHash
foreign import dataHash_toBytes :: DataHash -> Bytes
foreign import dataHash_toBech32 :: DataHash -> String -> String
foreign import dataHash_fromBech32 :: String -> DataHash
foreign import dataHash_toHex :: DataHash -> String
foreign import dataHash_fromHex :: String -> DataHash

type DataHashClass = { free :: DataHash -> Effect Unit, fromBytes :: Bytes -> DataHash, toBytes :: DataHash -> Bytes, toBech32 :: DataHash -> String -> String, fromBech32 :: String -> DataHash, toHex :: DataHash -> String, fromHex :: String -> DataHash }

dataHash :: DataHashClass
dataHash = { free: dataHash_free, fromBytes: dataHash_fromBytes, toBytes: dataHash_toBytes, toBech32: dataHash_toBech32, fromBech32: dataHash_fromBech32, toHex: dataHash_toHex, fromHex: dataHash_fromHex }

-------------------------------------------------------------------------------------
-- datumSource

foreign import datumSource_free :: DatumSource -> Effect Unit
foreign import datumSource_new :: PlutusData -> DatumSource
foreign import datumSource_newRefIn :: TxIn -> DatumSource

type DatumSourceClass = { free :: DatumSource -> Effect Unit, new :: PlutusData -> DatumSource, newRefIn :: TxIn -> DatumSource }

datumSource :: DatumSourceClass
datumSource = { free: datumSource_free, new: datumSource_new, newRefIn: datumSource_newRefIn }

-------------------------------------------------------------------------------------
-- ed25519KeyHash

foreign import ed25519KeyHash_free :: Ed25519KeyHash -> Effect Unit
foreign import ed25519KeyHash_fromBytes :: Bytes -> Ed25519KeyHash
foreign import ed25519KeyHash_toBytes :: Ed25519KeyHash -> Bytes
foreign import ed25519KeyHash_toBech32 :: Ed25519KeyHash -> String -> String
foreign import ed25519KeyHash_fromBech32 :: String -> Ed25519KeyHash
foreign import ed25519KeyHash_toHex :: Ed25519KeyHash -> String
foreign import ed25519KeyHash_fromHex :: String -> Ed25519KeyHash

type Ed25519KeyHashClass = { free :: Ed25519KeyHash -> Effect Unit, fromBytes :: Bytes -> Ed25519KeyHash, toBytes :: Ed25519KeyHash -> Bytes, toBech32 :: Ed25519KeyHash -> String -> String, fromBech32 :: String -> Ed25519KeyHash, toHex :: Ed25519KeyHash -> String, fromHex :: String -> Ed25519KeyHash }

ed25519KeyHash :: Ed25519KeyHashClass
ed25519KeyHash = { free: ed25519KeyHash_free, fromBytes: ed25519KeyHash_fromBytes, toBytes: ed25519KeyHash_toBytes, toBech32: ed25519KeyHash_toBech32, fromBech32: ed25519KeyHash_fromBech32, toHex: ed25519KeyHash_toHex, fromHex: ed25519KeyHash_fromHex }

-------------------------------------------------------------------------------------
-- ed25519KeyHashes

foreign import ed25519KeyHashes_free :: Ed25519KeyHashes -> Effect Unit
foreign import ed25519KeyHashes_toBytes :: Ed25519KeyHashes -> Bytes
foreign import ed25519KeyHashes_fromBytes :: Bytes -> Ed25519KeyHashes
foreign import ed25519KeyHashes_toHex :: Ed25519KeyHashes -> String
foreign import ed25519KeyHashes_fromHex :: String -> Ed25519KeyHashes
foreign import ed25519KeyHashes_toJson :: Ed25519KeyHashes -> String
foreign import ed25519KeyHashes_toJsValue :: Ed25519KeyHashes -> Ed25519KeyHashesJs
foreign import ed25519KeyHashes_fromJson :: String -> Ed25519KeyHashes
foreign import ed25519KeyHashes_new :: Ed25519KeyHashes
foreign import ed25519KeyHashes_len :: Ed25519KeyHashes -> Number
foreign import ed25519KeyHashes_get :: Ed25519KeyHashes -> Number -> Ed25519KeyHash
foreign import ed25519KeyHashes_add :: Ed25519KeyHashes -> Ed25519KeyHash -> Effect Unit
foreign import ed25519KeyHashes_toOption :: Ed25519KeyHashes -> Maybe Ed25519KeyHashes

type Ed25519KeyHashesClass = { free :: Ed25519KeyHashes -> Effect Unit, toBytes :: Ed25519KeyHashes -> Bytes, fromBytes :: Bytes -> Ed25519KeyHashes, toHex :: Ed25519KeyHashes -> String, fromHex :: String -> Ed25519KeyHashes, toJson :: Ed25519KeyHashes -> String, toJsValue :: Ed25519KeyHashes -> Ed25519KeyHashesJs, fromJson :: String -> Ed25519KeyHashes, new :: Ed25519KeyHashes, len :: Ed25519KeyHashes -> Number, get :: Ed25519KeyHashes -> Number -> Ed25519KeyHash, add :: Ed25519KeyHashes -> Ed25519KeyHash -> Effect Unit, toOption :: Ed25519KeyHashes -> Maybe Ed25519KeyHashes }

ed25519KeyHashes :: Ed25519KeyHashesClass
ed25519KeyHashes = { free: ed25519KeyHashes_free, toBytes: ed25519KeyHashes_toBytes, fromBytes: ed25519KeyHashes_fromBytes, toHex: ed25519KeyHashes_toHex, fromHex: ed25519KeyHashes_fromHex, toJson: ed25519KeyHashes_toJson, toJsValue: ed25519KeyHashes_toJsValue, fromJson: ed25519KeyHashes_fromJson, new: ed25519KeyHashes_new, len: ed25519KeyHashes_len, get: ed25519KeyHashes_get, add: ed25519KeyHashes_add, toOption: ed25519KeyHashes_toOption }

-------------------------------------------------------------------------------------
-- ed25519Signature

foreign import ed25519Signature_free :: Ed25519Signature -> Effect Unit
foreign import ed25519Signature_toBytes :: Ed25519Signature -> Bytes
foreign import ed25519Signature_toBech32 :: Ed25519Signature -> String
foreign import ed25519Signature_toHex :: Ed25519Signature -> String
foreign import ed25519Signature_fromBech32 :: String -> Ed25519Signature
foreign import ed25519Signature_fromHex :: String -> Ed25519Signature
foreign import ed25519Signature_fromBytes :: Bytes -> Ed25519Signature

type Ed25519SignatureClass = { free :: Ed25519Signature -> Effect Unit, toBytes :: Ed25519Signature -> Bytes, toBech32 :: Ed25519Signature -> String, toHex :: Ed25519Signature -> String, fromBech32 :: String -> Ed25519Signature, fromHex :: String -> Ed25519Signature, fromBytes :: Bytes -> Ed25519Signature }

ed25519Signature :: Ed25519SignatureClass
ed25519Signature = { free: ed25519Signature_free, toBytes: ed25519Signature_toBytes, toBech32: ed25519Signature_toBech32, toHex: ed25519Signature_toHex, fromBech32: ed25519Signature_fromBech32, fromHex: ed25519Signature_fromHex, fromBytes: ed25519Signature_fromBytes }

-------------------------------------------------------------------------------------
-- enterpriseAddress

foreign import enterpriseAddress_free :: EnterpriseAddress -> Effect Unit
foreign import enterpriseAddress_new :: Number -> StakeCredential -> EnterpriseAddress
foreign import enterpriseAddress_paymentCred :: EnterpriseAddress -> StakeCredential
foreign import enterpriseAddress_toAddress :: EnterpriseAddress -> Address
foreign import enterpriseAddress_fromAddress :: Address -> Maybe EnterpriseAddress

type EnterpriseAddressClass = { free :: EnterpriseAddress -> Effect Unit, new :: Number -> StakeCredential -> EnterpriseAddress, paymentCred :: EnterpriseAddress -> StakeCredential, toAddress :: EnterpriseAddress -> Address, fromAddress :: Address -> Maybe EnterpriseAddress }

enterpriseAddress :: EnterpriseAddressClass
enterpriseAddress = { free: enterpriseAddress_free, new: enterpriseAddress_new, paymentCred: enterpriseAddress_paymentCred, toAddress: enterpriseAddress_toAddress, fromAddress: enterpriseAddress_fromAddress }

-------------------------------------------------------------------------------------
-- exUnitPrices

foreign import exUnitPrices_free :: ExUnitPrices -> Effect Unit
foreign import exUnitPrices_toBytes :: ExUnitPrices -> Bytes
foreign import exUnitPrices_fromBytes :: Bytes -> ExUnitPrices
foreign import exUnitPrices_toHex :: ExUnitPrices -> String
foreign import exUnitPrices_fromHex :: String -> ExUnitPrices
foreign import exUnitPrices_toJson :: ExUnitPrices -> String
foreign import exUnitPrices_toJsValue :: ExUnitPrices -> ExUnitPricesJs
foreign import exUnitPrices_fromJson :: String -> ExUnitPrices
foreign import exUnitPrices_memPrice :: ExUnitPrices -> UnitInterval
foreign import exUnitPrices_stepPrice :: ExUnitPrices -> UnitInterval
foreign import exUnitPrices_new :: UnitInterval -> UnitInterval -> ExUnitPrices

type ExUnitPricesClass = { free :: ExUnitPrices -> Effect Unit, toBytes :: ExUnitPrices -> Bytes, fromBytes :: Bytes -> ExUnitPrices, toHex :: ExUnitPrices -> String, fromHex :: String -> ExUnitPrices, toJson :: ExUnitPrices -> String, toJsValue :: ExUnitPrices -> ExUnitPricesJs, fromJson :: String -> ExUnitPrices, memPrice :: ExUnitPrices -> UnitInterval, stepPrice :: ExUnitPrices -> UnitInterval, new :: UnitInterval -> UnitInterval -> ExUnitPrices }

exUnitPrices :: ExUnitPricesClass
exUnitPrices = { free: exUnitPrices_free, toBytes: exUnitPrices_toBytes, fromBytes: exUnitPrices_fromBytes, toHex: exUnitPrices_toHex, fromHex: exUnitPrices_fromHex, toJson: exUnitPrices_toJson, toJsValue: exUnitPrices_toJsValue, fromJson: exUnitPrices_fromJson, memPrice: exUnitPrices_memPrice, stepPrice: exUnitPrices_stepPrice, new: exUnitPrices_new }

-------------------------------------------------------------------------------------
-- exUnits

foreign import exUnits_free :: ExUnits -> Effect Unit
foreign import exUnits_toBytes :: ExUnits -> Bytes
foreign import exUnits_fromBytes :: Bytes -> ExUnits
foreign import exUnits_toHex :: ExUnits -> String
foreign import exUnits_fromHex :: String -> ExUnits
foreign import exUnits_toJson :: ExUnits -> String
foreign import exUnits_toJsValue :: ExUnits -> ExUnitsJs
foreign import exUnits_fromJson :: String -> ExUnits
foreign import exUnits_mem :: ExUnits -> BigNum
foreign import exUnits_steps :: ExUnits -> BigNum
foreign import exUnits_new :: BigNum -> BigNum -> ExUnits

type ExUnitsClass = { free :: ExUnits -> Effect Unit, toBytes :: ExUnits -> Bytes, fromBytes :: Bytes -> ExUnits, toHex :: ExUnits -> String, fromHex :: String -> ExUnits, toJson :: ExUnits -> String, toJsValue :: ExUnits -> ExUnitsJs, fromJson :: String -> ExUnits, mem :: ExUnits -> BigNum, steps :: ExUnits -> BigNum, new :: BigNum -> BigNum -> ExUnits }

exUnits :: ExUnitsClass
exUnits = { free: exUnits_free, toBytes: exUnits_toBytes, fromBytes: exUnits_fromBytes, toHex: exUnits_toHex, fromHex: exUnits_fromHex, toJson: exUnits_toJson, toJsValue: exUnits_toJsValue, fromJson: exUnits_fromJson, mem: exUnits_mem, steps: exUnits_steps, new: exUnits_new }

-------------------------------------------------------------------------------------
-- generalTxMetadata

foreign import generalTxMetadata_free :: GeneralTxMetadata -> Effect Unit
foreign import generalTxMetadata_toBytes :: GeneralTxMetadata -> Bytes
foreign import generalTxMetadata_fromBytes :: Bytes -> GeneralTxMetadata
foreign import generalTxMetadata_toHex :: GeneralTxMetadata -> String
foreign import generalTxMetadata_fromHex :: String -> GeneralTxMetadata
foreign import generalTxMetadata_toJson :: GeneralTxMetadata -> String
foreign import generalTxMetadata_toJsValue :: GeneralTxMetadata -> GeneralTxMetadataJs
foreign import generalTxMetadata_fromJson :: String -> GeneralTxMetadata
foreign import generalTxMetadata_new :: GeneralTxMetadata
foreign import generalTxMetadata_len :: GeneralTxMetadata -> Number
foreign import generalTxMetadata_insert :: GeneralTxMetadata -> BigNum -> TxMetadatum -> Maybe TxMetadatum
foreign import generalTxMetadata_get :: GeneralTxMetadata -> BigNum -> Maybe TxMetadatum
foreign import generalTxMetadata_keys :: GeneralTxMetadata -> TxMetadatumLabels

type GeneralTxMetadataClass = { free :: GeneralTxMetadata -> Effect Unit, toBytes :: GeneralTxMetadata -> Bytes, fromBytes :: Bytes -> GeneralTxMetadata, toHex :: GeneralTxMetadata -> String, fromHex :: String -> GeneralTxMetadata, toJson :: GeneralTxMetadata -> String, toJsValue :: GeneralTxMetadata -> GeneralTxMetadataJs, fromJson :: String -> GeneralTxMetadata, new :: GeneralTxMetadata, len :: GeneralTxMetadata -> Number, insert :: GeneralTxMetadata -> BigNum -> TxMetadatum -> Maybe TxMetadatum, get :: GeneralTxMetadata -> BigNum -> Maybe TxMetadatum, keys :: GeneralTxMetadata -> TxMetadatumLabels }

generalTxMetadata :: GeneralTxMetadataClass
generalTxMetadata = { free: generalTxMetadata_free, toBytes: generalTxMetadata_toBytes, fromBytes: generalTxMetadata_fromBytes, toHex: generalTxMetadata_toHex, fromHex: generalTxMetadata_fromHex, toJson: generalTxMetadata_toJson, toJsValue: generalTxMetadata_toJsValue, fromJson: generalTxMetadata_fromJson, new: generalTxMetadata_new, len: generalTxMetadata_len, insert: generalTxMetadata_insert, get: generalTxMetadata_get, keys: generalTxMetadata_keys }

-------------------------------------------------------------------------------------
-- genesisDelegateHash

foreign import genesisDelegateHash_free :: GenesisDelegateHash -> Effect Unit
foreign import genesisDelegateHash_fromBytes :: Bytes -> GenesisDelegateHash
foreign import genesisDelegateHash_toBytes :: GenesisDelegateHash -> Bytes
foreign import genesisDelegateHash_toBech32 :: GenesisDelegateHash -> String -> String
foreign import genesisDelegateHash_fromBech32 :: String -> GenesisDelegateHash
foreign import genesisDelegateHash_toHex :: GenesisDelegateHash -> String
foreign import genesisDelegateHash_fromHex :: String -> GenesisDelegateHash

type GenesisDelegateHashClass = { free :: GenesisDelegateHash -> Effect Unit, fromBytes :: Bytes -> GenesisDelegateHash, toBytes :: GenesisDelegateHash -> Bytes, toBech32 :: GenesisDelegateHash -> String -> String, fromBech32 :: String -> GenesisDelegateHash, toHex :: GenesisDelegateHash -> String, fromHex :: String -> GenesisDelegateHash }

genesisDelegateHash :: GenesisDelegateHashClass
genesisDelegateHash = { free: genesisDelegateHash_free, fromBytes: genesisDelegateHash_fromBytes, toBytes: genesisDelegateHash_toBytes, toBech32: genesisDelegateHash_toBech32, fromBech32: genesisDelegateHash_fromBech32, toHex: genesisDelegateHash_toHex, fromHex: genesisDelegateHash_fromHex }

-------------------------------------------------------------------------------------
-- genesisHash

foreign import genesisHash_free :: GenesisHash -> Effect Unit
foreign import genesisHash_fromBytes :: Bytes -> GenesisHash
foreign import genesisHash_toBytes :: GenesisHash -> Bytes
foreign import genesisHash_toBech32 :: GenesisHash -> String -> String
foreign import genesisHash_fromBech32 :: String -> GenesisHash
foreign import genesisHash_toHex :: GenesisHash -> String
foreign import genesisHash_fromHex :: String -> GenesisHash

type GenesisHashClass = { free :: GenesisHash -> Effect Unit, fromBytes :: Bytes -> GenesisHash, toBytes :: GenesisHash -> Bytes, toBech32 :: GenesisHash -> String -> String, fromBech32 :: String -> GenesisHash, toHex :: GenesisHash -> String, fromHex :: String -> GenesisHash }

genesisHash :: GenesisHashClass
genesisHash = { free: genesisHash_free, fromBytes: genesisHash_fromBytes, toBytes: genesisHash_toBytes, toBech32: genesisHash_toBech32, fromBech32: genesisHash_fromBech32, toHex: genesisHash_toHex, fromHex: genesisHash_fromHex }

-------------------------------------------------------------------------------------
-- genesisHashes

foreign import genesisHashes_free :: GenesisHashes -> Effect Unit
foreign import genesisHashes_toBytes :: GenesisHashes -> Bytes
foreign import genesisHashes_fromBytes :: Bytes -> GenesisHashes
foreign import genesisHashes_toHex :: GenesisHashes -> String
foreign import genesisHashes_fromHex :: String -> GenesisHashes
foreign import genesisHashes_toJson :: GenesisHashes -> String
foreign import genesisHashes_toJsValue :: GenesisHashes -> GenesisHashesJs
foreign import genesisHashes_fromJson :: String -> GenesisHashes
foreign import genesisHashes_new :: GenesisHashes
foreign import genesisHashes_len :: GenesisHashes -> Number
foreign import genesisHashes_get :: GenesisHashes -> Number -> GenesisHash
foreign import genesisHashes_add :: GenesisHashes -> GenesisHash -> Effect Unit

type GenesisHashesClass = { free :: GenesisHashes -> Effect Unit, toBytes :: GenesisHashes -> Bytes, fromBytes :: Bytes -> GenesisHashes, toHex :: GenesisHashes -> String, fromHex :: String -> GenesisHashes, toJson :: GenesisHashes -> String, toJsValue :: GenesisHashes -> GenesisHashesJs, fromJson :: String -> GenesisHashes, new :: GenesisHashes, len :: GenesisHashes -> Number, get :: GenesisHashes -> Number -> GenesisHash, add :: GenesisHashes -> GenesisHash -> Effect Unit }

genesisHashes :: GenesisHashesClass
genesisHashes = { free: genesisHashes_free, toBytes: genesisHashes_toBytes, fromBytes: genesisHashes_fromBytes, toHex: genesisHashes_toHex, fromHex: genesisHashes_fromHex, toJson: genesisHashes_toJson, toJsValue: genesisHashes_toJsValue, fromJson: genesisHashes_fromJson, new: genesisHashes_new, len: genesisHashes_len, get: genesisHashes_get, add: genesisHashes_add }

-------------------------------------------------------------------------------------
-- genesisKeyDelegation

foreign import genesisKeyDelegation_free :: GenesisKeyDelegation -> Effect Unit
foreign import genesisKeyDelegation_toBytes :: GenesisKeyDelegation -> Bytes
foreign import genesisKeyDelegation_fromBytes :: Bytes -> GenesisKeyDelegation
foreign import genesisKeyDelegation_toHex :: GenesisKeyDelegation -> String
foreign import genesisKeyDelegation_fromHex :: String -> GenesisKeyDelegation
foreign import genesisKeyDelegation_toJson :: GenesisKeyDelegation -> String
foreign import genesisKeyDelegation_toJsValue :: GenesisKeyDelegation -> GenesisKeyDelegationJs
foreign import genesisKeyDelegation_fromJson :: String -> GenesisKeyDelegation
foreign import genesisKeyDelegation_genesishash :: GenesisKeyDelegation -> GenesisHash
foreign import genesisKeyDelegation_genesisDelegateHash :: GenesisKeyDelegation -> GenesisDelegateHash
foreign import genesisKeyDelegation_vrfKeyhash :: GenesisKeyDelegation -> VRFKeyHash
foreign import genesisKeyDelegation_new :: GenesisHash -> GenesisDelegateHash -> VRFKeyHash -> GenesisKeyDelegation

type GenesisKeyDelegationClass = { free :: GenesisKeyDelegation -> Effect Unit, toBytes :: GenesisKeyDelegation -> Bytes, fromBytes :: Bytes -> GenesisKeyDelegation, toHex :: GenesisKeyDelegation -> String, fromHex :: String -> GenesisKeyDelegation, toJson :: GenesisKeyDelegation -> String, toJsValue :: GenesisKeyDelegation -> GenesisKeyDelegationJs, fromJson :: String -> GenesisKeyDelegation, genesishash :: GenesisKeyDelegation -> GenesisHash, genesisDelegateHash :: GenesisKeyDelegation -> GenesisDelegateHash, vrfKeyhash :: GenesisKeyDelegation -> VRFKeyHash, new :: GenesisHash -> GenesisDelegateHash -> VRFKeyHash -> GenesisKeyDelegation }

genesisKeyDelegation :: GenesisKeyDelegationClass
genesisKeyDelegation = { free: genesisKeyDelegation_free, toBytes: genesisKeyDelegation_toBytes, fromBytes: genesisKeyDelegation_fromBytes, toHex: genesisKeyDelegation_toHex, fromHex: genesisKeyDelegation_fromHex, toJson: genesisKeyDelegation_toJson, toJsValue: genesisKeyDelegation_toJsValue, fromJson: genesisKeyDelegation_fromJson, genesishash: genesisKeyDelegation_genesishash, genesisDelegateHash: genesisKeyDelegation_genesisDelegateHash, vrfKeyhash: genesisKeyDelegation_vrfKeyhash, new: genesisKeyDelegation_new }

-------------------------------------------------------------------------------------
-- header

foreign import header_free :: Header -> Effect Unit
foreign import header_toBytes :: Header -> Bytes
foreign import header_fromBytes :: Bytes -> Header
foreign import header_toHex :: Header -> String
foreign import header_fromHex :: String -> Header
foreign import header_toJson :: Header -> String
foreign import header_toJsValue :: Header -> HeaderJs
foreign import header_fromJson :: String -> Header
foreign import header_headerBody :: Header -> HeaderBody
foreign import header_bodySignature :: Header -> KESSignature
foreign import header_new :: HeaderBody -> KESSignature -> Header

type HeaderClass = { free :: Header -> Effect Unit, toBytes :: Header -> Bytes, fromBytes :: Bytes -> Header, toHex :: Header -> String, fromHex :: String -> Header, toJson :: Header -> String, toJsValue :: Header -> HeaderJs, fromJson :: String -> Header, headerBody :: Header -> HeaderBody, bodySignature :: Header -> KESSignature, new :: HeaderBody -> KESSignature -> Header }

header :: HeaderClass
header = { free: header_free, toBytes: header_toBytes, fromBytes: header_fromBytes, toHex: header_toHex, fromHex: header_fromHex, toJson: header_toJson, toJsValue: header_toJsValue, fromJson: header_fromJson, headerBody: header_headerBody, bodySignature: header_bodySignature, new: header_new }

-------------------------------------------------------------------------------------
-- headerBody

foreign import headerBody_free :: HeaderBody -> Effect Unit
foreign import headerBody_toBytes :: HeaderBody -> Bytes
foreign import headerBody_fromBytes :: Bytes -> HeaderBody
foreign import headerBody_toHex :: HeaderBody -> String
foreign import headerBody_fromHex :: String -> HeaderBody
foreign import headerBody_toJson :: HeaderBody -> String
foreign import headerBody_toJsValue :: HeaderBody -> HeaderBodyJs
foreign import headerBody_fromJson :: String -> HeaderBody
foreign import headerBody_blockNumber :: HeaderBody -> Number
foreign import headerBody_slot :: HeaderBody -> Number
foreign import headerBody_slotBignum :: HeaderBody -> BigNum
foreign import headerBody_prevHash :: HeaderBody -> Maybe BlockHash
foreign import headerBody_issuerVkey :: HeaderBody -> Vkey
foreign import headerBody_vrfVkey :: HeaderBody -> VRFVKey
foreign import headerBody_hasNonceAndLeaderVrf :: HeaderBody -> Boolean
foreign import headerBody_nonceVrfOrNothing :: HeaderBody -> Maybe VRFCert
foreign import headerBody_leaderVrfOrNothing :: HeaderBody -> Maybe VRFCert
foreign import headerBody_hasVrfResult :: HeaderBody -> Boolean
foreign import headerBody_vrfResultOrNothing :: HeaderBody -> Maybe VRFCert
foreign import headerBody_blockBodySize :: HeaderBody -> Number
foreign import headerBody_blockBodyHash :: HeaderBody -> BlockHash
foreign import headerBody_operationalCert :: HeaderBody -> OperationalCert
foreign import headerBody_protocolVersion :: HeaderBody -> ProtocolVersion
foreign import headerBody_new :: Number -> Number -> Maybe BlockHash -> Vkey -> VRFVKey -> VRFCert -> Number -> BlockHash -> OperationalCert -> ProtocolVersion -> HeaderBody
foreign import headerBody_newHeaderbody :: Number -> BigNum -> Maybe BlockHash -> Vkey -> VRFVKey -> VRFCert -> Number -> BlockHash -> OperationalCert -> ProtocolVersion -> HeaderBody

type HeaderBodyClass = { free :: HeaderBody -> Effect Unit, toBytes :: HeaderBody -> Bytes, fromBytes :: Bytes -> HeaderBody, toHex :: HeaderBody -> String, fromHex :: String -> HeaderBody, toJson :: HeaderBody -> String, toJsValue :: HeaderBody -> HeaderBodyJs, fromJson :: String -> HeaderBody, blockNumber :: HeaderBody -> Number, slot :: HeaderBody -> Number, slotBignum :: HeaderBody -> BigNum, prevHash :: HeaderBody -> Maybe BlockHash, issuerVkey :: HeaderBody -> Vkey, vrfVkey :: HeaderBody -> VRFVKey, hasNonceAndLeaderVrf :: HeaderBody -> Boolean, nonceVrfOrNothing :: HeaderBody -> Maybe VRFCert, leaderVrfOrNothing :: HeaderBody -> Maybe VRFCert, hasVrfResult :: HeaderBody -> Boolean, vrfResultOrNothing :: HeaderBody -> Maybe VRFCert, blockBodySize :: HeaderBody -> Number, blockBodyHash :: HeaderBody -> BlockHash, operationalCert :: HeaderBody -> OperationalCert, protocolVersion :: HeaderBody -> ProtocolVersion, new :: Number -> Number -> Maybe BlockHash -> Vkey -> VRFVKey -> VRFCert -> Number -> BlockHash -> OperationalCert -> ProtocolVersion -> HeaderBody, newHeaderbody :: Number -> BigNum -> Maybe BlockHash -> Vkey -> VRFVKey -> VRFCert -> Number -> BlockHash -> OperationalCert -> ProtocolVersion -> HeaderBody }

headerBody :: HeaderBodyClass
headerBody = { free: headerBody_free, toBytes: headerBody_toBytes, fromBytes: headerBody_fromBytes, toHex: headerBody_toHex, fromHex: headerBody_fromHex, toJson: headerBody_toJson, toJsValue: headerBody_toJsValue, fromJson: headerBody_fromJson, blockNumber: headerBody_blockNumber, slot: headerBody_slot, slotBignum: headerBody_slotBignum, prevHash: headerBody_prevHash, issuerVkey: headerBody_issuerVkey, vrfVkey: headerBody_vrfVkey, hasNonceAndLeaderVrf: headerBody_hasNonceAndLeaderVrf, nonceVrfOrNothing: headerBody_nonceVrfOrNothing, leaderVrfOrNothing: headerBody_leaderVrfOrNothing, hasVrfResult: headerBody_hasVrfResult, vrfResultOrNothing: headerBody_vrfResultOrNothing, blockBodySize: headerBody_blockBodySize, blockBodyHash: headerBody_blockBodyHash, operationalCert: headerBody_operationalCert, protocolVersion: headerBody_protocolVersion, new: headerBody_new, newHeaderbody: headerBody_newHeaderbody }

-------------------------------------------------------------------------------------
-- int

foreign import int_free :: Int -> Effect Unit
foreign import int_toBytes :: Int -> Bytes
foreign import int_fromBytes :: Bytes -> Int
foreign import int_toHex :: Int -> String
foreign import int_fromHex :: String -> Int
foreign import int_toJson :: Int -> String
foreign import int_toJsValue :: Int -> IntJs
foreign import int_fromJson :: String -> Int
foreign import int_new :: BigNum -> Int
foreign import int_newNegative :: BigNum -> Int
foreign import int_newI32 :: Number -> Int
foreign import int_isPositive :: Int -> Boolean
foreign import int_asPositive :: Int -> Maybe BigNum
foreign import int_asNegative :: Int -> Maybe BigNum
foreign import int_asI32 :: Int -> Maybe Number
foreign import int_asI32OrNothing :: Int -> Maybe Number
foreign import int_asI32OrFail :: Int -> Number
foreign import int_toStr :: Int -> String
foreign import int_fromStr :: String -> Int

type IntClass = { free :: Int -> Effect Unit, toBytes :: Int -> Bytes, fromBytes :: Bytes -> Int, toHex :: Int -> String, fromHex :: String -> Int, toJson :: Int -> String, toJsValue :: Int -> IntJs, fromJson :: String -> Int, new :: BigNum -> Int, newNegative :: BigNum -> Int, newI32 :: Number -> Int, isPositive :: Int -> Boolean, asPositive :: Int -> Maybe BigNum, asNegative :: Int -> Maybe BigNum, asI32 :: Int -> Maybe Number, asI32OrNothing :: Int -> Maybe Number, asI32OrFail :: Int -> Number, toStr :: Int -> String, fromStr :: String -> Int }

int :: IntClass
int = { free: int_free, toBytes: int_toBytes, fromBytes: int_fromBytes, toHex: int_toHex, fromHex: int_fromHex, toJson: int_toJson, toJsValue: int_toJsValue, fromJson: int_fromJson, new: int_new, newNegative: int_newNegative, newI32: int_newI32, isPositive: int_isPositive, asPositive: int_asPositive, asNegative: int_asNegative, asI32: int_asI32, asI32OrNothing: int_asI32OrNothing, asI32OrFail: int_asI32OrFail, toStr: int_toStr, fromStr: int_fromStr }

-------------------------------------------------------------------------------------
-- ipv4

foreign import ipv4_free :: Ipv4 -> Effect Unit
foreign import ipv4_toBytes :: Ipv4 -> Bytes
foreign import ipv4_fromBytes :: Bytes -> Ipv4
foreign import ipv4_toHex :: Ipv4 -> String
foreign import ipv4_fromHex :: String -> Ipv4
foreign import ipv4_toJson :: Ipv4 -> String
foreign import ipv4_toJsValue :: Ipv4 -> Ipv4Js
foreign import ipv4_fromJson :: String -> Ipv4
foreign import ipv4_new :: Bytes -> Ipv4
foreign import ipv4_ip :: Ipv4 -> Bytes

type Ipv4Class = { free :: Ipv4 -> Effect Unit, toBytes :: Ipv4 -> Bytes, fromBytes :: Bytes -> Ipv4, toHex :: Ipv4 -> String, fromHex :: String -> Ipv4, toJson :: Ipv4 -> String, toJsValue :: Ipv4 -> Ipv4Js, fromJson :: String -> Ipv4, new :: Bytes -> Ipv4, ip :: Ipv4 -> Bytes }

ipv4 :: Ipv4Class
ipv4 = { free: ipv4_free, toBytes: ipv4_toBytes, fromBytes: ipv4_fromBytes, toHex: ipv4_toHex, fromHex: ipv4_fromHex, toJson: ipv4_toJson, toJsValue: ipv4_toJsValue, fromJson: ipv4_fromJson, new: ipv4_new, ip: ipv4_ip }

-------------------------------------------------------------------------------------
-- ipv6

foreign import ipv6_free :: Ipv6 -> Effect Unit
foreign import ipv6_toBytes :: Ipv6 -> Bytes
foreign import ipv6_fromBytes :: Bytes -> Ipv6
foreign import ipv6_toHex :: Ipv6 -> String
foreign import ipv6_fromHex :: String -> Ipv6
foreign import ipv6_toJson :: Ipv6 -> String
foreign import ipv6_toJsValue :: Ipv6 -> Ipv6Js
foreign import ipv6_fromJson :: String -> Ipv6
foreign import ipv6_new :: Bytes -> Ipv6
foreign import ipv6_ip :: Ipv6 -> Bytes

type Ipv6Class = { free :: Ipv6 -> Effect Unit, toBytes :: Ipv6 -> Bytes, fromBytes :: Bytes -> Ipv6, toHex :: Ipv6 -> String, fromHex :: String -> Ipv6, toJson :: Ipv6 -> String, toJsValue :: Ipv6 -> Ipv6Js, fromJson :: String -> Ipv6, new :: Bytes -> Ipv6, ip :: Ipv6 -> Bytes }

ipv6 :: Ipv6Class
ipv6 = { free: ipv6_free, toBytes: ipv6_toBytes, fromBytes: ipv6_fromBytes, toHex: ipv6_toHex, fromHex: ipv6_fromHex, toJson: ipv6_toJson, toJsValue: ipv6_toJsValue, fromJson: ipv6_fromJson, new: ipv6_new, ip: ipv6_ip }

-------------------------------------------------------------------------------------
-- kESSignature

foreign import kESSignature_free :: KESSignature -> Effect Unit
foreign import kESSignature_toBytes :: KESSignature -> Bytes
foreign import kESSignature_fromBytes :: Bytes -> KESSignature

type KESSignatureClass = { free :: KESSignature -> Effect Unit, toBytes :: KESSignature -> Bytes, fromBytes :: Bytes -> KESSignature }

kESSignature :: KESSignatureClass
kESSignature = { free: kESSignature_free, toBytes: kESSignature_toBytes, fromBytes: kESSignature_fromBytes }

-------------------------------------------------------------------------------------
-- kESVKey

foreign import kESVKey_free :: KESVKey -> Effect Unit
foreign import kESVKey_fromBytes :: Bytes -> KESVKey
foreign import kESVKey_toBytes :: KESVKey -> Bytes
foreign import kESVKey_toBech32 :: KESVKey -> String -> String
foreign import kESVKey_fromBech32 :: String -> KESVKey
foreign import kESVKey_toHex :: KESVKey -> String
foreign import kESVKey_fromHex :: String -> KESVKey

type KESVKeyClass = { free :: KESVKey -> Effect Unit, fromBytes :: Bytes -> KESVKey, toBytes :: KESVKey -> Bytes, toBech32 :: KESVKey -> String -> String, fromBech32 :: String -> KESVKey, toHex :: KESVKey -> String, fromHex :: String -> KESVKey }

kESVKey :: KESVKeyClass
kESVKey = { free: kESVKey_free, fromBytes: kESVKey_fromBytes, toBytes: kESVKey_toBytes, toBech32: kESVKey_toBech32, fromBech32: kESVKey_fromBech32, toHex: kESVKey_toHex, fromHex: kESVKey_fromHex }

-------------------------------------------------------------------------------------
-- language

foreign import language_free :: Language -> Effect Unit
foreign import language_toBytes :: Language -> Bytes
foreign import language_fromBytes :: Bytes -> Language
foreign import language_toHex :: Language -> String
foreign import language_fromHex :: String -> Language
foreign import language_toJson :: Language -> String
foreign import language_toJsValue :: Language -> LanguageJs
foreign import language_fromJson :: String -> Language
foreign import language_newPlutusV1 :: Language
foreign import language_newPlutusV2 :: Language
foreign import language_kind :: Language -> Number

type LanguageClass = { free :: Language -> Effect Unit, toBytes :: Language -> Bytes, fromBytes :: Bytes -> Language, toHex :: Language -> String, fromHex :: String -> Language, toJson :: Language -> String, toJsValue :: Language -> LanguageJs, fromJson :: String -> Language, newPlutusV1 :: Language, newPlutusV2 :: Language, kind :: Language -> Number }

language :: LanguageClass
language = { free: language_free, toBytes: language_toBytes, fromBytes: language_fromBytes, toHex: language_toHex, fromHex: language_fromHex, toJson: language_toJson, toJsValue: language_toJsValue, fromJson: language_fromJson, newPlutusV1: language_newPlutusV1, newPlutusV2: language_newPlutusV2, kind: language_kind }

-------------------------------------------------------------------------------------
-- languages

foreign import languages_free :: Languages -> Effect Unit
foreign import languages_new :: Languages
foreign import languages_len :: Languages -> Number
foreign import languages_get :: Languages -> Number -> Language
foreign import languages_add :: Languages -> Language -> Effect Unit

type LanguagesClass = { free :: Languages -> Effect Unit, new :: Languages, len :: Languages -> Number, get :: Languages -> Number -> Language, add :: Languages -> Language -> Effect Unit }

languages :: LanguagesClass
languages = { free: languages_free, new: languages_new, len: languages_len, get: languages_get, add: languages_add }

-------------------------------------------------------------------------------------
-- legacyDaedalusPrivateKey

foreign import legacyDaedalusPrivateKey_free :: LegacyDaedalusPrivateKey -> Effect Unit
foreign import legacyDaedalusPrivateKey_fromBytes :: Bytes -> LegacyDaedalusPrivateKey
foreign import legacyDaedalusPrivateKey_asBytes :: LegacyDaedalusPrivateKey -> Bytes
foreign import legacyDaedalusPrivateKey_chaincode :: LegacyDaedalusPrivateKey -> Bytes

type LegacyDaedalusPrivateKeyClass = { free :: LegacyDaedalusPrivateKey -> Effect Unit, fromBytes :: Bytes -> LegacyDaedalusPrivateKey, asBytes :: LegacyDaedalusPrivateKey -> Bytes, chaincode :: LegacyDaedalusPrivateKey -> Bytes }

legacyDaedalusPrivateKey :: LegacyDaedalusPrivateKeyClass
legacyDaedalusPrivateKey = { free: legacyDaedalusPrivateKey_free, fromBytes: legacyDaedalusPrivateKey_fromBytes, asBytes: legacyDaedalusPrivateKey_asBytes, chaincode: legacyDaedalusPrivateKey_chaincode }

-------------------------------------------------------------------------------------
-- linearFee

foreign import linearFee_free :: LinearFee -> Effect Unit
foreign import linearFee_constant :: LinearFee -> BigNum
foreign import linearFee_coefficient :: LinearFee -> BigNum
foreign import linearFee_new :: BigNum -> BigNum -> LinearFee

type LinearFeeClass = { free :: LinearFee -> Effect Unit, constant :: LinearFee -> BigNum, coefficient :: LinearFee -> BigNum, new :: BigNum -> BigNum -> LinearFee }

linearFee :: LinearFeeClass
linearFee = { free: linearFee_free, constant: linearFee_constant, coefficient: linearFee_coefficient, new: linearFee_new }

-------------------------------------------------------------------------------------
-- mIRToStakeCredentials

foreign import mIRToStakeCredentials_free :: MIRToStakeCredentials -> Effect Unit
foreign import mIRToStakeCredentials_toBytes :: MIRToStakeCredentials -> Bytes
foreign import mIRToStakeCredentials_fromBytes :: Bytes -> MIRToStakeCredentials
foreign import mIRToStakeCredentials_toHex :: MIRToStakeCredentials -> String
foreign import mIRToStakeCredentials_fromHex :: String -> MIRToStakeCredentials
foreign import mIRToStakeCredentials_toJson :: MIRToStakeCredentials -> String
foreign import mIRToStakeCredentials_toJsValue :: MIRToStakeCredentials -> MIRToStakeCredentialsJs
foreign import mIRToStakeCredentials_fromJson :: String -> MIRToStakeCredentials
foreign import mIRToStakeCredentials_new :: MIRToStakeCredentials
foreign import mIRToStakeCredentials_len :: MIRToStakeCredentials -> Number
foreign import mIRToStakeCredentials_insert :: MIRToStakeCredentials -> StakeCredential -> Int -> Maybe Int
foreign import mIRToStakeCredentials_get :: MIRToStakeCredentials -> StakeCredential -> Maybe Int
foreign import mIRToStakeCredentials_keys :: MIRToStakeCredentials -> StakeCredentials

type MIRToStakeCredentialsClass = { free :: MIRToStakeCredentials -> Effect Unit, toBytes :: MIRToStakeCredentials -> Bytes, fromBytes :: Bytes -> MIRToStakeCredentials, toHex :: MIRToStakeCredentials -> String, fromHex :: String -> MIRToStakeCredentials, toJson :: MIRToStakeCredentials -> String, toJsValue :: MIRToStakeCredentials -> MIRToStakeCredentialsJs, fromJson :: String -> MIRToStakeCredentials, new :: MIRToStakeCredentials, len :: MIRToStakeCredentials -> Number, insert :: MIRToStakeCredentials -> StakeCredential -> Int -> Maybe Int, get :: MIRToStakeCredentials -> StakeCredential -> Maybe Int, keys :: MIRToStakeCredentials -> StakeCredentials }

mIRToStakeCredentials :: MIRToStakeCredentialsClass
mIRToStakeCredentials = { free: mIRToStakeCredentials_free, toBytes: mIRToStakeCredentials_toBytes, fromBytes: mIRToStakeCredentials_fromBytes, toHex: mIRToStakeCredentials_toHex, fromHex: mIRToStakeCredentials_fromHex, toJson: mIRToStakeCredentials_toJson, toJsValue: mIRToStakeCredentials_toJsValue, fromJson: mIRToStakeCredentials_fromJson, new: mIRToStakeCredentials_new, len: mIRToStakeCredentials_len, insert: mIRToStakeCredentials_insert, get: mIRToStakeCredentials_get, keys: mIRToStakeCredentials_keys }

-------------------------------------------------------------------------------------
-- metadataList

foreign import metadataList_free :: MetadataList -> Effect Unit
foreign import metadataList_toBytes :: MetadataList -> Bytes
foreign import metadataList_fromBytes :: Bytes -> MetadataList
foreign import metadataList_toHex :: MetadataList -> String
foreign import metadataList_fromHex :: String -> MetadataList
foreign import metadataList_new :: MetadataList
foreign import metadataList_len :: MetadataList -> Number
foreign import metadataList_get :: MetadataList -> Number -> TxMetadatum
foreign import metadataList_add :: MetadataList -> TxMetadatum -> Effect Unit

type MetadataListClass = { free :: MetadataList -> Effect Unit, toBytes :: MetadataList -> Bytes, fromBytes :: Bytes -> MetadataList, toHex :: MetadataList -> String, fromHex :: String -> MetadataList, new :: MetadataList, len :: MetadataList -> Number, get :: MetadataList -> Number -> TxMetadatum, add :: MetadataList -> TxMetadatum -> Effect Unit }

metadataList :: MetadataListClass
metadataList = { free: metadataList_free, toBytes: metadataList_toBytes, fromBytes: metadataList_fromBytes, toHex: metadataList_toHex, fromHex: metadataList_fromHex, new: metadataList_new, len: metadataList_len, get: metadataList_get, add: metadataList_add }

-------------------------------------------------------------------------------------
-- metadataMap

foreign import metadataMap_free :: MetadataMap -> Effect Unit
foreign import metadataMap_toBytes :: MetadataMap -> Bytes
foreign import metadataMap_fromBytes :: Bytes -> MetadataMap
foreign import metadataMap_toHex :: MetadataMap -> String
foreign import metadataMap_fromHex :: String -> MetadataMap
foreign import metadataMap_new :: MetadataMap
foreign import metadataMap_len :: MetadataMap -> Number
foreign import metadataMap_insert :: MetadataMap -> TxMetadatum -> TxMetadatum -> Maybe TxMetadatum
foreign import metadataMap_insertStr :: MetadataMap -> String -> TxMetadatum -> Maybe TxMetadatum
foreign import metadataMap_insertI32 :: MetadataMap -> Number -> TxMetadatum -> Maybe TxMetadatum
foreign import metadataMap_get :: MetadataMap -> TxMetadatum -> TxMetadatum
foreign import metadataMap_getStr :: MetadataMap -> String -> TxMetadatum
foreign import metadataMap_getI32 :: MetadataMap -> Number -> TxMetadatum
foreign import metadataMap_has :: MetadataMap -> TxMetadatum -> Boolean
foreign import metadataMap_keys :: MetadataMap -> MetadataList

type MetadataMapClass = { free :: MetadataMap -> Effect Unit, toBytes :: MetadataMap -> Bytes, fromBytes :: Bytes -> MetadataMap, toHex :: MetadataMap -> String, fromHex :: String -> MetadataMap, new :: MetadataMap, len :: MetadataMap -> Number, insert :: MetadataMap -> TxMetadatum -> TxMetadatum -> Maybe TxMetadatum, insertStr :: MetadataMap -> String -> TxMetadatum -> Maybe TxMetadatum, insertI32 :: MetadataMap -> Number -> TxMetadatum -> Maybe TxMetadatum, get :: MetadataMap -> TxMetadatum -> TxMetadatum, getStr :: MetadataMap -> String -> TxMetadatum, getI32 :: MetadataMap -> Number -> TxMetadatum, has :: MetadataMap -> TxMetadatum -> Boolean, keys :: MetadataMap -> MetadataList }

metadataMap :: MetadataMapClass
metadataMap = { free: metadataMap_free, toBytes: metadataMap_toBytes, fromBytes: metadataMap_fromBytes, toHex: metadataMap_toHex, fromHex: metadataMap_fromHex, new: metadataMap_new, len: metadataMap_len, insert: metadataMap_insert, insertStr: metadataMap_insertStr, insertI32: metadataMap_insertI32, get: metadataMap_get, getStr: metadataMap_getStr, getI32: metadataMap_getI32, has: metadataMap_has, keys: metadataMap_keys }

-------------------------------------------------------------------------------------
-- mint

foreign import mint_free :: Mint -> Effect Unit
foreign import mint_toBytes :: Mint -> Bytes
foreign import mint_fromBytes :: Bytes -> Mint
foreign import mint_toHex :: Mint -> String
foreign import mint_fromHex :: String -> Mint
foreign import mint_toJson :: Mint -> String
foreign import mint_toJsValue :: Mint -> MintJs
foreign import mint_fromJson :: String -> Mint
foreign import mint_new :: Mint
foreign import mint_newFromEntry :: ScriptHash -> MintAssets -> Mint
foreign import mint_len :: Mint -> Number
foreign import mint_insert :: Mint -> ScriptHash -> MintAssets -> Maybe MintAssets
foreign import mint_get :: Mint -> ScriptHash -> Maybe MintAssets
foreign import mint_keys :: Mint -> ScriptHashes
foreign import mint_asPositiveMultiasset :: Mint -> MultiAsset
foreign import mint_asNegativeMultiasset :: Mint -> MultiAsset

type MintClass = { free :: Mint -> Effect Unit, toBytes :: Mint -> Bytes, fromBytes :: Bytes -> Mint, toHex :: Mint -> String, fromHex :: String -> Mint, toJson :: Mint -> String, toJsValue :: Mint -> MintJs, fromJson :: String -> Mint, new :: Mint, newFromEntry :: ScriptHash -> MintAssets -> Mint, len :: Mint -> Number, insert :: Mint -> ScriptHash -> MintAssets -> Maybe MintAssets, get :: Mint -> ScriptHash -> Maybe MintAssets, keys :: Mint -> ScriptHashes, asPositiveMultiasset :: Mint -> MultiAsset, asNegativeMultiasset :: Mint -> MultiAsset }

mint :: MintClass
mint = { free: mint_free, toBytes: mint_toBytes, fromBytes: mint_fromBytes, toHex: mint_toHex, fromHex: mint_fromHex, toJson: mint_toJson, toJsValue: mint_toJsValue, fromJson: mint_fromJson, new: mint_new, newFromEntry: mint_newFromEntry, len: mint_len, insert: mint_insert, get: mint_get, keys: mint_keys, asPositiveMultiasset: mint_asPositiveMultiasset, asNegativeMultiasset: mint_asNegativeMultiasset }

-------------------------------------------------------------------------------------
-- mintAssets

foreign import mintAssets_free :: MintAssets -> Effect Unit
foreign import mintAssets_new :: MintAssets
foreign import mintAssets_newFromEntry :: AssetName -> Int -> MintAssets
foreign import mintAssets_len :: MintAssets -> Number
foreign import mintAssets_insert :: MintAssets -> AssetName -> Int -> Maybe Int
foreign import mintAssets_get :: MintAssets -> AssetName -> Maybe Int
foreign import mintAssets_keys :: MintAssets -> AssetNames

type MintAssetsClass = { free :: MintAssets -> Effect Unit, new :: MintAssets, newFromEntry :: AssetName -> Int -> MintAssets, len :: MintAssets -> Number, insert :: MintAssets -> AssetName -> Int -> Maybe Int, get :: MintAssets -> AssetName -> Maybe Int, keys :: MintAssets -> AssetNames }

mintAssets :: MintAssetsClass
mintAssets = { free: mintAssets_free, new: mintAssets_new, newFromEntry: mintAssets_newFromEntry, len: mintAssets_len, insert: mintAssets_insert, get: mintAssets_get, keys: mintAssets_keys }

-------------------------------------------------------------------------------------
-- moveInstantaneousReward

foreign import moveInstantaneousReward_free :: MoveInstantaneousReward -> Effect Unit
foreign import moveInstantaneousReward_toBytes :: MoveInstantaneousReward -> Bytes
foreign import moveInstantaneousReward_fromBytes :: Bytes -> MoveInstantaneousReward
foreign import moveInstantaneousReward_toHex :: MoveInstantaneousReward -> String
foreign import moveInstantaneousReward_fromHex :: String -> MoveInstantaneousReward
foreign import moveInstantaneousReward_toJson :: MoveInstantaneousReward -> String
foreign import moveInstantaneousReward_toJsValue :: MoveInstantaneousReward -> MoveInstantaneousRewardJs
foreign import moveInstantaneousReward_fromJson :: String -> MoveInstantaneousReward
foreign import moveInstantaneousReward_newToOtherPot :: Number -> BigNum -> MoveInstantaneousReward
foreign import moveInstantaneousReward_newToStakeCreds :: Number -> MIRToStakeCredentials -> MoveInstantaneousReward
foreign import moveInstantaneousReward_pot :: MoveInstantaneousReward -> Number
foreign import moveInstantaneousReward_kind :: MoveInstantaneousReward -> Number
foreign import moveInstantaneousReward_asToOtherPot :: MoveInstantaneousReward -> Maybe BigNum
foreign import moveInstantaneousReward_asToStakeCreds :: MoveInstantaneousReward -> Maybe MIRToStakeCredentials

type MoveInstantaneousRewardClass = { free :: MoveInstantaneousReward -> Effect Unit, toBytes :: MoveInstantaneousReward -> Bytes, fromBytes :: Bytes -> MoveInstantaneousReward, toHex :: MoveInstantaneousReward -> String, fromHex :: String -> MoveInstantaneousReward, toJson :: MoveInstantaneousReward -> String, toJsValue :: MoveInstantaneousReward -> MoveInstantaneousRewardJs, fromJson :: String -> MoveInstantaneousReward, newToOtherPot :: Number -> BigNum -> MoveInstantaneousReward, newToStakeCreds :: Number -> MIRToStakeCredentials -> MoveInstantaneousReward, pot :: MoveInstantaneousReward -> Number, kind :: MoveInstantaneousReward -> Number, asToOtherPot :: MoveInstantaneousReward -> Maybe BigNum, asToStakeCreds :: MoveInstantaneousReward -> Maybe MIRToStakeCredentials }

moveInstantaneousReward :: MoveInstantaneousRewardClass
moveInstantaneousReward = { free: moveInstantaneousReward_free, toBytes: moveInstantaneousReward_toBytes, fromBytes: moveInstantaneousReward_fromBytes, toHex: moveInstantaneousReward_toHex, fromHex: moveInstantaneousReward_fromHex, toJson: moveInstantaneousReward_toJson, toJsValue: moveInstantaneousReward_toJsValue, fromJson: moveInstantaneousReward_fromJson, newToOtherPot: moveInstantaneousReward_newToOtherPot, newToStakeCreds: moveInstantaneousReward_newToStakeCreds, pot: moveInstantaneousReward_pot, kind: moveInstantaneousReward_kind, asToOtherPot: moveInstantaneousReward_asToOtherPot, asToStakeCreds: moveInstantaneousReward_asToStakeCreds }

-------------------------------------------------------------------------------------
-- moveInstantaneousRewardsCert

foreign import moveInstantaneousRewardsCert_free :: MoveInstantaneousRewardsCert -> Effect Unit
foreign import moveInstantaneousRewardsCert_toBytes :: MoveInstantaneousRewardsCert -> Bytes
foreign import moveInstantaneousRewardsCert_fromBytes :: Bytes -> MoveInstantaneousRewardsCert
foreign import moveInstantaneousRewardsCert_toHex :: MoveInstantaneousRewardsCert -> String
foreign import moveInstantaneousRewardsCert_fromHex :: String -> MoveInstantaneousRewardsCert
foreign import moveInstantaneousRewardsCert_toJson :: MoveInstantaneousRewardsCert -> String
foreign import moveInstantaneousRewardsCert_toJsValue :: MoveInstantaneousRewardsCert -> MoveInstantaneousRewardsCertJs
foreign import moveInstantaneousRewardsCert_fromJson :: String -> MoveInstantaneousRewardsCert
foreign import moveInstantaneousRewardsCert_moveInstantaneousReward :: MoveInstantaneousRewardsCert -> MoveInstantaneousReward
foreign import moveInstantaneousRewardsCert_new :: MoveInstantaneousReward -> MoveInstantaneousRewardsCert

type MoveInstantaneousRewardsCertClass = { free :: MoveInstantaneousRewardsCert -> Effect Unit, toBytes :: MoveInstantaneousRewardsCert -> Bytes, fromBytes :: Bytes -> MoveInstantaneousRewardsCert, toHex :: MoveInstantaneousRewardsCert -> String, fromHex :: String -> MoveInstantaneousRewardsCert, toJson :: MoveInstantaneousRewardsCert -> String, toJsValue :: MoveInstantaneousRewardsCert -> MoveInstantaneousRewardsCertJs, fromJson :: String -> MoveInstantaneousRewardsCert, moveInstantaneousReward :: MoveInstantaneousRewardsCert -> MoveInstantaneousReward, new :: MoveInstantaneousReward -> MoveInstantaneousRewardsCert }

moveInstantaneousRewardsCert :: MoveInstantaneousRewardsCertClass
moveInstantaneousRewardsCert = { free: moveInstantaneousRewardsCert_free, toBytes: moveInstantaneousRewardsCert_toBytes, fromBytes: moveInstantaneousRewardsCert_fromBytes, toHex: moveInstantaneousRewardsCert_toHex, fromHex: moveInstantaneousRewardsCert_fromHex, toJson: moveInstantaneousRewardsCert_toJson, toJsValue: moveInstantaneousRewardsCert_toJsValue, fromJson: moveInstantaneousRewardsCert_fromJson, moveInstantaneousReward: moveInstantaneousRewardsCert_moveInstantaneousReward, new: moveInstantaneousRewardsCert_new }

-------------------------------------------------------------------------------------
-- multiAsset

foreign import multiAsset_free :: MultiAsset -> Effect Unit
foreign import multiAsset_toBytes :: MultiAsset -> Bytes
foreign import multiAsset_fromBytes :: Bytes -> MultiAsset
foreign import multiAsset_toHex :: MultiAsset -> String
foreign import multiAsset_fromHex :: String -> MultiAsset
foreign import multiAsset_toJson :: MultiAsset -> String
foreign import multiAsset_toJsValue :: MultiAsset -> MultiAssetJs
foreign import multiAsset_fromJson :: String -> MultiAsset
foreign import multiAsset_new :: MultiAsset
foreign import multiAsset_len :: MultiAsset -> Number
foreign import multiAsset_insert :: MultiAsset -> ScriptHash -> Assets -> Maybe Assets
foreign import multiAsset_get :: MultiAsset -> ScriptHash -> Maybe Assets
foreign import multiAsset_setAsset :: MultiAsset -> ScriptHash -> AssetName -> BigNum -> Maybe BigNum
foreign import multiAsset_getAsset :: MultiAsset -> ScriptHash -> AssetName -> BigNum
foreign import multiAsset_keys :: MultiAsset -> ScriptHashes
foreign import multiAsset_sub :: MultiAsset -> MultiAsset -> MultiAsset

type MultiAssetClass = { free :: MultiAsset -> Effect Unit, toBytes :: MultiAsset -> Bytes, fromBytes :: Bytes -> MultiAsset, toHex :: MultiAsset -> String, fromHex :: String -> MultiAsset, toJson :: MultiAsset -> String, toJsValue :: MultiAsset -> MultiAssetJs, fromJson :: String -> MultiAsset, new :: MultiAsset, len :: MultiAsset -> Number, insert :: MultiAsset -> ScriptHash -> Assets -> Maybe Assets, get :: MultiAsset -> ScriptHash -> Maybe Assets, setAsset :: MultiAsset -> ScriptHash -> AssetName -> BigNum -> Maybe BigNum, getAsset :: MultiAsset -> ScriptHash -> AssetName -> BigNum, keys :: MultiAsset -> ScriptHashes, sub :: MultiAsset -> MultiAsset -> MultiAsset }

multiAsset :: MultiAssetClass
multiAsset = { free: multiAsset_free, toBytes: multiAsset_toBytes, fromBytes: multiAsset_fromBytes, toHex: multiAsset_toHex, fromHex: multiAsset_fromHex, toJson: multiAsset_toJson, toJsValue: multiAsset_toJsValue, fromJson: multiAsset_fromJson, new: multiAsset_new, len: multiAsset_len, insert: multiAsset_insert, get: multiAsset_get, setAsset: multiAsset_setAsset, getAsset: multiAsset_getAsset, keys: multiAsset_keys, sub: multiAsset_sub }

-------------------------------------------------------------------------------------
-- multiHostName

foreign import multiHostName_free :: MultiHostName -> Effect Unit
foreign import multiHostName_toBytes :: MultiHostName -> Bytes
foreign import multiHostName_fromBytes :: Bytes -> MultiHostName
foreign import multiHostName_toHex :: MultiHostName -> String
foreign import multiHostName_fromHex :: String -> MultiHostName
foreign import multiHostName_toJson :: MultiHostName -> String
foreign import multiHostName_toJsValue :: MultiHostName -> MultiHostNameJs
foreign import multiHostName_fromJson :: String -> MultiHostName
foreign import multiHostName_dnsName :: MultiHostName -> DNSRecordSRV
foreign import multiHostName_new :: DNSRecordSRV -> MultiHostName

type MultiHostNameClass = { free :: MultiHostName -> Effect Unit, toBytes :: MultiHostName -> Bytes, fromBytes :: Bytes -> MultiHostName, toHex :: MultiHostName -> String, fromHex :: String -> MultiHostName, toJson :: MultiHostName -> String, toJsValue :: MultiHostName -> MultiHostNameJs, fromJson :: String -> MultiHostName, dnsName :: MultiHostName -> DNSRecordSRV, new :: DNSRecordSRV -> MultiHostName }

multiHostName :: MultiHostNameClass
multiHostName = { free: multiHostName_free, toBytes: multiHostName_toBytes, fromBytes: multiHostName_fromBytes, toHex: multiHostName_toHex, fromHex: multiHostName_fromHex, toJson: multiHostName_toJson, toJsValue: multiHostName_toJsValue, fromJson: multiHostName_fromJson, dnsName: multiHostName_dnsName, new: multiHostName_new }

-------------------------------------------------------------------------------------
-- nativeScript

foreign import nativeScript_free :: NativeScript -> Effect Unit
foreign import nativeScript_toBytes :: NativeScript -> Bytes
foreign import nativeScript_fromBytes :: Bytes -> NativeScript
foreign import nativeScript_toHex :: NativeScript -> String
foreign import nativeScript_fromHex :: String -> NativeScript
foreign import nativeScript_toJson :: NativeScript -> String
foreign import nativeScript_toJsValue :: NativeScript -> NativeScriptJs
foreign import nativeScript_fromJson :: String -> NativeScript
foreign import nativeScript_hash :: NativeScript -> ScriptHash
foreign import nativeScript_newScriptPubkey :: ScriptPubkey -> NativeScript
foreign import nativeScript_newScriptAll :: ScriptAll -> NativeScript
foreign import nativeScript_newScriptAny :: ScriptAny -> NativeScript
foreign import nativeScript_newScriptNOfK :: ScriptNOfK -> NativeScript
foreign import nativeScript_newTimelockStart :: TimelockStart -> NativeScript
foreign import nativeScript_newTimelockExpiry :: TimelockExpiry -> NativeScript
foreign import nativeScript_kind :: NativeScript -> Number
foreign import nativeScript_asScriptPubkey :: NativeScript -> Maybe ScriptPubkey
foreign import nativeScript_asScriptAll :: NativeScript -> Maybe ScriptAll
foreign import nativeScript_asScriptAny :: NativeScript -> Maybe ScriptAny
foreign import nativeScript_asScriptNOfK :: NativeScript -> Maybe ScriptNOfK
foreign import nativeScript_asTimelockStart :: NativeScript -> Maybe TimelockStart
foreign import nativeScript_asTimelockExpiry :: NativeScript -> Maybe TimelockExpiry
foreign import nativeScript_getRequiredSigners :: NativeScript -> Ed25519KeyHashes

type NativeScriptClass = { free :: NativeScript -> Effect Unit, toBytes :: NativeScript -> Bytes, fromBytes :: Bytes -> NativeScript, toHex :: NativeScript -> String, fromHex :: String -> NativeScript, toJson :: NativeScript -> String, toJsValue :: NativeScript -> NativeScriptJs, fromJson :: String -> NativeScript, hash :: NativeScript -> ScriptHash, newScriptPubkey :: ScriptPubkey -> NativeScript, newScriptAll :: ScriptAll -> NativeScript, newScriptAny :: ScriptAny -> NativeScript, newScriptNOfK :: ScriptNOfK -> NativeScript, newTimelockStart :: TimelockStart -> NativeScript, newTimelockExpiry :: TimelockExpiry -> NativeScript, kind :: NativeScript -> Number, asScriptPubkey :: NativeScript -> Maybe ScriptPubkey, asScriptAll :: NativeScript -> Maybe ScriptAll, asScriptAny :: NativeScript -> Maybe ScriptAny, asScriptNOfK :: NativeScript -> Maybe ScriptNOfK, asTimelockStart :: NativeScript -> Maybe TimelockStart, asTimelockExpiry :: NativeScript -> Maybe TimelockExpiry, getRequiredSigners :: NativeScript -> Ed25519KeyHashes }

nativeScript :: NativeScriptClass
nativeScript = { free: nativeScript_free, toBytes: nativeScript_toBytes, fromBytes: nativeScript_fromBytes, toHex: nativeScript_toHex, fromHex: nativeScript_fromHex, toJson: nativeScript_toJson, toJsValue: nativeScript_toJsValue, fromJson: nativeScript_fromJson, hash: nativeScript_hash, newScriptPubkey: nativeScript_newScriptPubkey, newScriptAll: nativeScript_newScriptAll, newScriptAny: nativeScript_newScriptAny, newScriptNOfK: nativeScript_newScriptNOfK, newTimelockStart: nativeScript_newTimelockStart, newTimelockExpiry: nativeScript_newTimelockExpiry, kind: nativeScript_kind, asScriptPubkey: nativeScript_asScriptPubkey, asScriptAll: nativeScript_asScriptAll, asScriptAny: nativeScript_asScriptAny, asScriptNOfK: nativeScript_asScriptNOfK, asTimelockStart: nativeScript_asTimelockStart, asTimelockExpiry: nativeScript_asTimelockExpiry, getRequiredSigners: nativeScript_getRequiredSigners }

-------------------------------------------------------------------------------------
-- nativeScripts

foreign import nativeScripts_free :: NativeScripts -> Effect Unit
foreign import nativeScripts_new :: NativeScripts
foreign import nativeScripts_len :: NativeScripts -> Number
foreign import nativeScripts_get :: NativeScripts -> Number -> NativeScript
foreign import nativeScripts_add :: NativeScripts -> NativeScript -> Effect Unit

type NativeScriptsClass = { free :: NativeScripts -> Effect Unit, new :: NativeScripts, len :: NativeScripts -> Number, get :: NativeScripts -> Number -> NativeScript, add :: NativeScripts -> NativeScript -> Effect Unit }

nativeScripts :: NativeScriptsClass
nativeScripts = { free: nativeScripts_free, new: nativeScripts_new, len: nativeScripts_len, get: nativeScripts_get, add: nativeScripts_add }

-------------------------------------------------------------------------------------
-- networkId

foreign import networkId_free :: NetworkId -> Effect Unit
foreign import networkId_toBytes :: NetworkId -> Bytes
foreign import networkId_fromBytes :: Bytes -> NetworkId
foreign import networkId_toHex :: NetworkId -> String
foreign import networkId_fromHex :: String -> NetworkId
foreign import networkId_toJson :: NetworkId -> String
foreign import networkId_toJsValue :: NetworkId -> NetworkIdJs
foreign import networkId_fromJson :: String -> NetworkId
foreign import networkId_testnet :: NetworkId
foreign import networkId_mainnet :: NetworkId
foreign import networkId_kind :: NetworkId -> Number

type NetworkIdClass = { free :: NetworkId -> Effect Unit, toBytes :: NetworkId -> Bytes, fromBytes :: Bytes -> NetworkId, toHex :: NetworkId -> String, fromHex :: String -> NetworkId, toJson :: NetworkId -> String, toJsValue :: NetworkId -> NetworkIdJs, fromJson :: String -> NetworkId, testnet :: NetworkId, mainnet :: NetworkId, kind :: NetworkId -> Number }

networkId :: NetworkIdClass
networkId = { free: networkId_free, toBytes: networkId_toBytes, fromBytes: networkId_fromBytes, toHex: networkId_toHex, fromHex: networkId_fromHex, toJson: networkId_toJson, toJsValue: networkId_toJsValue, fromJson: networkId_fromJson, testnet: networkId_testnet, mainnet: networkId_mainnet, kind: networkId_kind }

-------------------------------------------------------------------------------------
-- networkInfo

foreign import networkInfo_free :: NetworkInfo -> Effect Unit
foreign import networkInfo_new :: Number -> Number -> NetworkInfo
foreign import networkInfo_networkId :: NetworkInfo -> Number
foreign import networkInfo_protocolMagic :: NetworkInfo -> Number
foreign import networkInfo_testnet :: NetworkInfo
foreign import networkInfo_mainnet :: NetworkInfo

type NetworkInfoClass = { free :: NetworkInfo -> Effect Unit, new :: Number -> Number -> NetworkInfo, networkId :: NetworkInfo -> Number, protocolMagic :: NetworkInfo -> Number, testnet :: NetworkInfo, mainnet :: NetworkInfo }

networkInfo :: NetworkInfoClass
networkInfo = { free: networkInfo_free, new: networkInfo_new, networkId: networkInfo_networkId, protocolMagic: networkInfo_protocolMagic, testnet: networkInfo_testnet, mainnet: networkInfo_mainnet }

-------------------------------------------------------------------------------------
-- nonce

foreign import nonce_free :: Nonce -> Effect Unit
foreign import nonce_toBytes :: Nonce -> Bytes
foreign import nonce_fromBytes :: Bytes -> Nonce
foreign import nonce_toHex :: Nonce -> String
foreign import nonce_fromHex :: String -> Nonce
foreign import nonce_toJson :: Nonce -> String
foreign import nonce_toJsValue :: Nonce -> NonceJs
foreign import nonce_fromJson :: String -> Nonce
foreign import nonce_newIdentity :: Nonce
foreign import nonce_newFromHash :: Bytes -> Nonce
foreign import nonce_getHash :: Nonce -> Maybe Bytes

type NonceClass = { free :: Nonce -> Effect Unit, toBytes :: Nonce -> Bytes, fromBytes :: Bytes -> Nonce, toHex :: Nonce -> String, fromHex :: String -> Nonce, toJson :: Nonce -> String, toJsValue :: Nonce -> NonceJs, fromJson :: String -> Nonce, newIdentity :: Nonce, newFromHash :: Bytes -> Nonce, getHash :: Nonce -> Maybe Bytes }

nonce :: NonceClass
nonce = { free: nonce_free, toBytes: nonce_toBytes, fromBytes: nonce_fromBytes, toHex: nonce_toHex, fromHex: nonce_fromHex, toJson: nonce_toJson, toJsValue: nonce_toJsValue, fromJson: nonce_fromJson, newIdentity: nonce_newIdentity, newFromHash: nonce_newFromHash, getHash: nonce_getHash }

-------------------------------------------------------------------------------------
-- operationalCert

foreign import operationalCert_free :: OperationalCert -> Effect Unit
foreign import operationalCert_toBytes :: OperationalCert -> Bytes
foreign import operationalCert_fromBytes :: Bytes -> OperationalCert
foreign import operationalCert_toHex :: OperationalCert -> String
foreign import operationalCert_fromHex :: String -> OperationalCert
foreign import operationalCert_toJson :: OperationalCert -> String
foreign import operationalCert_toJsValue :: OperationalCert -> OperationalCertJs
foreign import operationalCert_fromJson :: String -> OperationalCert
foreign import operationalCert_hotVkey :: OperationalCert -> KESVKey
foreign import operationalCert_sequenceNumber :: OperationalCert -> Number
foreign import operationalCert_kesPeriod :: OperationalCert -> Number
foreign import operationalCert_sigma :: OperationalCert -> Ed25519Signature
foreign import operationalCert_new :: KESVKey -> Number -> Number -> Ed25519Signature -> OperationalCert

type OperationalCertClass = { free :: OperationalCert -> Effect Unit, toBytes :: OperationalCert -> Bytes, fromBytes :: Bytes -> OperationalCert, toHex :: OperationalCert -> String, fromHex :: String -> OperationalCert, toJson :: OperationalCert -> String, toJsValue :: OperationalCert -> OperationalCertJs, fromJson :: String -> OperationalCert, hotVkey :: OperationalCert -> KESVKey, sequenceNumber :: OperationalCert -> Number, kesPeriod :: OperationalCert -> Number, sigma :: OperationalCert -> Ed25519Signature, new :: KESVKey -> Number -> Number -> Ed25519Signature -> OperationalCert }

operationalCert :: OperationalCertClass
operationalCert = { free: operationalCert_free, toBytes: operationalCert_toBytes, fromBytes: operationalCert_fromBytes, toHex: operationalCert_toHex, fromHex: operationalCert_fromHex, toJson: operationalCert_toJson, toJsValue: operationalCert_toJsValue, fromJson: operationalCert_fromJson, hotVkey: operationalCert_hotVkey, sequenceNumber: operationalCert_sequenceNumber, kesPeriod: operationalCert_kesPeriod, sigma: operationalCert_sigma, new: operationalCert_new }

-------------------------------------------------------------------------------------
-- plutusData

foreign import plutusData_free :: PlutusData -> Effect Unit
foreign import plutusData_toBytes :: PlutusData -> Bytes
foreign import plutusData_fromBytes :: Bytes -> PlutusData
foreign import plutusData_toHex :: PlutusData -> String
foreign import plutusData_fromHex :: String -> PlutusData
foreign import plutusData_toJson :: PlutusData -> String
foreign import plutusData_toJsValue :: PlutusData -> PlutusDataJs
foreign import plutusData_fromJson :: String -> PlutusData
foreign import plutusData_newConstrPlutusData :: ConstrPlutusData -> PlutusData
foreign import plutusData_newEmptyConstrPlutusData :: BigNum -> PlutusData
foreign import plutusData_newMap :: PlutusMap -> PlutusData
foreign import plutusData_newList :: PlutusList -> PlutusData
foreign import plutusData_newInteger :: BigInt -> PlutusData
foreign import plutusData_newBytes :: Bytes -> PlutusData
foreign import plutusData_kind :: PlutusData -> Number
foreign import plutusData_asConstrPlutusData :: PlutusData -> Maybe ConstrPlutusData
foreign import plutusData_asMap :: PlutusData -> Maybe PlutusMap
foreign import plutusData_asList :: PlutusData -> Maybe PlutusList
foreign import plutusData_asInteger :: PlutusData -> Maybe BigInt
foreign import plutusData_asBytes :: PlutusData -> Maybe Bytes

type PlutusDataClass = { free :: PlutusData -> Effect Unit, toBytes :: PlutusData -> Bytes, fromBytes :: Bytes -> PlutusData, toHex :: PlutusData -> String, fromHex :: String -> PlutusData, toJson :: PlutusData -> String, toJsValue :: PlutusData -> PlutusDataJs, fromJson :: String -> PlutusData, newConstrPlutusData :: ConstrPlutusData -> PlutusData, newEmptyConstrPlutusData :: BigNum -> PlutusData, newMap :: PlutusMap -> PlutusData, newList :: PlutusList -> PlutusData, newInteger :: BigInt -> PlutusData, newBytes :: Bytes -> PlutusData, kind :: PlutusData -> Number, asConstrPlutusData :: PlutusData -> Maybe ConstrPlutusData, asMap :: PlutusData -> Maybe PlutusMap, asList :: PlutusData -> Maybe PlutusList, asInteger :: PlutusData -> Maybe BigInt, asBytes :: PlutusData -> Maybe Bytes }

plutusData :: PlutusDataClass
plutusData = { free: plutusData_free, toBytes: plutusData_toBytes, fromBytes: plutusData_fromBytes, toHex: plutusData_toHex, fromHex: plutusData_fromHex, toJson: plutusData_toJson, toJsValue: plutusData_toJsValue, fromJson: plutusData_fromJson, newConstrPlutusData: plutusData_newConstrPlutusData, newEmptyConstrPlutusData: plutusData_newEmptyConstrPlutusData, newMap: plutusData_newMap, newList: plutusData_newList, newInteger: plutusData_newInteger, newBytes: plutusData_newBytes, kind: plutusData_kind, asConstrPlutusData: plutusData_asConstrPlutusData, asMap: plutusData_asMap, asList: plutusData_asList, asInteger: plutusData_asInteger, asBytes: plutusData_asBytes }

-------------------------------------------------------------------------------------
-- plutusList

foreign import plutusList_free :: PlutusList -> Effect Unit
foreign import plutusList_toBytes :: PlutusList -> Bytes
foreign import plutusList_fromBytes :: Bytes -> PlutusList
foreign import plutusList_toHex :: PlutusList -> String
foreign import plutusList_fromHex :: String -> PlutusList
foreign import plutusList_toJson :: PlutusList -> String
foreign import plutusList_toJsValue :: PlutusList -> PlutusListJs
foreign import plutusList_fromJson :: String -> PlutusList
foreign import plutusList_new :: PlutusList
foreign import plutusList_len :: PlutusList -> Number
foreign import plutusList_get :: PlutusList -> Number -> PlutusData
foreign import plutusList_add :: PlutusList -> PlutusData -> Effect Unit

type PlutusListClass = { free :: PlutusList -> Effect Unit, toBytes :: PlutusList -> Bytes, fromBytes :: Bytes -> PlutusList, toHex :: PlutusList -> String, fromHex :: String -> PlutusList, toJson :: PlutusList -> String, toJsValue :: PlutusList -> PlutusListJs, fromJson :: String -> PlutusList, new :: PlutusList, len :: PlutusList -> Number, get :: PlutusList -> Number -> PlutusData, add :: PlutusList -> PlutusData -> Effect Unit }

plutusList :: PlutusListClass
plutusList = { free: plutusList_free, toBytes: plutusList_toBytes, fromBytes: plutusList_fromBytes, toHex: plutusList_toHex, fromHex: plutusList_fromHex, toJson: plutusList_toJson, toJsValue: plutusList_toJsValue, fromJson: plutusList_fromJson, new: plutusList_new, len: plutusList_len, get: plutusList_get, add: plutusList_add }

-------------------------------------------------------------------------------------
-- plutusMap

foreign import plutusMap_free :: PlutusMap -> Effect Unit
foreign import plutusMap_toBytes :: PlutusMap -> Bytes
foreign import plutusMap_fromBytes :: Bytes -> PlutusMap
foreign import plutusMap_toHex :: PlutusMap -> String
foreign import plutusMap_fromHex :: String -> PlutusMap
foreign import plutusMap_toJson :: PlutusMap -> String
foreign import plutusMap_toJsValue :: PlutusMap -> PlutusMapJs
foreign import plutusMap_fromJson :: String -> PlutusMap
foreign import plutusMap_new :: PlutusMap
foreign import plutusMap_len :: PlutusMap -> Number
foreign import plutusMap_insert :: PlutusMap -> PlutusData -> PlutusData -> Maybe PlutusData
foreign import plutusMap_get :: PlutusMap -> PlutusData -> Maybe PlutusData
foreign import plutusMap_keys :: PlutusMap -> PlutusList

type PlutusMapClass = { free :: PlutusMap -> Effect Unit, toBytes :: PlutusMap -> Bytes, fromBytes :: Bytes -> PlutusMap, toHex :: PlutusMap -> String, fromHex :: String -> PlutusMap, toJson :: PlutusMap -> String, toJsValue :: PlutusMap -> PlutusMapJs, fromJson :: String -> PlutusMap, new :: PlutusMap, len :: PlutusMap -> Number, insert :: PlutusMap -> PlutusData -> PlutusData -> Maybe PlutusData, get :: PlutusMap -> PlutusData -> Maybe PlutusData, keys :: PlutusMap -> PlutusList }

plutusMap :: PlutusMapClass
plutusMap = { free: plutusMap_free, toBytes: plutusMap_toBytes, fromBytes: plutusMap_fromBytes, toHex: plutusMap_toHex, fromHex: plutusMap_fromHex, toJson: plutusMap_toJson, toJsValue: plutusMap_toJsValue, fromJson: plutusMap_fromJson, new: plutusMap_new, len: plutusMap_len, insert: plutusMap_insert, get: plutusMap_get, keys: plutusMap_keys }

-------------------------------------------------------------------------------------
-- plutusScript

foreign import plutusScript_free :: PlutusScript -> Effect Unit
foreign import plutusScript_toBytes :: PlutusScript -> Bytes
foreign import plutusScript_fromBytes :: Bytes -> PlutusScript
foreign import plutusScript_toHex :: PlutusScript -> String
foreign import plutusScript_fromHex :: String -> PlutusScript
foreign import plutusScript_new :: Bytes -> PlutusScript
foreign import plutusScript_newV2 :: Bytes -> PlutusScript
foreign import plutusScript_newWithVersion :: Bytes -> Language -> PlutusScript
foreign import plutusScript_bytes :: PlutusScript -> Bytes
foreign import plutusScript_fromBytesV2 :: Bytes -> PlutusScript
foreign import plutusScript_fromBytesWithVersion :: Bytes -> Language -> PlutusScript
foreign import plutusScript_hash :: PlutusScript -> ScriptHash
foreign import plutusScript_languageVersion :: PlutusScript -> Language

type PlutusScriptClass = { free :: PlutusScript -> Effect Unit, toBytes :: PlutusScript -> Bytes, fromBytes :: Bytes -> PlutusScript, toHex :: PlutusScript -> String, fromHex :: String -> PlutusScript, new :: Bytes -> PlutusScript, newV2 :: Bytes -> PlutusScript, newWithVersion :: Bytes -> Language -> PlutusScript, bytes :: PlutusScript -> Bytes, fromBytesV2 :: Bytes -> PlutusScript, fromBytesWithVersion :: Bytes -> Language -> PlutusScript, hash :: PlutusScript -> ScriptHash, languageVersion :: PlutusScript -> Language }

plutusScript :: PlutusScriptClass
plutusScript = { free: plutusScript_free, toBytes: plutusScript_toBytes, fromBytes: plutusScript_fromBytes, toHex: plutusScript_toHex, fromHex: plutusScript_fromHex, new: plutusScript_new, newV2: plutusScript_newV2, newWithVersion: plutusScript_newWithVersion, bytes: plutusScript_bytes, fromBytesV2: plutusScript_fromBytesV2, fromBytesWithVersion: plutusScript_fromBytesWithVersion, hash: plutusScript_hash, languageVersion: plutusScript_languageVersion }

-------------------------------------------------------------------------------------
-- plutusScriptSource

foreign import plutusScriptSource_free :: PlutusScriptSource -> Effect Unit
foreign import plutusScriptSource_new :: PlutusScript -> PlutusScriptSource
foreign import plutusScriptSource_newRefIn :: ScriptHash -> TxIn -> PlutusScriptSource

type PlutusScriptSourceClass = { free :: PlutusScriptSource -> Effect Unit, new :: PlutusScript -> PlutusScriptSource, newRefIn :: ScriptHash -> TxIn -> PlutusScriptSource }

plutusScriptSource :: PlutusScriptSourceClass
plutusScriptSource = { free: plutusScriptSource_free, new: plutusScriptSource_new, newRefIn: plutusScriptSource_newRefIn }

-------------------------------------------------------------------------------------
-- plutusScripts

foreign import plutusScripts_free :: PlutusScripts -> Effect Unit
foreign import plutusScripts_toBytes :: PlutusScripts -> Bytes
foreign import plutusScripts_fromBytes :: Bytes -> PlutusScripts
foreign import plutusScripts_toHex :: PlutusScripts -> String
foreign import plutusScripts_fromHex :: String -> PlutusScripts
foreign import plutusScripts_toJson :: PlutusScripts -> String
foreign import plutusScripts_toJsValue :: PlutusScripts -> PlutusScriptsJs
foreign import plutusScripts_fromJson :: String -> PlutusScripts
foreign import plutusScripts_new :: PlutusScripts
foreign import plutusScripts_len :: PlutusScripts -> Number
foreign import plutusScripts_get :: PlutusScripts -> Number -> PlutusScript
foreign import plutusScripts_add :: PlutusScripts -> PlutusScript -> Effect Unit

type PlutusScriptsClass = { free :: PlutusScripts -> Effect Unit, toBytes :: PlutusScripts -> Bytes, fromBytes :: Bytes -> PlutusScripts, toHex :: PlutusScripts -> String, fromHex :: String -> PlutusScripts, toJson :: PlutusScripts -> String, toJsValue :: PlutusScripts -> PlutusScriptsJs, fromJson :: String -> PlutusScripts, new :: PlutusScripts, len :: PlutusScripts -> Number, get :: PlutusScripts -> Number -> PlutusScript, add :: PlutusScripts -> PlutusScript -> Effect Unit }

plutusScripts :: PlutusScriptsClass
plutusScripts = { free: plutusScripts_free, toBytes: plutusScripts_toBytes, fromBytes: plutusScripts_fromBytes, toHex: plutusScripts_toHex, fromHex: plutusScripts_fromHex, toJson: plutusScripts_toJson, toJsValue: plutusScripts_toJsValue, fromJson: plutusScripts_fromJson, new: plutusScripts_new, len: plutusScripts_len, get: plutusScripts_get, add: plutusScripts_add }

-------------------------------------------------------------------------------------
-- plutusWitness

foreign import plutusWitness_free :: PlutusWitness -> Effect Unit
foreign import plutusWitness_new :: PlutusScript -> PlutusData -> Redeemer -> PlutusWitness
foreign import plutusWitness_newWithRef :: PlutusScriptSource -> DatumSource -> Redeemer -> PlutusWitness
foreign import plutusWitness_script :: PlutusWitness -> Maybe PlutusScript
foreign import plutusWitness_datum :: PlutusWitness -> Maybe PlutusData
foreign import plutusWitness_redeemer :: PlutusWitness -> Redeemer

type PlutusWitnessClass = { free :: PlutusWitness -> Effect Unit, new :: PlutusScript -> PlutusData -> Redeemer -> PlutusWitness, newWithRef :: PlutusScriptSource -> DatumSource -> Redeemer -> PlutusWitness, script :: PlutusWitness -> Maybe PlutusScript, datum :: PlutusWitness -> Maybe PlutusData, redeemer :: PlutusWitness -> Redeemer }

plutusWitness :: PlutusWitnessClass
plutusWitness = { free: plutusWitness_free, new: plutusWitness_new, newWithRef: plutusWitness_newWithRef, script: plutusWitness_script, datum: plutusWitness_datum, redeemer: plutusWitness_redeemer }

-------------------------------------------------------------------------------------
-- plutusWitnesses

foreign import plutusWitnesses_free :: PlutusWitnesses -> Effect Unit
foreign import plutusWitnesses_new :: PlutusWitnesses
foreign import plutusWitnesses_len :: PlutusWitnesses -> Number
foreign import plutusWitnesses_get :: PlutusWitnesses -> Number -> PlutusWitness
foreign import plutusWitnesses_add :: PlutusWitnesses -> PlutusWitness -> Effect Unit

type PlutusWitnessesClass = { free :: PlutusWitnesses -> Effect Unit, new :: PlutusWitnesses, len :: PlutusWitnesses -> Number, get :: PlutusWitnesses -> Number -> PlutusWitness, add :: PlutusWitnesses -> PlutusWitness -> Effect Unit }

plutusWitnesses :: PlutusWitnessesClass
plutusWitnesses = { free: plutusWitnesses_free, new: plutusWitnesses_new, len: plutusWitnesses_len, get: plutusWitnesses_get, add: plutusWitnesses_add }

-------------------------------------------------------------------------------------
-- pointer

foreign import pointer_free :: Pointer -> Effect Unit
foreign import pointer_new :: Number -> Number -> Number -> Pointer
foreign import pointer_newPointer :: BigNum -> BigNum -> BigNum -> Pointer
foreign import pointer_slot :: Pointer -> Number
foreign import pointer_txIndex :: Pointer -> Number
foreign import pointer_certIndex :: Pointer -> Number
foreign import pointer_slotBignum :: Pointer -> BigNum
foreign import pointer_txIndexBignum :: Pointer -> BigNum
foreign import pointer_certIndexBignum :: Pointer -> BigNum

type PointerClass = { free :: Pointer -> Effect Unit, new :: Number -> Number -> Number -> Pointer, newPointer :: BigNum -> BigNum -> BigNum -> Pointer, slot :: Pointer -> Number, txIndex :: Pointer -> Number, certIndex :: Pointer -> Number, slotBignum :: Pointer -> BigNum, txIndexBignum :: Pointer -> BigNum, certIndexBignum :: Pointer -> BigNum }

pointer :: PointerClass
pointer = { free: pointer_free, new: pointer_new, newPointer: pointer_newPointer, slot: pointer_slot, txIndex: pointer_txIndex, certIndex: pointer_certIndex, slotBignum: pointer_slotBignum, txIndexBignum: pointer_txIndexBignum, certIndexBignum: pointer_certIndexBignum }

-------------------------------------------------------------------------------------
-- pointerAddress

foreign import pointerAddress_free :: PointerAddress -> Effect Unit
foreign import pointerAddress_new :: Number -> StakeCredential -> Pointer -> PointerAddress
foreign import pointerAddress_paymentCred :: PointerAddress -> StakeCredential
foreign import pointerAddress_stakePointer :: PointerAddress -> Pointer
foreign import pointerAddress_toAddress :: PointerAddress -> Address
foreign import pointerAddress_fromAddress :: Address -> Maybe PointerAddress

type PointerAddressClass = { free :: PointerAddress -> Effect Unit, new :: Number -> StakeCredential -> Pointer -> PointerAddress, paymentCred :: PointerAddress -> StakeCredential, stakePointer :: PointerAddress -> Pointer, toAddress :: PointerAddress -> Address, fromAddress :: Address -> Maybe PointerAddress }

pointerAddress :: PointerAddressClass
pointerAddress = { free: pointerAddress_free, new: pointerAddress_new, paymentCred: pointerAddress_paymentCred, stakePointer: pointerAddress_stakePointer, toAddress: pointerAddress_toAddress, fromAddress: pointerAddress_fromAddress }

-------------------------------------------------------------------------------------
-- poolMetadata

foreign import poolMetadata_free :: PoolMetadata -> Effect Unit
foreign import poolMetadata_toBytes :: PoolMetadata -> Bytes
foreign import poolMetadata_fromBytes :: Bytes -> PoolMetadata
foreign import poolMetadata_toHex :: PoolMetadata -> String
foreign import poolMetadata_fromHex :: String -> PoolMetadata
foreign import poolMetadata_toJson :: PoolMetadata -> String
foreign import poolMetadata_toJsValue :: PoolMetadata -> PoolMetadataJs
foreign import poolMetadata_fromJson :: String -> PoolMetadata
foreign import poolMetadata_url :: PoolMetadata -> URL
foreign import poolMetadata_poolMetadataHash :: PoolMetadata -> PoolMetadataHash
foreign import poolMetadata_new :: URL -> PoolMetadataHash -> PoolMetadata

type PoolMetadataClass = { free :: PoolMetadata -> Effect Unit, toBytes :: PoolMetadata -> Bytes, fromBytes :: Bytes -> PoolMetadata, toHex :: PoolMetadata -> String, fromHex :: String -> PoolMetadata, toJson :: PoolMetadata -> String, toJsValue :: PoolMetadata -> PoolMetadataJs, fromJson :: String -> PoolMetadata, url :: PoolMetadata -> URL, poolMetadataHash :: PoolMetadata -> PoolMetadataHash, new :: URL -> PoolMetadataHash -> PoolMetadata }

poolMetadata :: PoolMetadataClass
poolMetadata = { free: poolMetadata_free, toBytes: poolMetadata_toBytes, fromBytes: poolMetadata_fromBytes, toHex: poolMetadata_toHex, fromHex: poolMetadata_fromHex, toJson: poolMetadata_toJson, toJsValue: poolMetadata_toJsValue, fromJson: poolMetadata_fromJson, url: poolMetadata_url, poolMetadataHash: poolMetadata_poolMetadataHash, new: poolMetadata_new }

-------------------------------------------------------------------------------------
-- poolMetadataHash

foreign import poolMetadataHash_free :: PoolMetadataHash -> Effect Unit
foreign import poolMetadataHash_fromBytes :: Bytes -> PoolMetadataHash
foreign import poolMetadataHash_toBytes :: PoolMetadataHash -> Bytes
foreign import poolMetadataHash_toBech32 :: PoolMetadataHash -> String -> String
foreign import poolMetadataHash_fromBech32 :: String -> PoolMetadataHash
foreign import poolMetadataHash_toHex :: PoolMetadataHash -> String
foreign import poolMetadataHash_fromHex :: String -> PoolMetadataHash

type PoolMetadataHashClass = { free :: PoolMetadataHash -> Effect Unit, fromBytes :: Bytes -> PoolMetadataHash, toBytes :: PoolMetadataHash -> Bytes, toBech32 :: PoolMetadataHash -> String -> String, fromBech32 :: String -> PoolMetadataHash, toHex :: PoolMetadataHash -> String, fromHex :: String -> PoolMetadataHash }

poolMetadataHash :: PoolMetadataHashClass
poolMetadataHash = { free: poolMetadataHash_free, fromBytes: poolMetadataHash_fromBytes, toBytes: poolMetadataHash_toBytes, toBech32: poolMetadataHash_toBech32, fromBech32: poolMetadataHash_fromBech32, toHex: poolMetadataHash_toHex, fromHex: poolMetadataHash_fromHex }

-------------------------------------------------------------------------------------
-- poolParams

foreign import poolParams_free :: PoolParams -> Effect Unit
foreign import poolParams_toBytes :: PoolParams -> Bytes
foreign import poolParams_fromBytes :: Bytes -> PoolParams
foreign import poolParams_toHex :: PoolParams -> String
foreign import poolParams_fromHex :: String -> PoolParams
foreign import poolParams_toJson :: PoolParams -> String
foreign import poolParams_toJsValue :: PoolParams -> PoolParamsJs
foreign import poolParams_fromJson :: String -> PoolParams
foreign import poolParams_operator :: PoolParams -> Ed25519KeyHash
foreign import poolParams_vrfKeyhash :: PoolParams -> VRFKeyHash
foreign import poolParams_pledge :: PoolParams -> BigNum
foreign import poolParams_cost :: PoolParams -> BigNum
foreign import poolParams_margin :: PoolParams -> UnitInterval
foreign import poolParams_rewardAccount :: PoolParams -> RewardAddress
foreign import poolParams_poolOwners :: PoolParams -> Ed25519KeyHashes
foreign import poolParams_relays :: PoolParams -> Relays
foreign import poolParams_poolMetadata :: PoolParams -> Maybe PoolMetadata
foreign import poolParams_new :: Ed25519KeyHash -> VRFKeyHash -> BigNum -> BigNum -> UnitInterval -> RewardAddress -> Ed25519KeyHashes -> Relays -> PoolMetadata -> PoolParams

type PoolParamsClass = { free :: PoolParams -> Effect Unit, toBytes :: PoolParams -> Bytes, fromBytes :: Bytes -> PoolParams, toHex :: PoolParams -> String, fromHex :: String -> PoolParams, toJson :: PoolParams -> String, toJsValue :: PoolParams -> PoolParamsJs, fromJson :: String -> PoolParams, operator :: PoolParams -> Ed25519KeyHash, vrfKeyhash :: PoolParams -> VRFKeyHash, pledge :: PoolParams -> BigNum, cost :: PoolParams -> BigNum, margin :: PoolParams -> UnitInterval, rewardAccount :: PoolParams -> RewardAddress, poolOwners :: PoolParams -> Ed25519KeyHashes, relays :: PoolParams -> Relays, poolMetadata :: PoolParams -> Maybe PoolMetadata, new :: Ed25519KeyHash -> VRFKeyHash -> BigNum -> BigNum -> UnitInterval -> RewardAddress -> Ed25519KeyHashes -> Relays -> PoolMetadata -> PoolParams }

poolParams :: PoolParamsClass
poolParams = { free: poolParams_free, toBytes: poolParams_toBytes, fromBytes: poolParams_fromBytes, toHex: poolParams_toHex, fromHex: poolParams_fromHex, toJson: poolParams_toJson, toJsValue: poolParams_toJsValue, fromJson: poolParams_fromJson, operator: poolParams_operator, vrfKeyhash: poolParams_vrfKeyhash, pledge: poolParams_pledge, cost: poolParams_cost, margin: poolParams_margin, rewardAccount: poolParams_rewardAccount, poolOwners: poolParams_poolOwners, relays: poolParams_relays, poolMetadata: poolParams_poolMetadata, new: poolParams_new }

-------------------------------------------------------------------------------------
-- poolRegistration

foreign import poolRegistration_free :: PoolRegistration -> Effect Unit
foreign import poolRegistration_toBytes :: PoolRegistration -> Bytes
foreign import poolRegistration_fromBytes :: Bytes -> PoolRegistration
foreign import poolRegistration_toHex :: PoolRegistration -> String
foreign import poolRegistration_fromHex :: String -> PoolRegistration
foreign import poolRegistration_toJson :: PoolRegistration -> String
foreign import poolRegistration_toJsValue :: PoolRegistration -> PoolRegistrationJs
foreign import poolRegistration_fromJson :: String -> PoolRegistration
foreign import poolRegistration_poolParams :: PoolRegistration -> PoolParams
foreign import poolRegistration_new :: PoolParams -> PoolRegistration

type PoolRegistrationClass = { free :: PoolRegistration -> Effect Unit, toBytes :: PoolRegistration -> Bytes, fromBytes :: Bytes -> PoolRegistration, toHex :: PoolRegistration -> String, fromHex :: String -> PoolRegistration, toJson :: PoolRegistration -> String, toJsValue :: PoolRegistration -> PoolRegistrationJs, fromJson :: String -> PoolRegistration, poolParams :: PoolRegistration -> PoolParams, new :: PoolParams -> PoolRegistration }

poolRegistration :: PoolRegistrationClass
poolRegistration = { free: poolRegistration_free, toBytes: poolRegistration_toBytes, fromBytes: poolRegistration_fromBytes, toHex: poolRegistration_toHex, fromHex: poolRegistration_fromHex, toJson: poolRegistration_toJson, toJsValue: poolRegistration_toJsValue, fromJson: poolRegistration_fromJson, poolParams: poolRegistration_poolParams, new: poolRegistration_new }

-------------------------------------------------------------------------------------
-- poolRetirement

foreign import poolRetirement_free :: PoolRetirement -> Effect Unit
foreign import poolRetirement_toBytes :: PoolRetirement -> Bytes
foreign import poolRetirement_fromBytes :: Bytes -> PoolRetirement
foreign import poolRetirement_toHex :: PoolRetirement -> String
foreign import poolRetirement_fromHex :: String -> PoolRetirement
foreign import poolRetirement_toJson :: PoolRetirement -> String
foreign import poolRetirement_toJsValue :: PoolRetirement -> PoolRetirementJs
foreign import poolRetirement_fromJson :: String -> PoolRetirement
foreign import poolRetirement_poolKeyhash :: PoolRetirement -> Ed25519KeyHash
foreign import poolRetirement_epoch :: PoolRetirement -> Number
foreign import poolRetirement_new :: Ed25519KeyHash -> Number -> PoolRetirement

type PoolRetirementClass = { free :: PoolRetirement -> Effect Unit, toBytes :: PoolRetirement -> Bytes, fromBytes :: Bytes -> PoolRetirement, toHex :: PoolRetirement -> String, fromHex :: String -> PoolRetirement, toJson :: PoolRetirement -> String, toJsValue :: PoolRetirement -> PoolRetirementJs, fromJson :: String -> PoolRetirement, poolKeyhash :: PoolRetirement -> Ed25519KeyHash, epoch :: PoolRetirement -> Number, new :: Ed25519KeyHash -> Number -> PoolRetirement }

poolRetirement :: PoolRetirementClass
poolRetirement = { free: poolRetirement_free, toBytes: poolRetirement_toBytes, fromBytes: poolRetirement_fromBytes, toHex: poolRetirement_toHex, fromHex: poolRetirement_fromHex, toJson: poolRetirement_toJson, toJsValue: poolRetirement_toJsValue, fromJson: poolRetirement_fromJson, poolKeyhash: poolRetirement_poolKeyhash, epoch: poolRetirement_epoch, new: poolRetirement_new }

-------------------------------------------------------------------------------------
-- privateKey

foreign import privateKey_free :: PrivateKey -> Effect Unit
foreign import privateKey_toPublic :: PrivateKey -> PublicKey
foreign import privateKey_generateEd25519 :: PrivateKey
foreign import privateKey_generateEd25519extended :: PrivateKey
foreign import privateKey_fromBech32 :: String -> PrivateKey
foreign import privateKey_toBech32 :: PrivateKey -> String
foreign import privateKey_asBytes :: PrivateKey -> Bytes
foreign import privateKey_fromExtendedBytes :: Bytes -> PrivateKey
foreign import privateKey_fromNormalBytes :: Bytes -> PrivateKey
foreign import privateKey_sign :: PrivateKey -> Bytes -> Ed25519Signature
foreign import privateKey_toHex :: PrivateKey -> String
foreign import privateKey_fromHex :: String -> PrivateKey

type PrivateKeyClass = { free :: PrivateKey -> Effect Unit, toPublic :: PrivateKey -> PublicKey, generateEd25519 :: PrivateKey, generateEd25519extended :: PrivateKey, fromBech32 :: String -> PrivateKey, toBech32 :: PrivateKey -> String, asBytes :: PrivateKey -> Bytes, fromExtendedBytes :: Bytes -> PrivateKey, fromNormalBytes :: Bytes -> PrivateKey, sign :: PrivateKey -> Bytes -> Ed25519Signature, toHex :: PrivateKey -> String, fromHex :: String -> PrivateKey }

privateKey :: PrivateKeyClass
privateKey = { free: privateKey_free, toPublic: privateKey_toPublic, generateEd25519: privateKey_generateEd25519, generateEd25519extended: privateKey_generateEd25519extended, fromBech32: privateKey_fromBech32, toBech32: privateKey_toBech32, asBytes: privateKey_asBytes, fromExtendedBytes: privateKey_fromExtendedBytes, fromNormalBytes: privateKey_fromNormalBytes, sign: privateKey_sign, toHex: privateKey_toHex, fromHex: privateKey_fromHex }

-------------------------------------------------------------------------------------
-- proposedProtocolParameterUpdates

foreign import proposedProtocolParameterUpdates_free :: ProposedProtocolParameterUpdates -> Effect Unit
foreign import proposedProtocolParameterUpdates_toBytes :: ProposedProtocolParameterUpdates -> Bytes
foreign import proposedProtocolParameterUpdates_fromBytes :: Bytes -> ProposedProtocolParameterUpdates
foreign import proposedProtocolParameterUpdates_toHex :: ProposedProtocolParameterUpdates -> String
foreign import proposedProtocolParameterUpdates_fromHex :: String -> ProposedProtocolParameterUpdates
foreign import proposedProtocolParameterUpdates_toJson :: ProposedProtocolParameterUpdates -> String
foreign import proposedProtocolParameterUpdates_toJsValue :: ProposedProtocolParameterUpdates -> ProposedProtocolParameterUpdatesJs
foreign import proposedProtocolParameterUpdates_fromJson :: String -> ProposedProtocolParameterUpdates
foreign import proposedProtocolParameterUpdates_new :: ProposedProtocolParameterUpdates
foreign import proposedProtocolParameterUpdates_len :: ProposedProtocolParameterUpdates -> Number
foreign import proposedProtocolParameterUpdates_insert :: ProposedProtocolParameterUpdates -> GenesisHash -> ProtocolParamUpdate -> Maybe ProtocolParamUpdate
foreign import proposedProtocolParameterUpdates_get :: ProposedProtocolParameterUpdates -> GenesisHash -> Maybe ProtocolParamUpdate
foreign import proposedProtocolParameterUpdates_keys :: ProposedProtocolParameterUpdates -> GenesisHashes

type ProposedProtocolParameterUpdatesClass = { free :: ProposedProtocolParameterUpdates -> Effect Unit, toBytes :: ProposedProtocolParameterUpdates -> Bytes, fromBytes :: Bytes -> ProposedProtocolParameterUpdates, toHex :: ProposedProtocolParameterUpdates -> String, fromHex :: String -> ProposedProtocolParameterUpdates, toJson :: ProposedProtocolParameterUpdates -> String, toJsValue :: ProposedProtocolParameterUpdates -> ProposedProtocolParameterUpdatesJs, fromJson :: String -> ProposedProtocolParameterUpdates, new :: ProposedProtocolParameterUpdates, len :: ProposedProtocolParameterUpdates -> Number, insert :: ProposedProtocolParameterUpdates -> GenesisHash -> ProtocolParamUpdate -> Maybe ProtocolParamUpdate, get :: ProposedProtocolParameterUpdates -> GenesisHash -> Maybe ProtocolParamUpdate, keys :: ProposedProtocolParameterUpdates -> GenesisHashes }

proposedProtocolParameterUpdates :: ProposedProtocolParameterUpdatesClass
proposedProtocolParameterUpdates = { free: proposedProtocolParameterUpdates_free, toBytes: proposedProtocolParameterUpdates_toBytes, fromBytes: proposedProtocolParameterUpdates_fromBytes, toHex: proposedProtocolParameterUpdates_toHex, fromHex: proposedProtocolParameterUpdates_fromHex, toJson: proposedProtocolParameterUpdates_toJson, toJsValue: proposedProtocolParameterUpdates_toJsValue, fromJson: proposedProtocolParameterUpdates_fromJson, new: proposedProtocolParameterUpdates_new, len: proposedProtocolParameterUpdates_len, insert: proposedProtocolParameterUpdates_insert, get: proposedProtocolParameterUpdates_get, keys: proposedProtocolParameterUpdates_keys }

-------------------------------------------------------------------------------------
-- protocolParamUpdate

foreign import protocolParamUpdate_free :: ProtocolParamUpdate -> Effect Unit
foreign import protocolParamUpdate_toBytes :: ProtocolParamUpdate -> Bytes
foreign import protocolParamUpdate_fromBytes :: Bytes -> ProtocolParamUpdate
foreign import protocolParamUpdate_toHex :: ProtocolParamUpdate -> String
foreign import protocolParamUpdate_fromHex :: String -> ProtocolParamUpdate
foreign import protocolParamUpdate_toJson :: ProtocolParamUpdate -> String
foreign import protocolParamUpdate_toJsValue :: ProtocolParamUpdate -> ProtocolParamUpdateJs
foreign import protocolParamUpdate_fromJson :: String -> ProtocolParamUpdate
foreign import protocolParamUpdate_setMinfeeA :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_minfeeA :: ProtocolParamUpdate -> Maybe BigNum
foreign import protocolParamUpdate_setMinfeeB :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_minfeeB :: ProtocolParamUpdate -> Maybe BigNum
foreign import protocolParamUpdate_setMaxBlockBodySize :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_maxBlockBodySize :: ProtocolParamUpdate -> Maybe Number
foreign import protocolParamUpdate_setMaxTxSize :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_maxTxSize :: ProtocolParamUpdate -> Maybe Number
foreign import protocolParamUpdate_setMaxBlockHeaderSize :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_maxBlockHeaderSize :: ProtocolParamUpdate -> Maybe Number
foreign import protocolParamUpdate_setKeyDeposit :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_keyDeposit :: ProtocolParamUpdate -> Maybe BigNum
foreign import protocolParamUpdate_setPoolDeposit :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_poolDeposit :: ProtocolParamUpdate -> Maybe BigNum
foreign import protocolParamUpdate_setMaxEpoch :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_maxEpoch :: ProtocolParamUpdate -> Maybe Number
foreign import protocolParamUpdate_setNOpt :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_nOpt :: ProtocolParamUpdate -> Maybe Number
foreign import protocolParamUpdate_setPoolPledgeInfluence :: ProtocolParamUpdate -> UnitInterval -> Effect Unit
foreign import protocolParamUpdate_poolPledgeInfluence :: ProtocolParamUpdate -> Maybe UnitInterval
foreign import protocolParamUpdate_setExpansionRate :: ProtocolParamUpdate -> UnitInterval -> Effect Unit
foreign import protocolParamUpdate_expansionRate :: ProtocolParamUpdate -> Maybe UnitInterval
foreign import protocolParamUpdate_setTreasuryGrowthRate :: ProtocolParamUpdate -> UnitInterval -> Effect Unit
foreign import protocolParamUpdate_treasuryGrowthRate :: ProtocolParamUpdate -> Maybe UnitInterval
foreign import protocolParamUpdate_d :: ProtocolParamUpdate -> Maybe UnitInterval
foreign import protocolParamUpdate_extraEntropy :: ProtocolParamUpdate -> Maybe Nonce
foreign import protocolParamUpdate_setProtocolVersion :: ProtocolParamUpdate -> ProtocolVersion -> Effect Unit
foreign import protocolParamUpdate_protocolVersion :: ProtocolParamUpdate -> Maybe ProtocolVersion
foreign import protocolParamUpdate_setMinPoolCost :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_minPoolCost :: ProtocolParamUpdate -> Maybe BigNum
foreign import protocolParamUpdate_setAdaPerUtxoByte :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_adaPerUtxoByte :: ProtocolParamUpdate -> Maybe BigNum
foreign import protocolParamUpdate_setCostModels :: ProtocolParamUpdate -> Costmdls -> Effect Unit
foreign import protocolParamUpdate_costModels :: ProtocolParamUpdate -> Maybe Costmdls
foreign import protocolParamUpdate_setExecutionCosts :: ProtocolParamUpdate -> ExUnitPrices -> Effect Unit
foreign import protocolParamUpdate_executionCosts :: ProtocolParamUpdate -> Maybe ExUnitPrices
foreign import protocolParamUpdate_setMaxTxExUnits :: ProtocolParamUpdate -> ExUnits -> Effect Unit
foreign import protocolParamUpdate_maxTxExUnits :: ProtocolParamUpdate -> Maybe ExUnits
foreign import protocolParamUpdate_setMaxBlockExUnits :: ProtocolParamUpdate -> ExUnits -> Effect Unit
foreign import protocolParamUpdate_maxBlockExUnits :: ProtocolParamUpdate -> Maybe ExUnits
foreign import protocolParamUpdate_setMaxValueSize :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_maxValueSize :: ProtocolParamUpdate -> Maybe Number
foreign import protocolParamUpdate_setCollateralPercentage :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_collateralPercentage :: ProtocolParamUpdate -> Maybe Number
foreign import protocolParamUpdate_setMaxCollateralIns :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_maxCollateralIns :: ProtocolParamUpdate -> Maybe Number
foreign import protocolParamUpdate_new :: ProtocolParamUpdate

type ProtocolParamUpdateClass = { free :: ProtocolParamUpdate -> Effect Unit, toBytes :: ProtocolParamUpdate -> Bytes, fromBytes :: Bytes -> ProtocolParamUpdate, toHex :: ProtocolParamUpdate -> String, fromHex :: String -> ProtocolParamUpdate, toJson :: ProtocolParamUpdate -> String, toJsValue :: ProtocolParamUpdate -> ProtocolParamUpdateJs, fromJson :: String -> ProtocolParamUpdate, setMinfeeA :: ProtocolParamUpdate -> BigNum -> Effect Unit, minfeeA :: ProtocolParamUpdate -> Maybe BigNum, setMinfeeB :: ProtocolParamUpdate -> BigNum -> Effect Unit, minfeeB :: ProtocolParamUpdate -> Maybe BigNum, setMaxBlockBodySize :: ProtocolParamUpdate -> Number -> Effect Unit, maxBlockBodySize :: ProtocolParamUpdate -> Maybe Number, setMaxTxSize :: ProtocolParamUpdate -> Number -> Effect Unit, maxTxSize :: ProtocolParamUpdate -> Maybe Number, setMaxBlockHeaderSize :: ProtocolParamUpdate -> Number -> Effect Unit, maxBlockHeaderSize :: ProtocolParamUpdate -> Maybe Number, setKeyDeposit :: ProtocolParamUpdate -> BigNum -> Effect Unit, keyDeposit :: ProtocolParamUpdate -> Maybe BigNum, setPoolDeposit :: ProtocolParamUpdate -> BigNum -> Effect Unit, poolDeposit :: ProtocolParamUpdate -> Maybe BigNum, setMaxEpoch :: ProtocolParamUpdate -> Number -> Effect Unit, maxEpoch :: ProtocolParamUpdate -> Maybe Number, setNOpt :: ProtocolParamUpdate -> Number -> Effect Unit, nOpt :: ProtocolParamUpdate -> Maybe Number, setPoolPledgeInfluence :: ProtocolParamUpdate -> UnitInterval -> Effect Unit, poolPledgeInfluence :: ProtocolParamUpdate -> Maybe UnitInterval, setExpansionRate :: ProtocolParamUpdate -> UnitInterval -> Effect Unit, expansionRate :: ProtocolParamUpdate -> Maybe UnitInterval, setTreasuryGrowthRate :: ProtocolParamUpdate -> UnitInterval -> Effect Unit, treasuryGrowthRate :: ProtocolParamUpdate -> Maybe UnitInterval, d :: ProtocolParamUpdate -> Maybe UnitInterval, extraEntropy :: ProtocolParamUpdate -> Maybe Nonce, setProtocolVersion :: ProtocolParamUpdate -> ProtocolVersion -> Effect Unit, protocolVersion :: ProtocolParamUpdate -> Maybe ProtocolVersion, setMinPoolCost :: ProtocolParamUpdate -> BigNum -> Effect Unit, minPoolCost :: ProtocolParamUpdate -> Maybe BigNum, setAdaPerUtxoByte :: ProtocolParamUpdate -> BigNum -> Effect Unit, adaPerUtxoByte :: ProtocolParamUpdate -> Maybe BigNum, setCostModels :: ProtocolParamUpdate -> Costmdls -> Effect Unit, costModels :: ProtocolParamUpdate -> Maybe Costmdls, setExecutionCosts :: ProtocolParamUpdate -> ExUnitPrices -> Effect Unit, executionCosts :: ProtocolParamUpdate -> Maybe ExUnitPrices, setMaxTxExUnits :: ProtocolParamUpdate -> ExUnits -> Effect Unit, maxTxExUnits :: ProtocolParamUpdate -> Maybe ExUnits, setMaxBlockExUnits :: ProtocolParamUpdate -> ExUnits -> Effect Unit, maxBlockExUnits :: ProtocolParamUpdate -> Maybe ExUnits, setMaxValueSize :: ProtocolParamUpdate -> Number -> Effect Unit, maxValueSize :: ProtocolParamUpdate -> Maybe Number, setCollateralPercentage :: ProtocolParamUpdate -> Number -> Effect Unit, collateralPercentage :: ProtocolParamUpdate -> Maybe Number, setMaxCollateralIns :: ProtocolParamUpdate -> Number -> Effect Unit, maxCollateralIns :: ProtocolParamUpdate -> Maybe Number, new :: ProtocolParamUpdate }

protocolParamUpdate :: ProtocolParamUpdateClass
protocolParamUpdate = { free: protocolParamUpdate_free, toBytes: protocolParamUpdate_toBytes, fromBytes: protocolParamUpdate_fromBytes, toHex: protocolParamUpdate_toHex, fromHex: protocolParamUpdate_fromHex, toJson: protocolParamUpdate_toJson, toJsValue: protocolParamUpdate_toJsValue, fromJson: protocolParamUpdate_fromJson, setMinfeeA: protocolParamUpdate_setMinfeeA, minfeeA: protocolParamUpdate_minfeeA, setMinfeeB: protocolParamUpdate_setMinfeeB, minfeeB: protocolParamUpdate_minfeeB, setMaxBlockBodySize: protocolParamUpdate_setMaxBlockBodySize, maxBlockBodySize: protocolParamUpdate_maxBlockBodySize, setMaxTxSize: protocolParamUpdate_setMaxTxSize, maxTxSize: protocolParamUpdate_maxTxSize, setMaxBlockHeaderSize: protocolParamUpdate_setMaxBlockHeaderSize, maxBlockHeaderSize: protocolParamUpdate_maxBlockHeaderSize, setKeyDeposit: protocolParamUpdate_setKeyDeposit, keyDeposit: protocolParamUpdate_keyDeposit, setPoolDeposit: protocolParamUpdate_setPoolDeposit, poolDeposit: protocolParamUpdate_poolDeposit, setMaxEpoch: protocolParamUpdate_setMaxEpoch, maxEpoch: protocolParamUpdate_maxEpoch, setNOpt: protocolParamUpdate_setNOpt, nOpt: protocolParamUpdate_nOpt, setPoolPledgeInfluence: protocolParamUpdate_setPoolPledgeInfluence, poolPledgeInfluence: protocolParamUpdate_poolPledgeInfluence, setExpansionRate: protocolParamUpdate_setExpansionRate, expansionRate: protocolParamUpdate_expansionRate, setTreasuryGrowthRate: protocolParamUpdate_setTreasuryGrowthRate, treasuryGrowthRate: protocolParamUpdate_treasuryGrowthRate, d: protocolParamUpdate_d, extraEntropy: protocolParamUpdate_extraEntropy, setProtocolVersion: protocolParamUpdate_setProtocolVersion, protocolVersion: protocolParamUpdate_protocolVersion, setMinPoolCost: protocolParamUpdate_setMinPoolCost, minPoolCost: protocolParamUpdate_minPoolCost, setAdaPerUtxoByte: protocolParamUpdate_setAdaPerUtxoByte, adaPerUtxoByte: protocolParamUpdate_adaPerUtxoByte, setCostModels: protocolParamUpdate_setCostModels, costModels: protocolParamUpdate_costModels, setExecutionCosts: protocolParamUpdate_setExecutionCosts, executionCosts: protocolParamUpdate_executionCosts, setMaxTxExUnits: protocolParamUpdate_setMaxTxExUnits, maxTxExUnits: protocolParamUpdate_maxTxExUnits, setMaxBlockExUnits: protocolParamUpdate_setMaxBlockExUnits, maxBlockExUnits: protocolParamUpdate_maxBlockExUnits, setMaxValueSize: protocolParamUpdate_setMaxValueSize, maxValueSize: protocolParamUpdate_maxValueSize, setCollateralPercentage: protocolParamUpdate_setCollateralPercentage, collateralPercentage: protocolParamUpdate_collateralPercentage, setMaxCollateralIns: protocolParamUpdate_setMaxCollateralIns, maxCollateralIns: protocolParamUpdate_maxCollateralIns, new: protocolParamUpdate_new }

-------------------------------------------------------------------------------------
-- protocolVersion

foreign import protocolVersion_free :: ProtocolVersion -> Effect Unit
foreign import protocolVersion_toBytes :: ProtocolVersion -> Bytes
foreign import protocolVersion_fromBytes :: Bytes -> ProtocolVersion
foreign import protocolVersion_toHex :: ProtocolVersion -> String
foreign import protocolVersion_fromHex :: String -> ProtocolVersion
foreign import protocolVersion_toJson :: ProtocolVersion -> String
foreign import protocolVersion_toJsValue :: ProtocolVersion -> ProtocolVersionJs
foreign import protocolVersion_fromJson :: String -> ProtocolVersion
foreign import protocolVersion_major :: ProtocolVersion -> Number
foreign import protocolVersion_minor :: ProtocolVersion -> Number
foreign import protocolVersion_new :: Number -> Number -> ProtocolVersion

type ProtocolVersionClass = { free :: ProtocolVersion -> Effect Unit, toBytes :: ProtocolVersion -> Bytes, fromBytes :: Bytes -> ProtocolVersion, toHex :: ProtocolVersion -> String, fromHex :: String -> ProtocolVersion, toJson :: ProtocolVersion -> String, toJsValue :: ProtocolVersion -> ProtocolVersionJs, fromJson :: String -> ProtocolVersion, major :: ProtocolVersion -> Number, minor :: ProtocolVersion -> Number, new :: Number -> Number -> ProtocolVersion }

protocolVersion :: ProtocolVersionClass
protocolVersion = { free: protocolVersion_free, toBytes: protocolVersion_toBytes, fromBytes: protocolVersion_fromBytes, toHex: protocolVersion_toHex, fromHex: protocolVersion_fromHex, toJson: protocolVersion_toJson, toJsValue: protocolVersion_toJsValue, fromJson: protocolVersion_fromJson, major: protocolVersion_major, minor: protocolVersion_minor, new: protocolVersion_new }

-------------------------------------------------------------------------------------
-- publicKey

foreign import publicKey_free :: PublicKey -> Effect Unit
foreign import publicKey_fromBech32 :: String -> PublicKey
foreign import publicKey_toBech32 :: PublicKey -> String
foreign import publicKey_asBytes :: PublicKey -> Bytes
foreign import publicKey_fromBytes :: Bytes -> PublicKey
foreign import publicKey_verify :: PublicKey -> Bytes -> Ed25519Signature -> Boolean
foreign import publicKey_hash :: PublicKey -> Ed25519KeyHash
foreign import publicKey_toHex :: PublicKey -> String
foreign import publicKey_fromHex :: String -> PublicKey

type PublicKeyClass = { free :: PublicKey -> Effect Unit, fromBech32 :: String -> PublicKey, toBech32 :: PublicKey -> String, asBytes :: PublicKey -> Bytes, fromBytes :: Bytes -> PublicKey, verify :: PublicKey -> Bytes -> Ed25519Signature -> Boolean, hash :: PublicKey -> Ed25519KeyHash, toHex :: PublicKey -> String, fromHex :: String -> PublicKey }

publicKey :: PublicKeyClass
publicKey = { free: publicKey_free, fromBech32: publicKey_fromBech32, toBech32: publicKey_toBech32, asBytes: publicKey_asBytes, fromBytes: publicKey_fromBytes, verify: publicKey_verify, hash: publicKey_hash, toHex: publicKey_toHex, fromHex: publicKey_fromHex }

-------------------------------------------------------------------------------------
-- publicKeys

foreign import publicKeys_free :: PublicKeys -> Effect Unit
foreign import publicKeys_constructor :: PublicKeys -> This
foreign import publicKeys_size :: PublicKeys -> Number
foreign import publicKeys_get :: PublicKeys -> Number -> PublicKey
foreign import publicKeys_add :: PublicKeys -> PublicKey -> Effect Unit

type PublicKeysClass = { free :: PublicKeys -> Effect Unit, constructor :: PublicKeys -> This, size :: PublicKeys -> Number, get :: PublicKeys -> Number -> PublicKey, add :: PublicKeys -> PublicKey -> Effect Unit }

publicKeys :: PublicKeysClass
publicKeys = { free: publicKeys_free, constructor: publicKeys_constructor, size: publicKeys_size, get: publicKeys_get, add: publicKeys_add }

-------------------------------------------------------------------------------------
-- redeemer

foreign import redeemer_free :: Redeemer -> Effect Unit
foreign import redeemer_toBytes :: Redeemer -> Bytes
foreign import redeemer_fromBytes :: Bytes -> Redeemer
foreign import redeemer_toHex :: Redeemer -> String
foreign import redeemer_fromHex :: String -> Redeemer
foreign import redeemer_toJson :: Redeemer -> String
foreign import redeemer_toJsValue :: Redeemer -> RedeemerJs
foreign import redeemer_fromJson :: String -> Redeemer
foreign import redeemer_tag :: Redeemer -> RedeemerTag
foreign import redeemer_index :: Redeemer -> BigNum
foreign import redeemer_data :: Redeemer -> PlutusData
foreign import redeemer_exUnits :: Redeemer -> ExUnits
foreign import redeemer_new :: RedeemerTag -> BigNum -> PlutusData -> ExUnits -> Redeemer

type RedeemerClass = { free :: Redeemer -> Effect Unit, toBytes :: Redeemer -> Bytes, fromBytes :: Bytes -> Redeemer, toHex :: Redeemer -> String, fromHex :: String -> Redeemer, toJson :: Redeemer -> String, toJsValue :: Redeemer -> RedeemerJs, fromJson :: String -> Redeemer, tag :: Redeemer -> RedeemerTag, index :: Redeemer -> BigNum, data :: Redeemer -> PlutusData, exUnits :: Redeemer -> ExUnits, new :: RedeemerTag -> BigNum -> PlutusData -> ExUnits -> Redeemer }

redeemer :: RedeemerClass
redeemer = { free: redeemer_free, toBytes: redeemer_toBytes, fromBytes: redeemer_fromBytes, toHex: redeemer_toHex, fromHex: redeemer_fromHex, toJson: redeemer_toJson, toJsValue: redeemer_toJsValue, fromJson: redeemer_fromJson, tag: redeemer_tag, index: redeemer_index, data: redeemer_data, exUnits: redeemer_exUnits, new: redeemer_new }

-------------------------------------------------------------------------------------
-- redeemerTag

foreign import redeemerTag_free :: RedeemerTag -> Effect Unit
foreign import redeemerTag_toBytes :: RedeemerTag -> Bytes
foreign import redeemerTag_fromBytes :: Bytes -> RedeemerTag
foreign import redeemerTag_toHex :: RedeemerTag -> String
foreign import redeemerTag_fromHex :: String -> RedeemerTag
foreign import redeemerTag_toJson :: RedeemerTag -> String
foreign import redeemerTag_toJsValue :: RedeemerTag -> RedeemerTagJs
foreign import redeemerTag_fromJson :: String -> RedeemerTag
foreign import redeemerTag_newSpend :: RedeemerTag
foreign import redeemerTag_newMint :: RedeemerTag
foreign import redeemerTag_newCert :: RedeemerTag
foreign import redeemerTag_newReward :: RedeemerTag
foreign import redeemerTag_kind :: RedeemerTag -> Number

type RedeemerTagClass = { free :: RedeemerTag -> Effect Unit, toBytes :: RedeemerTag -> Bytes, fromBytes :: Bytes -> RedeemerTag, toHex :: RedeemerTag -> String, fromHex :: String -> RedeemerTag, toJson :: RedeemerTag -> String, toJsValue :: RedeemerTag -> RedeemerTagJs, fromJson :: String -> RedeemerTag, newSpend :: RedeemerTag, newMint :: RedeemerTag, newCert :: RedeemerTag, newReward :: RedeemerTag, kind :: RedeemerTag -> Number }

redeemerTag :: RedeemerTagClass
redeemerTag = { free: redeemerTag_free, toBytes: redeemerTag_toBytes, fromBytes: redeemerTag_fromBytes, toHex: redeemerTag_toHex, fromHex: redeemerTag_fromHex, toJson: redeemerTag_toJson, toJsValue: redeemerTag_toJsValue, fromJson: redeemerTag_fromJson, newSpend: redeemerTag_newSpend, newMint: redeemerTag_newMint, newCert: redeemerTag_newCert, newReward: redeemerTag_newReward, kind: redeemerTag_kind }

-------------------------------------------------------------------------------------
-- redeemers

foreign import redeemers_free :: Redeemers -> Effect Unit
foreign import redeemers_toBytes :: Redeemers -> Bytes
foreign import redeemers_fromBytes :: Bytes -> Redeemers
foreign import redeemers_toHex :: Redeemers -> String
foreign import redeemers_fromHex :: String -> Redeemers
foreign import redeemers_toJson :: Redeemers -> String
foreign import redeemers_toJsValue :: Redeemers -> RedeemersJs
foreign import redeemers_fromJson :: String -> Redeemers
foreign import redeemers_new :: Redeemers
foreign import redeemers_len :: Redeemers -> Number
foreign import redeemers_get :: Redeemers -> Number -> Redeemer
foreign import redeemers_add :: Redeemers -> Redeemer -> Effect Unit
foreign import redeemers_totalExUnits :: Redeemers -> ExUnits

type RedeemersClass = { free :: Redeemers -> Effect Unit, toBytes :: Redeemers -> Bytes, fromBytes :: Bytes -> Redeemers, toHex :: Redeemers -> String, fromHex :: String -> Redeemers, toJson :: Redeemers -> String, toJsValue :: Redeemers -> RedeemersJs, fromJson :: String -> Redeemers, new :: Redeemers, len :: Redeemers -> Number, get :: Redeemers -> Number -> Redeemer, add :: Redeemers -> Redeemer -> Effect Unit, totalExUnits :: Redeemers -> ExUnits }

redeemers :: RedeemersClass
redeemers = { free: redeemers_free, toBytes: redeemers_toBytes, fromBytes: redeemers_fromBytes, toHex: redeemers_toHex, fromHex: redeemers_fromHex, toJson: redeemers_toJson, toJsValue: redeemers_toJsValue, fromJson: redeemers_fromJson, new: redeemers_new, len: redeemers_len, get: redeemers_get, add: redeemers_add, totalExUnits: redeemers_totalExUnits }

-------------------------------------------------------------------------------------
-- relay

foreign import relay_free :: Relay -> Effect Unit
foreign import relay_toBytes :: Relay -> Bytes
foreign import relay_fromBytes :: Bytes -> Relay
foreign import relay_toHex :: Relay -> String
foreign import relay_fromHex :: String -> Relay
foreign import relay_toJson :: Relay -> String
foreign import relay_toJsValue :: Relay -> RelayJs
foreign import relay_fromJson :: String -> Relay
foreign import relay_newSingleHostAddr :: SingleHostAddr -> Relay
foreign import relay_newSingleHostName :: SingleHostName -> Relay
foreign import relay_newMultiHostName :: MultiHostName -> Relay
foreign import relay_kind :: Relay -> Number
foreign import relay_asSingleHostAddr :: Relay -> Maybe SingleHostAddr
foreign import relay_asSingleHostName :: Relay -> Maybe SingleHostName
foreign import relay_asMultiHostName :: Relay -> Maybe MultiHostName

type RelayClass = { free :: Relay -> Effect Unit, toBytes :: Relay -> Bytes, fromBytes :: Bytes -> Relay, toHex :: Relay -> String, fromHex :: String -> Relay, toJson :: Relay -> String, toJsValue :: Relay -> RelayJs, fromJson :: String -> Relay, newSingleHostAddr :: SingleHostAddr -> Relay, newSingleHostName :: SingleHostName -> Relay, newMultiHostName :: MultiHostName -> Relay, kind :: Relay -> Number, asSingleHostAddr :: Relay -> Maybe SingleHostAddr, asSingleHostName :: Relay -> Maybe SingleHostName, asMultiHostName :: Relay -> Maybe MultiHostName }

relay :: RelayClass
relay = { free: relay_free, toBytes: relay_toBytes, fromBytes: relay_fromBytes, toHex: relay_toHex, fromHex: relay_fromHex, toJson: relay_toJson, toJsValue: relay_toJsValue, fromJson: relay_fromJson, newSingleHostAddr: relay_newSingleHostAddr, newSingleHostName: relay_newSingleHostName, newMultiHostName: relay_newMultiHostName, kind: relay_kind, asSingleHostAddr: relay_asSingleHostAddr, asSingleHostName: relay_asSingleHostName, asMultiHostName: relay_asMultiHostName }

-------------------------------------------------------------------------------------
-- relays

foreign import relays_free :: Relays -> Effect Unit
foreign import relays_toBytes :: Relays -> Bytes
foreign import relays_fromBytes :: Bytes -> Relays
foreign import relays_toHex :: Relays -> String
foreign import relays_fromHex :: String -> Relays
foreign import relays_toJson :: Relays -> String
foreign import relays_toJsValue :: Relays -> RelaysJs
foreign import relays_fromJson :: String -> Relays
foreign import relays_new :: Relays
foreign import relays_len :: Relays -> Number
foreign import relays_get :: Relays -> Number -> Relay
foreign import relays_add :: Relays -> Relay -> Effect Unit

type RelaysClass = { free :: Relays -> Effect Unit, toBytes :: Relays -> Bytes, fromBytes :: Bytes -> Relays, toHex :: Relays -> String, fromHex :: String -> Relays, toJson :: Relays -> String, toJsValue :: Relays -> RelaysJs, fromJson :: String -> Relays, new :: Relays, len :: Relays -> Number, get :: Relays -> Number -> Relay, add :: Relays -> Relay -> Effect Unit }

relays :: RelaysClass
relays = { free: relays_free, toBytes: relays_toBytes, fromBytes: relays_fromBytes, toHex: relays_toHex, fromHex: relays_fromHex, toJson: relays_toJson, toJsValue: relays_toJsValue, fromJson: relays_fromJson, new: relays_new, len: relays_len, get: relays_get, add: relays_add }

-------------------------------------------------------------------------------------
-- rewardAddress

foreign import rewardAddress_free :: RewardAddress -> Effect Unit
foreign import rewardAddress_new :: Number -> StakeCredential -> RewardAddress
foreign import rewardAddress_paymentCred :: RewardAddress -> StakeCredential
foreign import rewardAddress_toAddress :: RewardAddress -> Address
foreign import rewardAddress_fromAddress :: Address -> Maybe RewardAddress

type RewardAddressClass = { free :: RewardAddress -> Effect Unit, new :: Number -> StakeCredential -> RewardAddress, paymentCred :: RewardAddress -> StakeCredential, toAddress :: RewardAddress -> Address, fromAddress :: Address -> Maybe RewardAddress }

rewardAddress :: RewardAddressClass
rewardAddress = { free: rewardAddress_free, new: rewardAddress_new, paymentCred: rewardAddress_paymentCred, toAddress: rewardAddress_toAddress, fromAddress: rewardAddress_fromAddress }

-------------------------------------------------------------------------------------
-- rewardAddresses

foreign import rewardAddresses_free :: RewardAddresses -> Effect Unit
foreign import rewardAddresses_toBytes :: RewardAddresses -> Bytes
foreign import rewardAddresses_fromBytes :: Bytes -> RewardAddresses
foreign import rewardAddresses_toHex :: RewardAddresses -> String
foreign import rewardAddresses_fromHex :: String -> RewardAddresses
foreign import rewardAddresses_toJson :: RewardAddresses -> String
foreign import rewardAddresses_toJsValue :: RewardAddresses -> RewardAddressesJs
foreign import rewardAddresses_fromJson :: String -> RewardAddresses
foreign import rewardAddresses_new :: RewardAddresses
foreign import rewardAddresses_len :: RewardAddresses -> Number
foreign import rewardAddresses_get :: RewardAddresses -> Number -> RewardAddress
foreign import rewardAddresses_add :: RewardAddresses -> RewardAddress -> Effect Unit

type RewardAddressesClass = { free :: RewardAddresses -> Effect Unit, toBytes :: RewardAddresses -> Bytes, fromBytes :: Bytes -> RewardAddresses, toHex :: RewardAddresses -> String, fromHex :: String -> RewardAddresses, toJson :: RewardAddresses -> String, toJsValue :: RewardAddresses -> RewardAddressesJs, fromJson :: String -> RewardAddresses, new :: RewardAddresses, len :: RewardAddresses -> Number, get :: RewardAddresses -> Number -> RewardAddress, add :: RewardAddresses -> RewardAddress -> Effect Unit }

rewardAddresses :: RewardAddressesClass
rewardAddresses = { free: rewardAddresses_free, toBytes: rewardAddresses_toBytes, fromBytes: rewardAddresses_fromBytes, toHex: rewardAddresses_toHex, fromHex: rewardAddresses_fromHex, toJson: rewardAddresses_toJson, toJsValue: rewardAddresses_toJsValue, fromJson: rewardAddresses_fromJson, new: rewardAddresses_new, len: rewardAddresses_len, get: rewardAddresses_get, add: rewardAddresses_add }

-------------------------------------------------------------------------------------
-- scriptAll

foreign import scriptAll_free :: ScriptAll -> Effect Unit
foreign import scriptAll_toBytes :: ScriptAll -> Bytes
foreign import scriptAll_fromBytes :: Bytes -> ScriptAll
foreign import scriptAll_toHex :: ScriptAll -> String
foreign import scriptAll_fromHex :: String -> ScriptAll
foreign import scriptAll_toJson :: ScriptAll -> String
foreign import scriptAll_toJsValue :: ScriptAll -> ScriptAllJs
foreign import scriptAll_fromJson :: String -> ScriptAll
foreign import scriptAll_nativeScripts :: ScriptAll -> NativeScripts
foreign import scriptAll_new :: NativeScripts -> ScriptAll

type ScriptAllClass = { free :: ScriptAll -> Effect Unit, toBytes :: ScriptAll -> Bytes, fromBytes :: Bytes -> ScriptAll, toHex :: ScriptAll -> String, fromHex :: String -> ScriptAll, toJson :: ScriptAll -> String, toJsValue :: ScriptAll -> ScriptAllJs, fromJson :: String -> ScriptAll, nativeScripts :: ScriptAll -> NativeScripts, new :: NativeScripts -> ScriptAll }

scriptAll :: ScriptAllClass
scriptAll = { free: scriptAll_free, toBytes: scriptAll_toBytes, fromBytes: scriptAll_fromBytes, toHex: scriptAll_toHex, fromHex: scriptAll_fromHex, toJson: scriptAll_toJson, toJsValue: scriptAll_toJsValue, fromJson: scriptAll_fromJson, nativeScripts: scriptAll_nativeScripts, new: scriptAll_new }

-------------------------------------------------------------------------------------
-- scriptAny

foreign import scriptAny_free :: ScriptAny -> Effect Unit
foreign import scriptAny_toBytes :: ScriptAny -> Bytes
foreign import scriptAny_fromBytes :: Bytes -> ScriptAny
foreign import scriptAny_toHex :: ScriptAny -> String
foreign import scriptAny_fromHex :: String -> ScriptAny
foreign import scriptAny_toJson :: ScriptAny -> String
foreign import scriptAny_toJsValue :: ScriptAny -> ScriptAnyJs
foreign import scriptAny_fromJson :: String -> ScriptAny
foreign import scriptAny_nativeScripts :: ScriptAny -> NativeScripts
foreign import scriptAny_new :: NativeScripts -> ScriptAny

type ScriptAnyClass = { free :: ScriptAny -> Effect Unit, toBytes :: ScriptAny -> Bytes, fromBytes :: Bytes -> ScriptAny, toHex :: ScriptAny -> String, fromHex :: String -> ScriptAny, toJson :: ScriptAny -> String, toJsValue :: ScriptAny -> ScriptAnyJs, fromJson :: String -> ScriptAny, nativeScripts :: ScriptAny -> NativeScripts, new :: NativeScripts -> ScriptAny }

scriptAny :: ScriptAnyClass
scriptAny = { free: scriptAny_free, toBytes: scriptAny_toBytes, fromBytes: scriptAny_fromBytes, toHex: scriptAny_toHex, fromHex: scriptAny_fromHex, toJson: scriptAny_toJson, toJsValue: scriptAny_toJsValue, fromJson: scriptAny_fromJson, nativeScripts: scriptAny_nativeScripts, new: scriptAny_new }

-------------------------------------------------------------------------------------
-- scriptDataHash

foreign import scriptDataHash_free :: ScriptDataHash -> Effect Unit
foreign import scriptDataHash_fromBytes :: Bytes -> ScriptDataHash
foreign import scriptDataHash_toBytes :: ScriptDataHash -> Bytes
foreign import scriptDataHash_toBech32 :: ScriptDataHash -> String -> String
foreign import scriptDataHash_fromBech32 :: String -> ScriptDataHash
foreign import scriptDataHash_toHex :: ScriptDataHash -> String
foreign import scriptDataHash_fromHex :: String -> ScriptDataHash

type ScriptDataHashClass = { free :: ScriptDataHash -> Effect Unit, fromBytes :: Bytes -> ScriptDataHash, toBytes :: ScriptDataHash -> Bytes, toBech32 :: ScriptDataHash -> String -> String, fromBech32 :: String -> ScriptDataHash, toHex :: ScriptDataHash -> String, fromHex :: String -> ScriptDataHash }

scriptDataHash :: ScriptDataHashClass
scriptDataHash = { free: scriptDataHash_free, fromBytes: scriptDataHash_fromBytes, toBytes: scriptDataHash_toBytes, toBech32: scriptDataHash_toBech32, fromBech32: scriptDataHash_fromBech32, toHex: scriptDataHash_toHex, fromHex: scriptDataHash_fromHex }

-------------------------------------------------------------------------------------
-- scriptHash

foreign import scriptHash_free :: ScriptHash -> Effect Unit
foreign import scriptHash_fromBytes :: Bytes -> ScriptHash
foreign import scriptHash_toBytes :: ScriptHash -> Bytes
foreign import scriptHash_toBech32 :: ScriptHash -> String -> String
foreign import scriptHash_fromBech32 :: String -> ScriptHash
foreign import scriptHash_toHex :: ScriptHash -> String
foreign import scriptHash_fromHex :: String -> ScriptHash

type ScriptHashClass = { free :: ScriptHash -> Effect Unit, fromBytes :: Bytes -> ScriptHash, toBytes :: ScriptHash -> Bytes, toBech32 :: ScriptHash -> String -> String, fromBech32 :: String -> ScriptHash, toHex :: ScriptHash -> String, fromHex :: String -> ScriptHash }

scriptHash :: ScriptHashClass
scriptHash = { free: scriptHash_free, fromBytes: scriptHash_fromBytes, toBytes: scriptHash_toBytes, toBech32: scriptHash_toBech32, fromBech32: scriptHash_fromBech32, toHex: scriptHash_toHex, fromHex: scriptHash_fromHex }

-------------------------------------------------------------------------------------
-- scriptHashes

foreign import scriptHashes_free :: ScriptHashes -> Effect Unit
foreign import scriptHashes_toBytes :: ScriptHashes -> Bytes
foreign import scriptHashes_fromBytes :: Bytes -> ScriptHashes
foreign import scriptHashes_toHex :: ScriptHashes -> String
foreign import scriptHashes_fromHex :: String -> ScriptHashes
foreign import scriptHashes_toJson :: ScriptHashes -> String
foreign import scriptHashes_toJsValue :: ScriptHashes -> ScriptHashesJs
foreign import scriptHashes_fromJson :: String -> ScriptHashes
foreign import scriptHashes_new :: ScriptHashes
foreign import scriptHashes_len :: ScriptHashes -> Number
foreign import scriptHashes_get :: ScriptHashes -> Number -> ScriptHash
foreign import scriptHashes_add :: ScriptHashes -> ScriptHash -> Effect Unit

type ScriptHashesClass = { free :: ScriptHashes -> Effect Unit, toBytes :: ScriptHashes -> Bytes, fromBytes :: Bytes -> ScriptHashes, toHex :: ScriptHashes -> String, fromHex :: String -> ScriptHashes, toJson :: ScriptHashes -> String, toJsValue :: ScriptHashes -> ScriptHashesJs, fromJson :: String -> ScriptHashes, new :: ScriptHashes, len :: ScriptHashes -> Number, get :: ScriptHashes -> Number -> ScriptHash, add :: ScriptHashes -> ScriptHash -> Effect Unit }

scriptHashes :: ScriptHashesClass
scriptHashes = { free: scriptHashes_free, toBytes: scriptHashes_toBytes, fromBytes: scriptHashes_fromBytes, toHex: scriptHashes_toHex, fromHex: scriptHashes_fromHex, toJson: scriptHashes_toJson, toJsValue: scriptHashes_toJsValue, fromJson: scriptHashes_fromJson, new: scriptHashes_new, len: scriptHashes_len, get: scriptHashes_get, add: scriptHashes_add }

-------------------------------------------------------------------------------------
-- scriptNOfK

foreign import scriptNOfK_free :: ScriptNOfK -> Effect Unit
foreign import scriptNOfK_toBytes :: ScriptNOfK -> Bytes
foreign import scriptNOfK_fromBytes :: Bytes -> ScriptNOfK
foreign import scriptNOfK_toHex :: ScriptNOfK -> String
foreign import scriptNOfK_fromHex :: String -> ScriptNOfK
foreign import scriptNOfK_toJson :: ScriptNOfK -> String
foreign import scriptNOfK_toJsValue :: ScriptNOfK -> ScriptNOfKJs
foreign import scriptNOfK_fromJson :: String -> ScriptNOfK
foreign import scriptNOfK_n :: ScriptNOfK -> Number
foreign import scriptNOfK_nativeScripts :: ScriptNOfK -> NativeScripts
foreign import scriptNOfK_new :: Number -> NativeScripts -> ScriptNOfK

type ScriptNOfKClass = { free :: ScriptNOfK -> Effect Unit, toBytes :: ScriptNOfK -> Bytes, fromBytes :: Bytes -> ScriptNOfK, toHex :: ScriptNOfK -> String, fromHex :: String -> ScriptNOfK, toJson :: ScriptNOfK -> String, toJsValue :: ScriptNOfK -> ScriptNOfKJs, fromJson :: String -> ScriptNOfK, n :: ScriptNOfK -> Number, nativeScripts :: ScriptNOfK -> NativeScripts, new :: Number -> NativeScripts -> ScriptNOfK }

scriptNOfK :: ScriptNOfKClass
scriptNOfK = { free: scriptNOfK_free, toBytes: scriptNOfK_toBytes, fromBytes: scriptNOfK_fromBytes, toHex: scriptNOfK_toHex, fromHex: scriptNOfK_fromHex, toJson: scriptNOfK_toJson, toJsValue: scriptNOfK_toJsValue, fromJson: scriptNOfK_fromJson, n: scriptNOfK_n, nativeScripts: scriptNOfK_nativeScripts, new: scriptNOfK_new }

-------------------------------------------------------------------------------------
-- scriptPubkey

foreign import scriptPubkey_free :: ScriptPubkey -> Effect Unit
foreign import scriptPubkey_toBytes :: ScriptPubkey -> Bytes
foreign import scriptPubkey_fromBytes :: Bytes -> ScriptPubkey
foreign import scriptPubkey_toHex :: ScriptPubkey -> String
foreign import scriptPubkey_fromHex :: String -> ScriptPubkey
foreign import scriptPubkey_toJson :: ScriptPubkey -> String
foreign import scriptPubkey_toJsValue :: ScriptPubkey -> ScriptPubkeyJs
foreign import scriptPubkey_fromJson :: String -> ScriptPubkey
foreign import scriptPubkey_addrKeyhash :: ScriptPubkey -> Ed25519KeyHash
foreign import scriptPubkey_new :: Ed25519KeyHash -> ScriptPubkey

type ScriptPubkeyClass = { free :: ScriptPubkey -> Effect Unit, toBytes :: ScriptPubkey -> Bytes, fromBytes :: Bytes -> ScriptPubkey, toHex :: ScriptPubkey -> String, fromHex :: String -> ScriptPubkey, toJson :: ScriptPubkey -> String, toJsValue :: ScriptPubkey -> ScriptPubkeyJs, fromJson :: String -> ScriptPubkey, addrKeyhash :: ScriptPubkey -> Ed25519KeyHash, new :: Ed25519KeyHash -> ScriptPubkey }

scriptPubkey :: ScriptPubkeyClass
scriptPubkey = { free: scriptPubkey_free, toBytes: scriptPubkey_toBytes, fromBytes: scriptPubkey_fromBytes, toHex: scriptPubkey_toHex, fromHex: scriptPubkey_fromHex, toJson: scriptPubkey_toJson, toJsValue: scriptPubkey_toJsValue, fromJson: scriptPubkey_fromJson, addrKeyhash: scriptPubkey_addrKeyhash, new: scriptPubkey_new }

-------------------------------------------------------------------------------------
-- scriptRef

foreign import scriptRef_free :: ScriptRef -> Effect Unit
foreign import scriptRef_toBytes :: ScriptRef -> Bytes
foreign import scriptRef_fromBytes :: Bytes -> ScriptRef
foreign import scriptRef_toHex :: ScriptRef -> String
foreign import scriptRef_fromHex :: String -> ScriptRef
foreign import scriptRef_toJson :: ScriptRef -> String
foreign import scriptRef_toJsValue :: ScriptRef -> ScriptRefJs
foreign import scriptRef_fromJson :: String -> ScriptRef
foreign import scriptRef_newNativeScript :: NativeScript -> ScriptRef
foreign import scriptRef_newPlutusScript :: PlutusScript -> ScriptRef
foreign import scriptRef_isNativeScript :: ScriptRef -> Boolean
foreign import scriptRef_isPlutusScript :: ScriptRef -> Boolean
foreign import scriptRef_nativeScript :: ScriptRef -> Maybe NativeScript
foreign import scriptRef_plutusScript :: ScriptRef -> Maybe PlutusScript

type ScriptRefClass = { free :: ScriptRef -> Effect Unit, toBytes :: ScriptRef -> Bytes, fromBytes :: Bytes -> ScriptRef, toHex :: ScriptRef -> String, fromHex :: String -> ScriptRef, toJson :: ScriptRef -> String, toJsValue :: ScriptRef -> ScriptRefJs, fromJson :: String -> ScriptRef, newNativeScript :: NativeScript -> ScriptRef, newPlutusScript :: PlutusScript -> ScriptRef, isNativeScript :: ScriptRef -> Boolean, isPlutusScript :: ScriptRef -> Boolean, nativeScript :: ScriptRef -> Maybe NativeScript, plutusScript :: ScriptRef -> Maybe PlutusScript }

scriptRef :: ScriptRefClass
scriptRef = { free: scriptRef_free, toBytes: scriptRef_toBytes, fromBytes: scriptRef_fromBytes, toHex: scriptRef_toHex, fromHex: scriptRef_fromHex, toJson: scriptRef_toJson, toJsValue: scriptRef_toJsValue, fromJson: scriptRef_fromJson, newNativeScript: scriptRef_newNativeScript, newPlutusScript: scriptRef_newPlutusScript, isNativeScript: scriptRef_isNativeScript, isPlutusScript: scriptRef_isPlutusScript, nativeScript: scriptRef_nativeScript, plutusScript: scriptRef_plutusScript }

-------------------------------------------------------------------------------------
-- singleHostAddr

foreign import singleHostAddr_free :: SingleHostAddr -> Effect Unit
foreign import singleHostAddr_toBytes :: SingleHostAddr -> Bytes
foreign import singleHostAddr_fromBytes :: Bytes -> SingleHostAddr
foreign import singleHostAddr_toHex :: SingleHostAddr -> String
foreign import singleHostAddr_fromHex :: String -> SingleHostAddr
foreign import singleHostAddr_toJson :: SingleHostAddr -> String
foreign import singleHostAddr_toJsValue :: SingleHostAddr -> SingleHostAddrJs
foreign import singleHostAddr_fromJson :: String -> SingleHostAddr
foreign import singleHostAddr_port :: SingleHostAddr -> Maybe Number
foreign import singleHostAddr_ipv4 :: SingleHostAddr -> Maybe Ipv4
foreign import singleHostAddr_ipv6 :: SingleHostAddr -> Maybe Ipv6
foreign import singleHostAddr_new :: Number -> Ipv4 -> Ipv6 -> SingleHostAddr

type SingleHostAddrClass = { free :: SingleHostAddr -> Effect Unit, toBytes :: SingleHostAddr -> Bytes, fromBytes :: Bytes -> SingleHostAddr, toHex :: SingleHostAddr -> String, fromHex :: String -> SingleHostAddr, toJson :: SingleHostAddr -> String, toJsValue :: SingleHostAddr -> SingleHostAddrJs, fromJson :: String -> SingleHostAddr, port :: SingleHostAddr -> Maybe Number, ipv4 :: SingleHostAddr -> Maybe Ipv4, ipv6 :: SingleHostAddr -> Maybe Ipv6, new :: Number -> Ipv4 -> Ipv6 -> SingleHostAddr }

singleHostAddr :: SingleHostAddrClass
singleHostAddr = { free: singleHostAddr_free, toBytes: singleHostAddr_toBytes, fromBytes: singleHostAddr_fromBytes, toHex: singleHostAddr_toHex, fromHex: singleHostAddr_fromHex, toJson: singleHostAddr_toJson, toJsValue: singleHostAddr_toJsValue, fromJson: singleHostAddr_fromJson, port: singleHostAddr_port, ipv4: singleHostAddr_ipv4, ipv6: singleHostAddr_ipv6, new: singleHostAddr_new }

-------------------------------------------------------------------------------------
-- singleHostName

foreign import singleHostName_free :: SingleHostName -> Effect Unit
foreign import singleHostName_toBytes :: SingleHostName -> Bytes
foreign import singleHostName_fromBytes :: Bytes -> SingleHostName
foreign import singleHostName_toHex :: SingleHostName -> String
foreign import singleHostName_fromHex :: String -> SingleHostName
foreign import singleHostName_toJson :: SingleHostName -> String
foreign import singleHostName_toJsValue :: SingleHostName -> SingleHostNameJs
foreign import singleHostName_fromJson :: String -> SingleHostName
foreign import singleHostName_port :: SingleHostName -> Maybe Number
foreign import singleHostName_dnsName :: SingleHostName -> DNSRecordAorAAAA
foreign import singleHostName_new :: Maybe Number -> DNSRecordAorAAAA -> SingleHostName

type SingleHostNameClass = { free :: SingleHostName -> Effect Unit, toBytes :: SingleHostName -> Bytes, fromBytes :: Bytes -> SingleHostName, toHex :: SingleHostName -> String, fromHex :: String -> SingleHostName, toJson :: SingleHostName -> String, toJsValue :: SingleHostName -> SingleHostNameJs, fromJson :: String -> SingleHostName, port :: SingleHostName -> Maybe Number, dnsName :: SingleHostName -> DNSRecordAorAAAA, new :: Maybe Number -> DNSRecordAorAAAA -> SingleHostName }

singleHostName :: SingleHostNameClass
singleHostName = { free: singleHostName_free, toBytes: singleHostName_toBytes, fromBytes: singleHostName_fromBytes, toHex: singleHostName_toHex, fromHex: singleHostName_fromHex, toJson: singleHostName_toJson, toJsValue: singleHostName_toJsValue, fromJson: singleHostName_fromJson, port: singleHostName_port, dnsName: singleHostName_dnsName, new: singleHostName_new }

-------------------------------------------------------------------------------------
-- stakeCredential

foreign import stakeCredential_free :: StakeCredential -> Effect Unit
foreign import stakeCredential_fromKeyhash :: Ed25519KeyHash -> StakeCredential
foreign import stakeCredential_fromScripthash :: ScriptHash -> StakeCredential
foreign import stakeCredential_toKeyhash :: StakeCredential -> Maybe Ed25519KeyHash
foreign import stakeCredential_toScripthash :: StakeCredential -> Maybe ScriptHash
foreign import stakeCredential_kind :: StakeCredential -> Number
foreign import stakeCredential_toBytes :: StakeCredential -> Bytes
foreign import stakeCredential_fromBytes :: Bytes -> StakeCredential
foreign import stakeCredential_toHex :: StakeCredential -> String
foreign import stakeCredential_fromHex :: String -> StakeCredential
foreign import stakeCredential_toJson :: StakeCredential -> String
foreign import stakeCredential_toJsValue :: StakeCredential -> StakeCredentialJs
foreign import stakeCredential_fromJson :: String -> StakeCredential

type StakeCredentialClass = { free :: StakeCredential -> Effect Unit, fromKeyhash :: Ed25519KeyHash -> StakeCredential, fromScripthash :: ScriptHash -> StakeCredential, toKeyhash :: StakeCredential -> Maybe Ed25519KeyHash, toScripthash :: StakeCredential -> Maybe ScriptHash, kind :: StakeCredential -> Number, toBytes :: StakeCredential -> Bytes, fromBytes :: Bytes -> StakeCredential, toHex :: StakeCredential -> String, fromHex :: String -> StakeCredential, toJson :: StakeCredential -> String, toJsValue :: StakeCredential -> StakeCredentialJs, fromJson :: String -> StakeCredential }

stakeCredential :: StakeCredentialClass
stakeCredential = { free: stakeCredential_free, fromKeyhash: stakeCredential_fromKeyhash, fromScripthash: stakeCredential_fromScripthash, toKeyhash: stakeCredential_toKeyhash, toScripthash: stakeCredential_toScripthash, kind: stakeCredential_kind, toBytes: stakeCredential_toBytes, fromBytes: stakeCredential_fromBytes, toHex: stakeCredential_toHex, fromHex: stakeCredential_fromHex, toJson: stakeCredential_toJson, toJsValue: stakeCredential_toJsValue, fromJson: stakeCredential_fromJson }

-------------------------------------------------------------------------------------
-- stakeCredentials

foreign import stakeCredentials_free :: StakeCredentials -> Effect Unit
foreign import stakeCredentials_toBytes :: StakeCredentials -> Bytes
foreign import stakeCredentials_fromBytes :: Bytes -> StakeCredentials
foreign import stakeCredentials_toHex :: StakeCredentials -> String
foreign import stakeCredentials_fromHex :: String -> StakeCredentials
foreign import stakeCredentials_toJson :: StakeCredentials -> String
foreign import stakeCredentials_toJsValue :: StakeCredentials -> StakeCredentialsJs
foreign import stakeCredentials_fromJson :: String -> StakeCredentials
foreign import stakeCredentials_new :: StakeCredentials
foreign import stakeCredentials_len :: StakeCredentials -> Number
foreign import stakeCredentials_get :: StakeCredentials -> Number -> StakeCredential
foreign import stakeCredentials_add :: StakeCredentials -> StakeCredential -> Effect Unit

type StakeCredentialsClass = { free :: StakeCredentials -> Effect Unit, toBytes :: StakeCredentials -> Bytes, fromBytes :: Bytes -> StakeCredentials, toHex :: StakeCredentials -> String, fromHex :: String -> StakeCredentials, toJson :: StakeCredentials -> String, toJsValue :: StakeCredentials -> StakeCredentialsJs, fromJson :: String -> StakeCredentials, new :: StakeCredentials, len :: StakeCredentials -> Number, get :: StakeCredentials -> Number -> StakeCredential, add :: StakeCredentials -> StakeCredential -> Effect Unit }

stakeCredentials :: StakeCredentialsClass
stakeCredentials = { free: stakeCredentials_free, toBytes: stakeCredentials_toBytes, fromBytes: stakeCredentials_fromBytes, toHex: stakeCredentials_toHex, fromHex: stakeCredentials_fromHex, toJson: stakeCredentials_toJson, toJsValue: stakeCredentials_toJsValue, fromJson: stakeCredentials_fromJson, new: stakeCredentials_new, len: stakeCredentials_len, get: stakeCredentials_get, add: stakeCredentials_add }

-------------------------------------------------------------------------------------
-- stakeDelegation

foreign import stakeDelegation_free :: StakeDelegation -> Effect Unit
foreign import stakeDelegation_toBytes :: StakeDelegation -> Bytes
foreign import stakeDelegation_fromBytes :: Bytes -> StakeDelegation
foreign import stakeDelegation_toHex :: StakeDelegation -> String
foreign import stakeDelegation_fromHex :: String -> StakeDelegation
foreign import stakeDelegation_toJson :: StakeDelegation -> String
foreign import stakeDelegation_toJsValue :: StakeDelegation -> StakeDelegationJs
foreign import stakeDelegation_fromJson :: String -> StakeDelegation
foreign import stakeDelegation_stakeCredential :: StakeDelegation -> StakeCredential
foreign import stakeDelegation_poolKeyhash :: StakeDelegation -> Ed25519KeyHash
foreign import stakeDelegation_new :: StakeCredential -> Ed25519KeyHash -> StakeDelegation

type StakeDelegationClass = { free :: StakeDelegation -> Effect Unit, toBytes :: StakeDelegation -> Bytes, fromBytes :: Bytes -> StakeDelegation, toHex :: StakeDelegation -> String, fromHex :: String -> StakeDelegation, toJson :: StakeDelegation -> String, toJsValue :: StakeDelegation -> StakeDelegationJs, fromJson :: String -> StakeDelegation, stakeCredential :: StakeDelegation -> StakeCredential, poolKeyhash :: StakeDelegation -> Ed25519KeyHash, new :: StakeCredential -> Ed25519KeyHash -> StakeDelegation }

stakeDelegation :: StakeDelegationClass
stakeDelegation = { free: stakeDelegation_free, toBytes: stakeDelegation_toBytes, fromBytes: stakeDelegation_fromBytes, toHex: stakeDelegation_toHex, fromHex: stakeDelegation_fromHex, toJson: stakeDelegation_toJson, toJsValue: stakeDelegation_toJsValue, fromJson: stakeDelegation_fromJson, stakeCredential: stakeDelegation_stakeCredential, poolKeyhash: stakeDelegation_poolKeyhash, new: stakeDelegation_new }

-------------------------------------------------------------------------------------
-- stakeDeregistration

foreign import stakeDeregistration_free :: StakeDeregistration -> Effect Unit
foreign import stakeDeregistration_toBytes :: StakeDeregistration -> Bytes
foreign import stakeDeregistration_fromBytes :: Bytes -> StakeDeregistration
foreign import stakeDeregistration_toHex :: StakeDeregistration -> String
foreign import stakeDeregistration_fromHex :: String -> StakeDeregistration
foreign import stakeDeregistration_toJson :: StakeDeregistration -> String
foreign import stakeDeregistration_toJsValue :: StakeDeregistration -> StakeDeregistrationJs
foreign import stakeDeregistration_fromJson :: String -> StakeDeregistration
foreign import stakeDeregistration_stakeCredential :: StakeDeregistration -> StakeCredential
foreign import stakeDeregistration_new :: StakeCredential -> StakeDeregistration

type StakeDeregistrationClass = { free :: StakeDeregistration -> Effect Unit, toBytes :: StakeDeregistration -> Bytes, fromBytes :: Bytes -> StakeDeregistration, toHex :: StakeDeregistration -> String, fromHex :: String -> StakeDeregistration, toJson :: StakeDeregistration -> String, toJsValue :: StakeDeregistration -> StakeDeregistrationJs, fromJson :: String -> StakeDeregistration, stakeCredential :: StakeDeregistration -> StakeCredential, new :: StakeCredential -> StakeDeregistration }

stakeDeregistration :: StakeDeregistrationClass
stakeDeregistration = { free: stakeDeregistration_free, toBytes: stakeDeregistration_toBytes, fromBytes: stakeDeregistration_fromBytes, toHex: stakeDeregistration_toHex, fromHex: stakeDeregistration_fromHex, toJson: stakeDeregistration_toJson, toJsValue: stakeDeregistration_toJsValue, fromJson: stakeDeregistration_fromJson, stakeCredential: stakeDeregistration_stakeCredential, new: stakeDeregistration_new }

-------------------------------------------------------------------------------------
-- stakeRegistration

foreign import stakeRegistration_free :: StakeRegistration -> Effect Unit
foreign import stakeRegistration_toBytes :: StakeRegistration -> Bytes
foreign import stakeRegistration_fromBytes :: Bytes -> StakeRegistration
foreign import stakeRegistration_toHex :: StakeRegistration -> String
foreign import stakeRegistration_fromHex :: String -> StakeRegistration
foreign import stakeRegistration_toJson :: StakeRegistration -> String
foreign import stakeRegistration_toJsValue :: StakeRegistration -> StakeRegistrationJs
foreign import stakeRegistration_fromJson :: String -> StakeRegistration
foreign import stakeRegistration_stakeCredential :: StakeRegistration -> StakeCredential
foreign import stakeRegistration_new :: StakeCredential -> StakeRegistration

type StakeRegistrationClass = { free :: StakeRegistration -> Effect Unit, toBytes :: StakeRegistration -> Bytes, fromBytes :: Bytes -> StakeRegistration, toHex :: StakeRegistration -> String, fromHex :: String -> StakeRegistration, toJson :: StakeRegistration -> String, toJsValue :: StakeRegistration -> StakeRegistrationJs, fromJson :: String -> StakeRegistration, stakeCredential :: StakeRegistration -> StakeCredential, new :: StakeCredential -> StakeRegistration }

stakeRegistration :: StakeRegistrationClass
stakeRegistration = { free: stakeRegistration_free, toBytes: stakeRegistration_toBytes, fromBytes: stakeRegistration_fromBytes, toHex: stakeRegistration_toHex, fromHex: stakeRegistration_fromHex, toJson: stakeRegistration_toJson, toJsValue: stakeRegistration_toJsValue, fromJson: stakeRegistration_fromJson, stakeCredential: stakeRegistration_stakeCredential, new: stakeRegistration_new }

-------------------------------------------------------------------------------------
-- strings

foreign import strings_free :: Strings -> Effect Unit
foreign import strings_new :: Strings
foreign import strings_len :: Strings -> Number
foreign import strings_get :: Strings -> Number -> String
foreign import strings_add :: Strings -> String -> Effect Unit

type StringsClass = { free :: Strings -> Effect Unit, new :: Strings, len :: Strings -> Number, get :: Strings -> Number -> String, add :: Strings -> String -> Effect Unit }

strings :: StringsClass
strings = { free: strings_free, new: strings_new, len: strings_len, get: strings_get, add: strings_add }

-------------------------------------------------------------------------------------
-- timelockExpiry

foreign import timelockExpiry_free :: TimelockExpiry -> Effect Unit
foreign import timelockExpiry_toBytes :: TimelockExpiry -> Bytes
foreign import timelockExpiry_fromBytes :: Bytes -> TimelockExpiry
foreign import timelockExpiry_toHex :: TimelockExpiry -> String
foreign import timelockExpiry_fromHex :: String -> TimelockExpiry
foreign import timelockExpiry_toJson :: TimelockExpiry -> String
foreign import timelockExpiry_toJsValue :: TimelockExpiry -> TimelockExpiryJs
foreign import timelockExpiry_fromJson :: String -> TimelockExpiry
foreign import timelockExpiry_slot :: TimelockExpiry -> Number
foreign import timelockExpiry_slotBignum :: TimelockExpiry -> BigNum
foreign import timelockExpiry_new :: Number -> TimelockExpiry
foreign import timelockExpiry_newTimelockexpiry :: BigNum -> TimelockExpiry

type TimelockExpiryClass = { free :: TimelockExpiry -> Effect Unit, toBytes :: TimelockExpiry -> Bytes, fromBytes :: Bytes -> TimelockExpiry, toHex :: TimelockExpiry -> String, fromHex :: String -> TimelockExpiry, toJson :: TimelockExpiry -> String, toJsValue :: TimelockExpiry -> TimelockExpiryJs, fromJson :: String -> TimelockExpiry, slot :: TimelockExpiry -> Number, slotBignum :: TimelockExpiry -> BigNum, new :: Number -> TimelockExpiry, newTimelockexpiry :: BigNum -> TimelockExpiry }

timelockExpiry :: TimelockExpiryClass
timelockExpiry = { free: timelockExpiry_free, toBytes: timelockExpiry_toBytes, fromBytes: timelockExpiry_fromBytes, toHex: timelockExpiry_toHex, fromHex: timelockExpiry_fromHex, toJson: timelockExpiry_toJson, toJsValue: timelockExpiry_toJsValue, fromJson: timelockExpiry_fromJson, slot: timelockExpiry_slot, slotBignum: timelockExpiry_slotBignum, new: timelockExpiry_new, newTimelockexpiry: timelockExpiry_newTimelockexpiry }

-------------------------------------------------------------------------------------
-- timelockStart

foreign import timelockStart_free :: TimelockStart -> Effect Unit
foreign import timelockStart_toBytes :: TimelockStart -> Bytes
foreign import timelockStart_fromBytes :: Bytes -> TimelockStart
foreign import timelockStart_toHex :: TimelockStart -> String
foreign import timelockStart_fromHex :: String -> TimelockStart
foreign import timelockStart_toJson :: TimelockStart -> String
foreign import timelockStart_toJsValue :: TimelockStart -> TimelockStartJs
foreign import timelockStart_fromJson :: String -> TimelockStart
foreign import timelockStart_slot :: TimelockStart -> Number
foreign import timelockStart_slotBignum :: TimelockStart -> BigNum
foreign import timelockStart_new :: Number -> TimelockStart
foreign import timelockStart_newTimelockstart :: BigNum -> TimelockStart

type TimelockStartClass = { free :: TimelockStart -> Effect Unit, toBytes :: TimelockStart -> Bytes, fromBytes :: Bytes -> TimelockStart, toHex :: TimelockStart -> String, fromHex :: String -> TimelockStart, toJson :: TimelockStart -> String, toJsValue :: TimelockStart -> TimelockStartJs, fromJson :: String -> TimelockStart, slot :: TimelockStart -> Number, slotBignum :: TimelockStart -> BigNum, new :: Number -> TimelockStart, newTimelockstart :: BigNum -> TimelockStart }

timelockStart :: TimelockStartClass
timelockStart = { free: timelockStart_free, toBytes: timelockStart_toBytes, fromBytes: timelockStart_fromBytes, toHex: timelockStart_toHex, fromHex: timelockStart_fromHex, toJson: timelockStart_toJson, toJsValue: timelockStart_toJsValue, fromJson: timelockStart_fromJson, slot: timelockStart_slot, slotBignum: timelockStart_slotBignum, new: timelockStart_new, newTimelockstart: timelockStart_newTimelockstart }

-------------------------------------------------------------------------------------
-- tx

foreign import tx_free :: Tx -> Effect Unit
foreign import tx_toBytes :: Tx -> Bytes
foreign import tx_fromBytes :: Bytes -> Tx
foreign import tx_toHex :: Tx -> String
foreign import tx_fromHex :: String -> Tx
foreign import tx_toJson :: Tx -> String
foreign import tx_toJsValue :: Tx -> TxJs
foreign import tx_fromJson :: String -> Tx
foreign import tx_body :: Tx -> TxBody
foreign import tx_witnessSet :: Tx -> TxWitnessSet
foreign import tx_isValid :: Tx -> Boolean
foreign import tx_auxiliaryData :: Tx -> Maybe AuxiliaryData
foreign import tx_setIsValid :: Tx -> Boolean -> Effect Unit
foreign import tx_new :: TxBody -> TxWitnessSet -> AuxiliaryData -> Tx

type TxClass = { free :: Tx -> Effect Unit, toBytes :: Tx -> Bytes, fromBytes :: Bytes -> Tx, toHex :: Tx -> String, fromHex :: String -> Tx, toJson :: Tx -> String, toJsValue :: Tx -> TxJs, fromJson :: String -> Tx, body :: Tx -> TxBody, witnessSet :: Tx -> TxWitnessSet, isValid :: Tx -> Boolean, auxiliaryData :: Tx -> Maybe AuxiliaryData, setIsValid :: Tx -> Boolean -> Effect Unit, new :: TxBody -> TxWitnessSet -> AuxiliaryData -> Tx }

tx :: TxClass
tx = { free: tx_free, toBytes: tx_toBytes, fromBytes: tx_fromBytes, toHex: tx_toHex, fromHex: tx_fromHex, toJson: tx_toJson, toJsValue: tx_toJsValue, fromJson: tx_fromJson, body: tx_body, witnessSet: tx_witnessSet, isValid: tx_isValid, auxiliaryData: tx_auxiliaryData, setIsValid: tx_setIsValid, new: tx_new }

-------------------------------------------------------------------------------------
-- txBodies

foreign import txBodies_free :: TxBodies -> Effect Unit
foreign import txBodies_toBytes :: TxBodies -> Bytes
foreign import txBodies_fromBytes :: Bytes -> TxBodies
foreign import txBodies_toHex :: TxBodies -> String
foreign import txBodies_fromHex :: String -> TxBodies
foreign import txBodies_toJson :: TxBodies -> String
foreign import txBodies_toJsValue :: TxBodies -> TxBodiesJs
foreign import txBodies_fromJson :: String -> TxBodies
foreign import txBodies_new :: TxBodies
foreign import txBodies_len :: TxBodies -> Number
foreign import txBodies_get :: TxBodies -> Number -> TxBody
foreign import txBodies_add :: TxBodies -> TxBody -> Effect Unit

type TxBodiesClass = { free :: TxBodies -> Effect Unit, toBytes :: TxBodies -> Bytes, fromBytes :: Bytes -> TxBodies, toHex :: TxBodies -> String, fromHex :: String -> TxBodies, toJson :: TxBodies -> String, toJsValue :: TxBodies -> TxBodiesJs, fromJson :: String -> TxBodies, new :: TxBodies, len :: TxBodies -> Number, get :: TxBodies -> Number -> TxBody, add :: TxBodies -> TxBody -> Effect Unit }

txBodies :: TxBodiesClass
txBodies = { free: txBodies_free, toBytes: txBodies_toBytes, fromBytes: txBodies_fromBytes, toHex: txBodies_toHex, fromHex: txBodies_fromHex, toJson: txBodies_toJson, toJsValue: txBodies_toJsValue, fromJson: txBodies_fromJson, new: txBodies_new, len: txBodies_len, get: txBodies_get, add: txBodies_add }

-------------------------------------------------------------------------------------
-- txBody

foreign import txBody_free :: TxBody -> Effect Unit
foreign import txBody_toBytes :: TxBody -> Bytes
foreign import txBody_fromBytes :: Bytes -> TxBody
foreign import txBody_toHex :: TxBody -> String
foreign import txBody_fromHex :: String -> TxBody
foreign import txBody_toJson :: TxBody -> String
foreign import txBody_toJsValue :: TxBody -> TxBodyJs
foreign import txBody_fromJson :: String -> TxBody
foreign import txBody_ins :: TxBody -> TxIns
foreign import txBody_outs :: TxBody -> TxOuts
foreign import txBody_fee :: TxBody -> BigNum
foreign import txBody_ttl :: TxBody -> Maybe Number
foreign import txBody_ttlBignum :: TxBody -> Maybe BigNum
foreign import txBody_setTtl :: TxBody -> BigNum -> Effect Unit
foreign import txBody_removeTtl :: TxBody -> Effect Unit
foreign import txBody_setCerts :: TxBody -> Certificates -> Effect Unit
foreign import txBody_certs :: TxBody -> Maybe Certificates
foreign import txBody_setWithdrawals :: TxBody -> Withdrawals -> Effect Unit
foreign import txBody_withdrawals :: TxBody -> Maybe Withdrawals
foreign import txBody_setUpdate :: TxBody -> Update -> Effect Unit
foreign import txBody_update :: TxBody -> Maybe Update
foreign import txBody_setAuxiliaryDataHash :: TxBody -> AuxiliaryDataHash -> Effect Unit
foreign import txBody_auxiliaryDataHash :: TxBody -> Maybe AuxiliaryDataHash
foreign import txBody_setValidityStartInterval :: TxBody -> Number -> Effect Unit
foreign import txBody_setValidityStartIntervalBignum :: TxBody -> BigNum -> Effect Unit
foreign import txBody_validityStartIntervalBignum :: TxBody -> Maybe BigNum
foreign import txBody_validityStartInterval :: TxBody -> Maybe Number
foreign import txBody_setMint :: TxBody -> Mint -> Effect Unit
foreign import txBody_mint :: TxBody -> Maybe Mint
foreign import txBody_multiassets :: TxBody -> Maybe Mint
foreign import txBody_setReferenceIns :: TxBody -> TxIns -> Effect Unit
foreign import txBody_referenceIns :: TxBody -> Maybe TxIns
foreign import txBody_setScriptDataHash :: TxBody -> ScriptDataHash -> Effect Unit
foreign import txBody_scriptDataHash :: TxBody -> Maybe ScriptDataHash
foreign import txBody_setCollateral :: TxBody -> TxIns -> Effect Unit
foreign import txBody_collateral :: TxBody -> Maybe TxIns
foreign import txBody_setRequiredSigners :: TxBody -> Ed25519KeyHashes -> Effect Unit
foreign import txBody_requiredSigners :: TxBody -> Maybe Ed25519KeyHashes
foreign import txBody_setNetworkId :: TxBody -> NetworkId -> Effect Unit
foreign import txBody_networkId :: TxBody -> Maybe NetworkId
foreign import txBody_setCollateralReturn :: TxBody -> TxOut -> Effect Unit
foreign import txBody_collateralReturn :: TxBody -> Maybe TxOut
foreign import txBody_setTotalCollateral :: TxBody -> BigNum -> Effect Unit
foreign import txBody_totalCollateral :: TxBody -> Maybe BigNum
foreign import txBody_new :: TxIns -> TxOuts -> BigNum -> Number -> TxBody
foreign import txBody_newTxBody :: TxIns -> TxOuts -> BigNum -> TxBody

type TxBodyClass = { free :: TxBody -> Effect Unit, toBytes :: TxBody -> Bytes, fromBytes :: Bytes -> TxBody, toHex :: TxBody -> String, fromHex :: String -> TxBody, toJson :: TxBody -> String, toJsValue :: TxBody -> TxBodyJs, fromJson :: String -> TxBody, ins :: TxBody -> TxIns, outs :: TxBody -> TxOuts, fee :: TxBody -> BigNum, ttl :: TxBody -> Maybe Number, ttlBignum :: TxBody -> Maybe BigNum, setTtl :: TxBody -> BigNum -> Effect Unit, removeTtl :: TxBody -> Effect Unit, setCerts :: TxBody -> Certificates -> Effect Unit, certs :: TxBody -> Maybe Certificates, setWithdrawals :: TxBody -> Withdrawals -> Effect Unit, withdrawals :: TxBody -> Maybe Withdrawals, setUpdate :: TxBody -> Update -> Effect Unit, update :: TxBody -> Maybe Update, setAuxiliaryDataHash :: TxBody -> AuxiliaryDataHash -> Effect Unit, auxiliaryDataHash :: TxBody -> Maybe AuxiliaryDataHash, setValidityStartInterval :: TxBody -> Number -> Effect Unit, setValidityStartIntervalBignum :: TxBody -> BigNum -> Effect Unit, validityStartIntervalBignum :: TxBody -> Maybe BigNum, validityStartInterval :: TxBody -> Maybe Number, setMint :: TxBody -> Mint -> Effect Unit, mint :: TxBody -> Maybe Mint, multiassets :: TxBody -> Maybe Mint, setReferenceIns :: TxBody -> TxIns -> Effect Unit, referenceIns :: TxBody -> Maybe TxIns, setScriptDataHash :: TxBody -> ScriptDataHash -> Effect Unit, scriptDataHash :: TxBody -> Maybe ScriptDataHash, setCollateral :: TxBody -> TxIns -> Effect Unit, collateral :: TxBody -> Maybe TxIns, setRequiredSigners :: TxBody -> Ed25519KeyHashes -> Effect Unit, requiredSigners :: TxBody -> Maybe Ed25519KeyHashes, setNetworkId :: TxBody -> NetworkId -> Effect Unit, networkId :: TxBody -> Maybe NetworkId, setCollateralReturn :: TxBody -> TxOut -> Effect Unit, collateralReturn :: TxBody -> Maybe TxOut, setTotalCollateral :: TxBody -> BigNum -> Effect Unit, totalCollateral :: TxBody -> Maybe BigNum, new :: TxIns -> TxOuts -> BigNum -> Number -> TxBody, newTxBody :: TxIns -> TxOuts -> BigNum -> TxBody }

txBody :: TxBodyClass
txBody = { free: txBody_free, toBytes: txBody_toBytes, fromBytes: txBody_fromBytes, toHex: txBody_toHex, fromHex: txBody_fromHex, toJson: txBody_toJson, toJsValue: txBody_toJsValue, fromJson: txBody_fromJson, ins: txBody_ins, outs: txBody_outs, fee: txBody_fee, ttl: txBody_ttl, ttlBignum: txBody_ttlBignum, setTtl: txBody_setTtl, removeTtl: txBody_removeTtl, setCerts: txBody_setCerts, certs: txBody_certs, setWithdrawals: txBody_setWithdrawals, withdrawals: txBody_withdrawals, setUpdate: txBody_setUpdate, update: txBody_update, setAuxiliaryDataHash: txBody_setAuxiliaryDataHash, auxiliaryDataHash: txBody_auxiliaryDataHash, setValidityStartInterval: txBody_setValidityStartInterval, setValidityStartIntervalBignum: txBody_setValidityStartIntervalBignum, validityStartIntervalBignum: txBody_validityStartIntervalBignum, validityStartInterval: txBody_validityStartInterval, setMint: txBody_setMint, mint: txBody_mint, multiassets: txBody_multiassets, setReferenceIns: txBody_setReferenceIns, referenceIns: txBody_referenceIns, setScriptDataHash: txBody_setScriptDataHash, scriptDataHash: txBody_scriptDataHash, setCollateral: txBody_setCollateral, collateral: txBody_collateral, setRequiredSigners: txBody_setRequiredSigners, requiredSigners: txBody_requiredSigners, setNetworkId: txBody_setNetworkId, networkId: txBody_networkId, setCollateralReturn: txBody_setCollateralReturn, collateralReturn: txBody_collateralReturn, setTotalCollateral: txBody_setTotalCollateral, totalCollateral: txBody_totalCollateral, new: txBody_new, newTxBody: txBody_newTxBody }

-------------------------------------------------------------------------------------
-- txBuilder

foreign import txBuilder_free :: TxBuilder -> Effect Unit
foreign import txBuilder_addInsFrom :: TxBuilder -> TxUnspentOuts -> Number -> Effect Unit
foreign import txBuilder_setIns :: TxBuilder -> TxInsBuilder -> Effect Unit
foreign import txBuilder_setCollateral :: TxBuilder -> TxInsBuilder -> Effect Unit
foreign import txBuilder_setCollateralReturn :: TxBuilder -> TxOut -> Effect Unit
foreign import txBuilder_setCollateralReturnAndTotal :: TxBuilder -> TxOut -> Effect Unit
foreign import txBuilder_setTotalCollateral :: TxBuilder -> BigNum -> Effect Unit
foreign import txBuilder_setTotalCollateralAndReturn :: TxBuilder -> BigNum -> Address -> Effect Unit
foreign import txBuilder_addReferenceIn :: TxBuilder -> TxIn -> Effect Unit
foreign import txBuilder_addKeyIn :: TxBuilder -> Ed25519KeyHash -> TxIn -> Value -> Effect Unit
foreign import txBuilder_addScriptIn :: TxBuilder -> ScriptHash -> TxIn -> Value -> Effect Unit
foreign import txBuilder_addNativeScriptIn :: TxBuilder -> NativeScript -> TxIn -> Value -> Effect Unit
foreign import txBuilder_addPlutusScriptIn :: TxBuilder -> PlutusWitness -> TxIn -> Value -> Effect Unit
foreign import txBuilder_addBootstrapIn :: TxBuilder -> ByronAddress -> TxIn -> Value -> Effect Unit
foreign import txBuilder_addIn :: TxBuilder -> Address -> TxIn -> Value -> Effect Unit
foreign import txBuilder_countMissingInScripts :: TxBuilder -> Number
foreign import txBuilder_addRequiredNativeInScripts :: TxBuilder -> NativeScripts -> Number
foreign import txBuilder_addRequiredPlutusInScripts :: TxBuilder -> PlutusWitnesses -> Number
foreign import txBuilder_getNativeInScripts :: TxBuilder -> Maybe NativeScripts
foreign import txBuilder_getPlutusInScripts :: TxBuilder -> Maybe PlutusWitnesses
foreign import txBuilder_feeForIn :: TxBuilder -> Address -> TxIn -> Value -> BigNum
foreign import txBuilder_addOut :: TxBuilder -> TxOut -> Effect Unit
foreign import txBuilder_feeForOut :: TxBuilder -> TxOut -> BigNum
foreign import txBuilder_setFee :: TxBuilder -> BigNum -> Effect Unit
foreign import txBuilder_setTtl :: TxBuilder -> Number -> Effect Unit
foreign import txBuilder_setTtlBignum :: TxBuilder -> BigNum -> Effect Unit
foreign import txBuilder_setValidityStartInterval :: TxBuilder -> Number -> Effect Unit
foreign import txBuilder_setValidityStartIntervalBignum :: TxBuilder -> BigNum -> Effect Unit
foreign import txBuilder_setCerts :: TxBuilder -> Certificates -> Effect Unit
foreign import txBuilder_setWithdrawals :: TxBuilder -> Withdrawals -> Effect Unit
foreign import txBuilder_getAuxiliaryData :: TxBuilder -> Maybe AuxiliaryData
foreign import txBuilder_setAuxiliaryData :: TxBuilder -> AuxiliaryData -> Effect Unit
foreign import txBuilder_setMetadata :: TxBuilder -> GeneralTxMetadata -> Effect Unit
foreign import txBuilder_addMetadatum :: TxBuilder -> BigNum -> TxMetadatum -> Effect Unit
foreign import txBuilder_addJsonMetadatum :: TxBuilder -> BigNum -> String -> Effect Unit
foreign import txBuilder_addJsonMetadatumWithSchema :: TxBuilder -> BigNum -> String -> Number -> Effect Unit
foreign import txBuilder_setMint :: TxBuilder -> Mint -> NativeScripts -> Effect Unit
foreign import txBuilder_getMint :: TxBuilder -> Maybe Mint
foreign import txBuilder_getMintScripts :: TxBuilder -> Maybe NativeScripts
foreign import txBuilder_setMintAsset :: TxBuilder -> NativeScript -> MintAssets -> Effect Unit
foreign import txBuilder_addMintAsset :: TxBuilder -> NativeScript -> AssetName -> Int -> Effect Unit
foreign import txBuilder_addMintAssetAndOut :: TxBuilder -> NativeScript -> AssetName -> Int -> TxOutAmountBuilder -> BigNum -> Effect Unit
foreign import txBuilder_addMintAssetAndOutMinRequiredCoin :: TxBuilder -> NativeScript -> AssetName -> Int -> TxOutAmountBuilder -> Effect Unit
foreign import txBuilder_new :: TxBuilderConfig -> Effect TxBuilder
foreign import txBuilder_getReferenceIns :: TxBuilder -> TxIns
foreign import txBuilder_getExplicitIn :: TxBuilder -> Value
foreign import txBuilder_getImplicitIn :: TxBuilder -> Value
foreign import txBuilder_getTotalIn :: TxBuilder -> Value
foreign import txBuilder_getTotalOut :: TxBuilder -> Value
foreign import txBuilder_getExplicitOut :: TxBuilder -> Value
foreign import txBuilder_getDeposit :: TxBuilder -> BigNum
foreign import txBuilder_getFeeIfSet :: TxBuilder -> Maybe BigNum
foreign import txBuilder_addChangeIfNeeded :: TxBuilder -> Address -> Boolean
foreign import txBuilder_calcScriptDataHash :: TxBuilder -> Costmdls -> Effect Unit
foreign import txBuilder_setScriptDataHash :: TxBuilder -> ScriptDataHash -> Effect Unit
foreign import txBuilder_removeScriptDataHash :: TxBuilder -> Effect Unit
foreign import txBuilder_addRequiredSigner :: TxBuilder -> Ed25519KeyHash -> Effect Unit
foreign import txBuilder_fullSize :: TxBuilder -> Number
foreign import txBuilder_outSizes :: TxBuilder -> Uint32Array
foreign import txBuilder_build :: TxBuilder -> TxBody
foreign import txBuilder_buildTx :: TxBuilder -> Tx
foreign import txBuilder_buildTxUnsafe :: TxBuilder -> Tx
foreign import txBuilder_minFee :: TxBuilder -> BigNum

type TxBuilderClass = { free :: TxBuilder -> Effect Unit, addInsFrom :: TxBuilder -> TxUnspentOuts -> Number -> Effect Unit, setIns :: TxBuilder -> TxInsBuilder -> Effect Unit, setCollateral :: TxBuilder -> TxInsBuilder -> Effect Unit, setCollateralReturn :: TxBuilder -> TxOut -> Effect Unit, setCollateralReturnAndTotal :: TxBuilder -> TxOut -> Effect Unit, setTotalCollateral :: TxBuilder -> BigNum -> Effect Unit, setTotalCollateralAndReturn :: TxBuilder -> BigNum -> Address -> Effect Unit, addReferenceIn :: TxBuilder -> TxIn -> Effect Unit, addKeyIn :: TxBuilder -> Ed25519KeyHash -> TxIn -> Value -> Effect Unit, addScriptIn :: TxBuilder -> ScriptHash -> TxIn -> Value -> Effect Unit, addNativeScriptIn :: TxBuilder -> NativeScript -> TxIn -> Value -> Effect Unit, addPlutusScriptIn :: TxBuilder -> PlutusWitness -> TxIn -> Value -> Effect Unit, addBootstrapIn :: TxBuilder -> ByronAddress -> TxIn -> Value -> Effect Unit, addIn :: TxBuilder -> Address -> TxIn -> Value -> Effect Unit, countMissingInScripts :: TxBuilder -> Number, addRequiredNativeInScripts :: TxBuilder -> NativeScripts -> Number, addRequiredPlutusInScripts :: TxBuilder -> PlutusWitnesses -> Number, getNativeInScripts :: TxBuilder -> Maybe NativeScripts, getPlutusInScripts :: TxBuilder -> Maybe PlutusWitnesses, feeForIn :: TxBuilder -> Address -> TxIn -> Value -> BigNum, addOut :: TxBuilder -> TxOut -> Effect Unit, feeForOut :: TxBuilder -> TxOut -> BigNum, setFee :: TxBuilder -> BigNum -> Effect Unit, setTtl :: TxBuilder -> Number -> Effect Unit, setTtlBignum :: TxBuilder -> BigNum -> Effect Unit, setValidityStartInterval :: TxBuilder -> Number -> Effect Unit, setValidityStartIntervalBignum :: TxBuilder -> BigNum -> Effect Unit, setCerts :: TxBuilder -> Certificates -> Effect Unit, setWithdrawals :: TxBuilder -> Withdrawals -> Effect Unit, getAuxiliaryData :: TxBuilder -> Maybe AuxiliaryData, setAuxiliaryData :: TxBuilder -> AuxiliaryData -> Effect Unit, setMetadata :: TxBuilder -> GeneralTxMetadata -> Effect Unit, addMetadatum :: TxBuilder -> BigNum -> TxMetadatum -> Effect Unit, addJsonMetadatum :: TxBuilder -> BigNum -> String -> Effect Unit, addJsonMetadatumWithSchema :: TxBuilder -> BigNum -> String -> Number -> Effect Unit, setMint :: TxBuilder -> Mint -> NativeScripts -> Effect Unit, getMint :: TxBuilder -> Maybe Mint, getMintScripts :: TxBuilder -> Maybe NativeScripts, setMintAsset :: TxBuilder -> NativeScript -> MintAssets -> Effect Unit, addMintAsset :: TxBuilder -> NativeScript -> AssetName -> Int -> Effect Unit, addMintAssetAndOut :: TxBuilder -> NativeScript -> AssetName -> Int -> TxOutAmountBuilder -> BigNum -> Effect Unit, addMintAssetAndOutMinRequiredCoin :: TxBuilder -> NativeScript -> AssetName -> Int -> TxOutAmountBuilder -> Effect Unit, new :: TxBuilderConfig -> Effect TxBuilder, getReferenceIns :: TxBuilder -> TxIns, getExplicitIn :: TxBuilder -> Value, getImplicitIn :: TxBuilder -> Value, getTotalIn :: TxBuilder -> Value, getTotalOut :: TxBuilder -> Value, getExplicitOut :: TxBuilder -> Value, getDeposit :: TxBuilder -> BigNum, getFeeIfSet :: TxBuilder -> Maybe BigNum, addChangeIfNeeded :: TxBuilder -> Address -> Boolean, calcScriptDataHash :: TxBuilder -> Costmdls -> Effect Unit, setScriptDataHash :: TxBuilder -> ScriptDataHash -> Effect Unit, removeScriptDataHash :: TxBuilder -> Effect Unit, addRequiredSigner :: TxBuilder -> Ed25519KeyHash -> Effect Unit, fullSize :: TxBuilder -> Number, outSizes :: TxBuilder -> Uint32Array, build :: TxBuilder -> TxBody, buildTx :: TxBuilder -> Tx, buildTxUnsafe :: TxBuilder -> Tx, minFee :: TxBuilder -> BigNum }

txBuilder :: TxBuilderClass
txBuilder = { free: txBuilder_free, addInsFrom: txBuilder_addInsFrom, setIns: txBuilder_setIns, setCollateral: txBuilder_setCollateral, setCollateralReturn: txBuilder_setCollateralReturn, setCollateralReturnAndTotal: txBuilder_setCollateralReturnAndTotal, setTotalCollateral: txBuilder_setTotalCollateral, setTotalCollateralAndReturn: txBuilder_setTotalCollateralAndReturn, addReferenceIn: txBuilder_addReferenceIn, addKeyIn: txBuilder_addKeyIn, addScriptIn: txBuilder_addScriptIn, addNativeScriptIn: txBuilder_addNativeScriptIn, addPlutusScriptIn: txBuilder_addPlutusScriptIn, addBootstrapIn: txBuilder_addBootstrapIn, addIn: txBuilder_addIn, countMissingInScripts: txBuilder_countMissingInScripts, addRequiredNativeInScripts: txBuilder_addRequiredNativeInScripts, addRequiredPlutusInScripts: txBuilder_addRequiredPlutusInScripts, getNativeInScripts: txBuilder_getNativeInScripts, getPlutusInScripts: txBuilder_getPlutusInScripts, feeForIn: txBuilder_feeForIn, addOut: txBuilder_addOut, feeForOut: txBuilder_feeForOut, setFee: txBuilder_setFee, setTtl: txBuilder_setTtl, setTtlBignum: txBuilder_setTtlBignum, setValidityStartInterval: txBuilder_setValidityStartInterval, setValidityStartIntervalBignum: txBuilder_setValidityStartIntervalBignum, setCerts: txBuilder_setCerts, setWithdrawals: txBuilder_setWithdrawals, getAuxiliaryData: txBuilder_getAuxiliaryData, setAuxiliaryData: txBuilder_setAuxiliaryData, setMetadata: txBuilder_setMetadata, addMetadatum: txBuilder_addMetadatum, addJsonMetadatum: txBuilder_addJsonMetadatum, addJsonMetadatumWithSchema: txBuilder_addJsonMetadatumWithSchema, setMint: txBuilder_setMint, getMint: txBuilder_getMint, getMintScripts: txBuilder_getMintScripts, setMintAsset: txBuilder_setMintAsset, addMintAsset: txBuilder_addMintAsset, addMintAssetAndOut: txBuilder_addMintAssetAndOut, addMintAssetAndOutMinRequiredCoin: txBuilder_addMintAssetAndOutMinRequiredCoin, new: txBuilder_new, getReferenceIns: txBuilder_getReferenceIns, getExplicitIn: txBuilder_getExplicitIn, getImplicitIn: txBuilder_getImplicitIn, getTotalIn: txBuilder_getTotalIn, getTotalOut: txBuilder_getTotalOut, getExplicitOut: txBuilder_getExplicitOut, getDeposit: txBuilder_getDeposit, getFeeIfSet: txBuilder_getFeeIfSet, addChangeIfNeeded: txBuilder_addChangeIfNeeded, calcScriptDataHash: txBuilder_calcScriptDataHash, setScriptDataHash: txBuilder_setScriptDataHash, removeScriptDataHash: txBuilder_removeScriptDataHash, addRequiredSigner: txBuilder_addRequiredSigner, fullSize: txBuilder_fullSize, outSizes: txBuilder_outSizes, build: txBuilder_build, buildTx: txBuilder_buildTx, buildTxUnsafe: txBuilder_buildTxUnsafe, minFee: txBuilder_minFee }

-------------------------------------------------------------------------------------
-- txBuilderConfig

foreign import txBuilderConfig_free :: TxBuilderConfig -> Effect Unit

type TxBuilderConfigClass = { free :: TxBuilderConfig -> Effect Unit }

txBuilderConfig :: TxBuilderConfigClass
txBuilderConfig = { free: txBuilderConfig_free }

-------------------------------------------------------------------------------------
-- txBuilderConfigBuilder

foreign import txBuilderConfigBuilder_free :: TxBuilderConfigBuilder -> Effect Unit
foreign import txBuilderConfigBuilder_new :: TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_feeAlgo :: TxBuilderConfigBuilder -> LinearFee -> TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_coinsPerUtxoWord :: TxBuilderConfigBuilder -> BigNum -> TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_coinsPerUtxoByte :: TxBuilderConfigBuilder -> BigNum -> TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_exUnitPrices :: TxBuilderConfigBuilder -> ExUnitPrices -> TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_poolDeposit :: TxBuilderConfigBuilder -> BigNum -> TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_keyDeposit :: TxBuilderConfigBuilder -> BigNum -> TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_maxValueSize :: TxBuilderConfigBuilder -> Number -> TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_maxTxSize :: TxBuilderConfigBuilder -> Number -> TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_preferPureChange :: TxBuilderConfigBuilder -> Boolean -> TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_build :: TxBuilderConfigBuilder -> TxBuilderConfig

type TxBuilderConfigBuilderClass = { free :: TxBuilderConfigBuilder -> Effect Unit, new :: TxBuilderConfigBuilder, feeAlgo :: TxBuilderConfigBuilder -> LinearFee -> TxBuilderConfigBuilder, coinsPerUtxoWord :: TxBuilderConfigBuilder -> BigNum -> TxBuilderConfigBuilder, coinsPerUtxoByte :: TxBuilderConfigBuilder -> BigNum -> TxBuilderConfigBuilder, exUnitPrices :: TxBuilderConfigBuilder -> ExUnitPrices -> TxBuilderConfigBuilder, poolDeposit :: TxBuilderConfigBuilder -> BigNum -> TxBuilderConfigBuilder, keyDeposit :: TxBuilderConfigBuilder -> BigNum -> TxBuilderConfigBuilder, maxValueSize :: TxBuilderConfigBuilder -> Number -> TxBuilderConfigBuilder, maxTxSize :: TxBuilderConfigBuilder -> Number -> TxBuilderConfigBuilder, preferPureChange :: TxBuilderConfigBuilder -> Boolean -> TxBuilderConfigBuilder, build :: TxBuilderConfigBuilder -> TxBuilderConfig }

txBuilderConfigBuilder :: TxBuilderConfigBuilderClass
txBuilderConfigBuilder = { free: txBuilderConfigBuilder_free, new: txBuilderConfigBuilder_new, feeAlgo: txBuilderConfigBuilder_feeAlgo, coinsPerUtxoWord: txBuilderConfigBuilder_coinsPerUtxoWord, coinsPerUtxoByte: txBuilderConfigBuilder_coinsPerUtxoByte, exUnitPrices: txBuilderConfigBuilder_exUnitPrices, poolDeposit: txBuilderConfigBuilder_poolDeposit, keyDeposit: txBuilderConfigBuilder_keyDeposit, maxValueSize: txBuilderConfigBuilder_maxValueSize, maxTxSize: txBuilderConfigBuilder_maxTxSize, preferPureChange: txBuilderConfigBuilder_preferPureChange, build: txBuilderConfigBuilder_build }

-------------------------------------------------------------------------------------
-- txHash

foreign import txHash_free :: TxHash -> Effect Unit
foreign import txHash_fromBytes :: Bytes -> TxHash
foreign import txHash_toBytes :: TxHash -> Bytes
foreign import txHash_toBech32 :: TxHash -> String -> String
foreign import txHash_fromBech32 :: String -> TxHash
foreign import txHash_toHex :: TxHash -> String
foreign import txHash_fromHex :: String -> TxHash

type TxHashClass = { free :: TxHash -> Effect Unit, fromBytes :: Bytes -> TxHash, toBytes :: TxHash -> Bytes, toBech32 :: TxHash -> String -> String, fromBech32 :: String -> TxHash, toHex :: TxHash -> String, fromHex :: String -> TxHash }

txHash :: TxHashClass
txHash = { free: txHash_free, fromBytes: txHash_fromBytes, toBytes: txHash_toBytes, toBech32: txHash_toBech32, fromBech32: txHash_fromBech32, toHex: txHash_toHex, fromHex: txHash_fromHex }

-------------------------------------------------------------------------------------
-- txIn

foreign import txIn_free :: TxIn -> Effect Unit
foreign import txIn_toBytes :: TxIn -> Bytes
foreign import txIn_fromBytes :: Bytes -> TxIn
foreign import txIn_toHex :: TxIn -> String
foreign import txIn_fromHex :: String -> TxIn
foreign import txIn_toJson :: TxIn -> String
foreign import txIn_toJsValue :: TxIn -> TxInJs
foreign import txIn_fromJson :: String -> TxIn
foreign import txIn_txId :: TxIn -> TxHash
foreign import txIn_index :: TxIn -> Number
foreign import txIn_new :: TxHash -> Number -> TxIn

type TxInClass = { free :: TxIn -> Effect Unit, toBytes :: TxIn -> Bytes, fromBytes :: Bytes -> TxIn, toHex :: TxIn -> String, fromHex :: String -> TxIn, toJson :: TxIn -> String, toJsValue :: TxIn -> TxInJs, fromJson :: String -> TxIn, txId :: TxIn -> TxHash, index :: TxIn -> Number, new :: TxHash -> Number -> TxIn }

txIn :: TxInClass
txIn = { free: txIn_free, toBytes: txIn_toBytes, fromBytes: txIn_fromBytes, toHex: txIn_toHex, fromHex: txIn_fromHex, toJson: txIn_toJson, toJsValue: txIn_toJsValue, fromJson: txIn_fromJson, txId: txIn_txId, index: txIn_index, new: txIn_new }

-------------------------------------------------------------------------------------
-- txIns

foreign import txIns_free :: TxIns -> Effect Unit
foreign import txIns_toBytes :: TxIns -> Bytes
foreign import txIns_fromBytes :: Bytes -> TxIns
foreign import txIns_toHex :: TxIns -> String
foreign import txIns_fromHex :: String -> TxIns
foreign import txIns_toJson :: TxIns -> String
foreign import txIns_toJsValue :: TxIns -> TxInsJs
foreign import txIns_fromJson :: String -> TxIns
foreign import txIns_new :: TxIns
foreign import txIns_len :: TxIns -> Number
foreign import txIns_get :: TxIns -> Number -> TxIn
foreign import txIns_add :: TxIns -> TxIn -> Effect Unit
foreign import txIns_toOption :: TxIns -> Maybe TxIns

type TxInsClass = { free :: TxIns -> Effect Unit, toBytes :: TxIns -> Bytes, fromBytes :: Bytes -> TxIns, toHex :: TxIns -> String, fromHex :: String -> TxIns, toJson :: TxIns -> String, toJsValue :: TxIns -> TxInsJs, fromJson :: String -> TxIns, new :: TxIns, len :: TxIns -> Number, get :: TxIns -> Number -> TxIn, add :: TxIns -> TxIn -> Effect Unit, toOption :: TxIns -> Maybe TxIns }

txIns :: TxInsClass
txIns = { free: txIns_free, toBytes: txIns_toBytes, fromBytes: txIns_fromBytes, toHex: txIns_toHex, fromHex: txIns_fromHex, toJson: txIns_toJson, toJsValue: txIns_toJsValue, fromJson: txIns_fromJson, new: txIns_new, len: txIns_len, get: txIns_get, add: txIns_add, toOption: txIns_toOption }

-------------------------------------------------------------------------------------
-- txMetadatum

foreign import txMetadatum_free :: TxMetadatum -> Effect Unit
foreign import txMetadatum_toBytes :: TxMetadatum -> Bytes
foreign import txMetadatum_fromBytes :: Bytes -> TxMetadatum
foreign import txMetadatum_toHex :: TxMetadatum -> String
foreign import txMetadatum_fromHex :: String -> TxMetadatum
foreign import txMetadatum_newMap :: MetadataMap -> TxMetadatum
foreign import txMetadatum_newList :: MetadataList -> TxMetadatum
foreign import txMetadatum_newInt :: Int -> TxMetadatum
foreign import txMetadatum_newBytes :: Bytes -> TxMetadatum
foreign import txMetadatum_newText :: String -> TxMetadatum
foreign import txMetadatum_kind :: TxMetadatum -> Number
foreign import txMetadatum_asMap :: TxMetadatum -> MetadataMap
foreign import txMetadatum_asList :: TxMetadatum -> MetadataList
foreign import txMetadatum_asInt :: TxMetadatum -> Int
foreign import txMetadatum_asBytes :: TxMetadatum -> Bytes
foreign import txMetadatum_asText :: TxMetadatum -> String

type TxMetadatumClass = { free :: TxMetadatum -> Effect Unit, toBytes :: TxMetadatum -> Bytes, fromBytes :: Bytes -> TxMetadatum, toHex :: TxMetadatum -> String, fromHex :: String -> TxMetadatum, newMap :: MetadataMap -> TxMetadatum, newList :: MetadataList -> TxMetadatum, newInt :: Int -> TxMetadatum, newBytes :: Bytes -> TxMetadatum, newText :: String -> TxMetadatum, kind :: TxMetadatum -> Number, asMap :: TxMetadatum -> MetadataMap, asList :: TxMetadatum -> MetadataList, asInt :: TxMetadatum -> Int, asBytes :: TxMetadatum -> Bytes, asText :: TxMetadatum -> String }

txMetadatum :: TxMetadatumClass
txMetadatum = { free: txMetadatum_free, toBytes: txMetadatum_toBytes, fromBytes: txMetadatum_fromBytes, toHex: txMetadatum_toHex, fromHex: txMetadatum_fromHex, newMap: txMetadatum_newMap, newList: txMetadatum_newList, newInt: txMetadatum_newInt, newBytes: txMetadatum_newBytes, newText: txMetadatum_newText, kind: txMetadatum_kind, asMap: txMetadatum_asMap, asList: txMetadatum_asList, asInt: txMetadatum_asInt, asBytes: txMetadatum_asBytes, asText: txMetadatum_asText }

-------------------------------------------------------------------------------------
-- txMetadatumLabels

foreign import txMetadatumLabels_free :: TxMetadatumLabels -> Effect Unit
foreign import txMetadatumLabels_toBytes :: TxMetadatumLabels -> Bytes
foreign import txMetadatumLabels_fromBytes :: Bytes -> TxMetadatumLabels
foreign import txMetadatumLabels_toHex :: TxMetadatumLabels -> String
foreign import txMetadatumLabels_fromHex :: String -> TxMetadatumLabels
foreign import txMetadatumLabels_new :: TxMetadatumLabels
foreign import txMetadatumLabels_len :: TxMetadatumLabels -> Number
foreign import txMetadatumLabels_get :: TxMetadatumLabels -> Number -> BigNum
foreign import txMetadatumLabels_add :: TxMetadatumLabels -> BigNum -> Effect Unit

type TxMetadatumLabelsClass = { free :: TxMetadatumLabels -> Effect Unit, toBytes :: TxMetadatumLabels -> Bytes, fromBytes :: Bytes -> TxMetadatumLabels, toHex :: TxMetadatumLabels -> String, fromHex :: String -> TxMetadatumLabels, new :: TxMetadatumLabels, len :: TxMetadatumLabels -> Number, get :: TxMetadatumLabels -> Number -> BigNum, add :: TxMetadatumLabels -> BigNum -> Effect Unit }

txMetadatumLabels :: TxMetadatumLabelsClass
txMetadatumLabels = { free: txMetadatumLabels_free, toBytes: txMetadatumLabels_toBytes, fromBytes: txMetadatumLabels_fromBytes, toHex: txMetadatumLabels_toHex, fromHex: txMetadatumLabels_fromHex, new: txMetadatumLabels_new, len: txMetadatumLabels_len, get: txMetadatumLabels_get, add: txMetadatumLabels_add }

-------------------------------------------------------------------------------------
-- txOut

foreign import txOut_free :: TxOut -> Effect Unit
foreign import txOut_toBytes :: TxOut -> Bytes
foreign import txOut_fromBytes :: Bytes -> TxOut
foreign import txOut_toHex :: TxOut -> String
foreign import txOut_fromHex :: String -> TxOut
foreign import txOut_toJson :: TxOut -> String
foreign import txOut_toJsValue :: TxOut -> TxOutJs
foreign import txOut_fromJson :: String -> TxOut
foreign import txOut_address :: TxOut -> Address
foreign import txOut_amount :: TxOut -> Value
foreign import txOut_dataHash :: TxOut -> Maybe DataHash
foreign import txOut_plutusData :: TxOut -> Maybe PlutusData
foreign import txOut_scriptRef :: TxOut -> Maybe ScriptRef
foreign import txOut_setScriptRef :: TxOut -> ScriptRef -> Effect Unit
foreign import txOut_setPlutusData :: TxOut -> PlutusData -> Effect Unit
foreign import txOut_setDataHash :: TxOut -> DataHash -> Effect Unit
foreign import txOut_hasPlutusData :: TxOut -> Boolean
foreign import txOut_hasDataHash :: TxOut -> Boolean
foreign import txOut_hasScriptRef :: TxOut -> Boolean
foreign import txOut_new :: Address -> Value -> TxOut

type TxOutClass = { free :: TxOut -> Effect Unit, toBytes :: TxOut -> Bytes, fromBytes :: Bytes -> TxOut, toHex :: TxOut -> String, fromHex :: String -> TxOut, toJson :: TxOut -> String, toJsValue :: TxOut -> TxOutJs, fromJson :: String -> TxOut, address :: TxOut -> Address, amount :: TxOut -> Value, dataHash :: TxOut -> Maybe DataHash, plutusData :: TxOut -> Maybe PlutusData, scriptRef :: TxOut -> Maybe ScriptRef, setScriptRef :: TxOut -> ScriptRef -> Effect Unit, setPlutusData :: TxOut -> PlutusData -> Effect Unit, setDataHash :: TxOut -> DataHash -> Effect Unit, hasPlutusData :: TxOut -> Boolean, hasDataHash :: TxOut -> Boolean, hasScriptRef :: TxOut -> Boolean, new :: Address -> Value -> TxOut }

txOut :: TxOutClass
txOut = { free: txOut_free, toBytes: txOut_toBytes, fromBytes: txOut_fromBytes, toHex: txOut_toHex, fromHex: txOut_fromHex, toJson: txOut_toJson, toJsValue: txOut_toJsValue, fromJson: txOut_fromJson, address: txOut_address, amount: txOut_amount, dataHash: txOut_dataHash, plutusData: txOut_plutusData, scriptRef: txOut_scriptRef, setScriptRef: txOut_setScriptRef, setPlutusData: txOut_setPlutusData, setDataHash: txOut_setDataHash, hasPlutusData: txOut_hasPlutusData, hasDataHash: txOut_hasDataHash, hasScriptRef: txOut_hasScriptRef, new: txOut_new }

-------------------------------------------------------------------------------------
-- txOutAmountBuilder

foreign import txOutAmountBuilder_free :: TxOutAmountBuilder -> Effect Unit
foreign import txOutAmountBuilder_withValue :: TxOutAmountBuilder -> Value -> TxOutAmountBuilder
foreign import txOutAmountBuilder_withCoin :: TxOutAmountBuilder -> BigNum -> TxOutAmountBuilder
foreign import txOutAmountBuilder_withCoinAndAsset :: TxOutAmountBuilder -> BigNum -> MultiAsset -> TxOutAmountBuilder
foreign import txOutAmountBuilder_withAssetAndMinRequiredCoin :: TxOutAmountBuilder -> MultiAsset -> BigNum -> TxOutAmountBuilder
foreign import txOutAmountBuilder_withAssetAndMinRequiredCoinByUtxoCost :: TxOutAmountBuilder -> MultiAsset -> DataCost -> TxOutAmountBuilder
foreign import txOutAmountBuilder_build :: TxOutAmountBuilder -> TxOut

type TxOutAmountBuilderClass = { free :: TxOutAmountBuilder -> Effect Unit, withValue :: TxOutAmountBuilder -> Value -> TxOutAmountBuilder, withCoin :: TxOutAmountBuilder -> BigNum -> TxOutAmountBuilder, withCoinAndAsset :: TxOutAmountBuilder -> BigNum -> MultiAsset -> TxOutAmountBuilder, withAssetAndMinRequiredCoin :: TxOutAmountBuilder -> MultiAsset -> BigNum -> TxOutAmountBuilder, withAssetAndMinRequiredCoinByUtxoCost :: TxOutAmountBuilder -> MultiAsset -> DataCost -> TxOutAmountBuilder, build :: TxOutAmountBuilder -> TxOut }

txOutAmountBuilder :: TxOutAmountBuilderClass
txOutAmountBuilder = { free: txOutAmountBuilder_free, withValue: txOutAmountBuilder_withValue, withCoin: txOutAmountBuilder_withCoin, withCoinAndAsset: txOutAmountBuilder_withCoinAndAsset, withAssetAndMinRequiredCoin: txOutAmountBuilder_withAssetAndMinRequiredCoin, withAssetAndMinRequiredCoinByUtxoCost: txOutAmountBuilder_withAssetAndMinRequiredCoinByUtxoCost, build: txOutAmountBuilder_build }

-------------------------------------------------------------------------------------
-- txOutBuilder

foreign import txOutBuilder_free :: TxOutBuilder -> Effect Unit
foreign import txOutBuilder_new :: TxOutBuilder
foreign import txOutBuilder_withAddress :: TxOutBuilder -> Address -> TxOutBuilder
foreign import txOutBuilder_withDataHash :: TxOutBuilder -> DataHash -> TxOutBuilder
foreign import txOutBuilder_withPlutusData :: TxOutBuilder -> PlutusData -> TxOutBuilder
foreign import txOutBuilder_withScriptRef :: TxOutBuilder -> ScriptRef -> TxOutBuilder
foreign import txOutBuilder_next :: TxOutBuilder -> TxOutAmountBuilder

type TxOutBuilderClass = { free :: TxOutBuilder -> Effect Unit, new :: TxOutBuilder, withAddress :: TxOutBuilder -> Address -> TxOutBuilder, withDataHash :: TxOutBuilder -> DataHash -> TxOutBuilder, withPlutusData :: TxOutBuilder -> PlutusData -> TxOutBuilder, withScriptRef :: TxOutBuilder -> ScriptRef -> TxOutBuilder, next :: TxOutBuilder -> TxOutAmountBuilder }

txOutBuilder :: TxOutBuilderClass
txOutBuilder = { free: txOutBuilder_free, new: txOutBuilder_new, withAddress: txOutBuilder_withAddress, withDataHash: txOutBuilder_withDataHash, withPlutusData: txOutBuilder_withPlutusData, withScriptRef: txOutBuilder_withScriptRef, next: txOutBuilder_next }

-------------------------------------------------------------------------------------
-- txOuts

foreign import txOuts_free :: TxOuts -> Effect Unit
foreign import txOuts_toBytes :: TxOuts -> Bytes
foreign import txOuts_fromBytes :: Bytes -> TxOuts
foreign import txOuts_toHex :: TxOuts -> String
foreign import txOuts_fromHex :: String -> TxOuts
foreign import txOuts_toJson :: TxOuts -> String
foreign import txOuts_toJsValue :: TxOuts -> TxOutsJs
foreign import txOuts_fromJson :: String -> TxOuts
foreign import txOuts_new :: TxOuts
foreign import txOuts_len :: TxOuts -> Number
foreign import txOuts_get :: TxOuts -> Number -> TxOut
foreign import txOuts_add :: TxOuts -> TxOut -> Effect Unit

type TxOutsClass = { free :: TxOuts -> Effect Unit, toBytes :: TxOuts -> Bytes, fromBytes :: Bytes -> TxOuts, toHex :: TxOuts -> String, fromHex :: String -> TxOuts, toJson :: TxOuts -> String, toJsValue :: TxOuts -> TxOutsJs, fromJson :: String -> TxOuts, new :: TxOuts, len :: TxOuts -> Number, get :: TxOuts -> Number -> TxOut, add :: TxOuts -> TxOut -> Effect Unit }

txOuts :: TxOutsClass
txOuts = { free: txOuts_free, toBytes: txOuts_toBytes, fromBytes: txOuts_fromBytes, toHex: txOuts_toHex, fromHex: txOuts_fromHex, toJson: txOuts_toJson, toJsValue: txOuts_toJsValue, fromJson: txOuts_fromJson, new: txOuts_new, len: txOuts_len, get: txOuts_get, add: txOuts_add }

-------------------------------------------------------------------------------------
-- txUnspentOut

foreign import txUnspentOut_free :: TxUnspentOut -> Effect Unit
foreign import txUnspentOut_toBytes :: TxUnspentOut -> Bytes
foreign import txUnspentOut_fromBytes :: Bytes -> TxUnspentOut
foreign import txUnspentOut_toHex :: TxUnspentOut -> String
foreign import txUnspentOut_fromHex :: String -> TxUnspentOut
foreign import txUnspentOut_toJson :: TxUnspentOut -> String
foreign import txUnspentOut_toJsValue :: TxUnspentOut -> TxUnspentOutJs
foreign import txUnspentOut_fromJson :: String -> TxUnspentOut
foreign import txUnspentOut_new :: TxIn -> TxOut -> TxUnspentOut
foreign import txUnspentOut_in :: TxUnspentOut -> TxIn
foreign import txUnspentOut_out :: TxUnspentOut -> TxOut

type TxUnspentOutClass = { free :: TxUnspentOut -> Effect Unit, toBytes :: TxUnspentOut -> Bytes, fromBytes :: Bytes -> TxUnspentOut, toHex :: TxUnspentOut -> String, fromHex :: String -> TxUnspentOut, toJson :: TxUnspentOut -> String, toJsValue :: TxUnspentOut -> TxUnspentOutJs, fromJson :: String -> TxUnspentOut, new :: TxIn -> TxOut -> TxUnspentOut, in :: TxUnspentOut -> TxIn, out :: TxUnspentOut -> TxOut }

txUnspentOut :: TxUnspentOutClass
txUnspentOut = { free: txUnspentOut_free, toBytes: txUnspentOut_toBytes, fromBytes: txUnspentOut_fromBytes, toHex: txUnspentOut_toHex, fromHex: txUnspentOut_fromHex, toJson: txUnspentOut_toJson, toJsValue: txUnspentOut_toJsValue, fromJson: txUnspentOut_fromJson, new: txUnspentOut_new, in: txUnspentOut_in, out: txUnspentOut_out }

-------------------------------------------------------------------------------------
-- txUnspentOuts

foreign import txUnspentOuts_free :: TxUnspentOuts -> Effect Unit
foreign import txUnspentOuts_toJson :: TxUnspentOuts -> String
foreign import txUnspentOuts_toJsValue :: TxUnspentOuts -> TxUnspentOutsJs
foreign import txUnspentOuts_fromJson :: String -> TxUnspentOuts
foreign import txUnspentOuts_new :: TxUnspentOuts
foreign import txUnspentOuts_len :: TxUnspentOuts -> Number
foreign import txUnspentOuts_get :: TxUnspentOuts -> Number -> TxUnspentOut
foreign import txUnspentOuts_add :: TxUnspentOuts -> TxUnspentOut -> Effect Unit

type TxUnspentOutsClass = { free :: TxUnspentOuts -> Effect Unit, toJson :: TxUnspentOuts -> String, toJsValue :: TxUnspentOuts -> TxUnspentOutsJs, fromJson :: String -> TxUnspentOuts, new :: TxUnspentOuts, len :: TxUnspentOuts -> Number, get :: TxUnspentOuts -> Number -> TxUnspentOut, add :: TxUnspentOuts -> TxUnspentOut -> Effect Unit }

txUnspentOuts :: TxUnspentOutsClass
txUnspentOuts = { free: txUnspentOuts_free, toJson: txUnspentOuts_toJson, toJsValue: txUnspentOuts_toJsValue, fromJson: txUnspentOuts_fromJson, new: txUnspentOuts_new, len: txUnspentOuts_len, get: txUnspentOuts_get, add: txUnspentOuts_add }

-------------------------------------------------------------------------------------
-- txWitnessSet

foreign import txWitnessSet_free :: TxWitnessSet -> Effect Unit
foreign import txWitnessSet_toBytes :: TxWitnessSet -> Bytes
foreign import txWitnessSet_fromBytes :: Bytes -> TxWitnessSet
foreign import txWitnessSet_toHex :: TxWitnessSet -> String
foreign import txWitnessSet_fromHex :: String -> TxWitnessSet
foreign import txWitnessSet_toJson :: TxWitnessSet -> String
foreign import txWitnessSet_toJsValue :: TxWitnessSet -> TxWitnessSetJs
foreign import txWitnessSet_fromJson :: String -> TxWitnessSet
foreign import txWitnessSet_setVkeys :: TxWitnessSet -> Vkeywitnesses -> Effect Unit
foreign import txWitnessSet_vkeys :: TxWitnessSet -> Maybe Vkeywitnesses
foreign import txWitnessSet_setNativeScripts :: TxWitnessSet -> NativeScripts -> Effect Unit
foreign import txWitnessSet_nativeScripts :: TxWitnessSet -> Maybe NativeScripts
foreign import txWitnessSet_setBootstraps :: TxWitnessSet -> BootstrapWitnesses -> Effect Unit
foreign import txWitnessSet_bootstraps :: TxWitnessSet -> Maybe BootstrapWitnesses
foreign import txWitnessSet_setPlutusScripts :: TxWitnessSet -> PlutusScripts -> Effect Unit
foreign import txWitnessSet_plutusScripts :: TxWitnessSet -> Maybe PlutusScripts
foreign import txWitnessSet_setPlutusData :: TxWitnessSet -> PlutusList -> Effect Unit
foreign import txWitnessSet_plutusData :: TxWitnessSet -> Maybe PlutusList
foreign import txWitnessSet_setRedeemers :: TxWitnessSet -> Redeemers -> Effect Unit
foreign import txWitnessSet_redeemers :: TxWitnessSet -> Maybe Redeemers
foreign import txWitnessSet_new :: TxWitnessSet

type TxWitnessSetClass = { free :: TxWitnessSet -> Effect Unit, toBytes :: TxWitnessSet -> Bytes, fromBytes :: Bytes -> TxWitnessSet, toHex :: TxWitnessSet -> String, fromHex :: String -> TxWitnessSet, toJson :: TxWitnessSet -> String, toJsValue :: TxWitnessSet -> TxWitnessSetJs, fromJson :: String -> TxWitnessSet, setVkeys :: TxWitnessSet -> Vkeywitnesses -> Effect Unit, vkeys :: TxWitnessSet -> Maybe Vkeywitnesses, setNativeScripts :: TxWitnessSet -> NativeScripts -> Effect Unit, nativeScripts :: TxWitnessSet -> Maybe NativeScripts, setBootstraps :: TxWitnessSet -> BootstrapWitnesses -> Effect Unit, bootstraps :: TxWitnessSet -> Maybe BootstrapWitnesses, setPlutusScripts :: TxWitnessSet -> PlutusScripts -> Effect Unit, plutusScripts :: TxWitnessSet -> Maybe PlutusScripts, setPlutusData :: TxWitnessSet -> PlutusList -> Effect Unit, plutusData :: TxWitnessSet -> Maybe PlutusList, setRedeemers :: TxWitnessSet -> Redeemers -> Effect Unit, redeemers :: TxWitnessSet -> Maybe Redeemers, new :: TxWitnessSet }

txWitnessSet :: TxWitnessSetClass
txWitnessSet = { free: txWitnessSet_free, toBytes: txWitnessSet_toBytes, fromBytes: txWitnessSet_fromBytes, toHex: txWitnessSet_toHex, fromHex: txWitnessSet_fromHex, toJson: txWitnessSet_toJson, toJsValue: txWitnessSet_toJsValue, fromJson: txWitnessSet_fromJson, setVkeys: txWitnessSet_setVkeys, vkeys: txWitnessSet_vkeys, setNativeScripts: txWitnessSet_setNativeScripts, nativeScripts: txWitnessSet_nativeScripts, setBootstraps: txWitnessSet_setBootstraps, bootstraps: txWitnessSet_bootstraps, setPlutusScripts: txWitnessSet_setPlutusScripts, plutusScripts: txWitnessSet_plutusScripts, setPlutusData: txWitnessSet_setPlutusData, plutusData: txWitnessSet_plutusData, setRedeemers: txWitnessSet_setRedeemers, redeemers: txWitnessSet_redeemers, new: txWitnessSet_new }

-------------------------------------------------------------------------------------
-- txWitnessSets

foreign import txWitnessSets_free :: TxWitnessSets -> Effect Unit
foreign import txWitnessSets_toBytes :: TxWitnessSets -> Bytes
foreign import txWitnessSets_fromBytes :: Bytes -> TxWitnessSets
foreign import txWitnessSets_toHex :: TxWitnessSets -> String
foreign import txWitnessSets_fromHex :: String -> TxWitnessSets
foreign import txWitnessSets_toJson :: TxWitnessSets -> String
foreign import txWitnessSets_toJsValue :: TxWitnessSets -> TxWitnessSetsJs
foreign import txWitnessSets_fromJson :: String -> TxWitnessSets
foreign import txWitnessSets_new :: TxWitnessSets
foreign import txWitnessSets_len :: TxWitnessSets -> Number
foreign import txWitnessSets_get :: TxWitnessSets -> Number -> TxWitnessSet
foreign import txWitnessSets_add :: TxWitnessSets -> TxWitnessSet -> Effect Unit

type TxWitnessSetsClass = { free :: TxWitnessSets -> Effect Unit, toBytes :: TxWitnessSets -> Bytes, fromBytes :: Bytes -> TxWitnessSets, toHex :: TxWitnessSets -> String, fromHex :: String -> TxWitnessSets, toJson :: TxWitnessSets -> String, toJsValue :: TxWitnessSets -> TxWitnessSetsJs, fromJson :: String -> TxWitnessSets, new :: TxWitnessSets, len :: TxWitnessSets -> Number, get :: TxWitnessSets -> Number -> TxWitnessSet, add :: TxWitnessSets -> TxWitnessSet -> Effect Unit }

txWitnessSets :: TxWitnessSetsClass
txWitnessSets = { free: txWitnessSets_free, toBytes: txWitnessSets_toBytes, fromBytes: txWitnessSets_fromBytes, toHex: txWitnessSets_toHex, fromHex: txWitnessSets_fromHex, toJson: txWitnessSets_toJson, toJsValue: txWitnessSets_toJsValue, fromJson: txWitnessSets_fromJson, new: txWitnessSets_new, len: txWitnessSets_len, get: txWitnessSets_get, add: txWitnessSets_add }

-------------------------------------------------------------------------------------
-- txBuilderConstants

foreign import txBuilderConstants_free :: TxBuilderConstants -> Effect Unit
foreign import txBuilderConstants_plutusDefaultCostModels :: Costmdls
foreign import txBuilderConstants_plutusAlonzoCostModels :: Costmdls
foreign import txBuilderConstants_plutusVasilCostModels :: Costmdls

type TxBuilderConstantsClass = { free :: TxBuilderConstants -> Effect Unit, plutusDefaultCostModels :: Costmdls, plutusAlonzoCostModels :: Costmdls, plutusVasilCostModels :: Costmdls }

txBuilderConstants :: TxBuilderConstantsClass
txBuilderConstants = { free: txBuilderConstants_free, plutusDefaultCostModels: txBuilderConstants_plutusDefaultCostModels, plutusAlonzoCostModels: txBuilderConstants_plutusAlonzoCostModels, plutusVasilCostModels: txBuilderConstants_plutusVasilCostModels }

-------------------------------------------------------------------------------------
-- txInsBuilder

foreign import txInsBuilder_free :: TxInsBuilder -> Effect Unit
foreign import txInsBuilder_new :: Effect TxInsBuilder
foreign import txInsBuilder_addKeyIn :: TxInsBuilder -> Ed25519KeyHash -> TxIn -> Value -> Effect Unit
foreign import txInsBuilder_addScriptIn :: TxInsBuilder -> ScriptHash -> TxIn -> Value -> Effect Unit
foreign import txInsBuilder_addNativeScriptIn :: TxInsBuilder -> NativeScript -> TxIn -> Value -> Effect Unit
foreign import txInsBuilder_addPlutusScriptIn :: TxInsBuilder -> PlutusWitness -> TxIn -> Value -> Effect Unit
foreign import txInsBuilder_addBootstrapIn :: TxInsBuilder -> ByronAddress -> TxIn -> Value -> Effect Unit
foreign import txInsBuilder_addIn :: TxInsBuilder -> Address -> TxIn -> Value -> Effect Unit
foreign import txInsBuilder_countMissingInScripts :: TxInsBuilder -> Number
foreign import txInsBuilder_addRequiredNativeInScripts :: TxInsBuilder -> NativeScripts -> Number
foreign import txInsBuilder_addRequiredPlutusInScripts :: TxInsBuilder -> PlutusWitnesses -> Number
foreign import txInsBuilder_getRefIns :: TxInsBuilder -> TxIns
foreign import txInsBuilder_getNativeInScripts :: TxInsBuilder -> Maybe NativeScripts
foreign import txInsBuilder_getPlutusInScripts :: TxInsBuilder -> Maybe PlutusWitnesses
foreign import txInsBuilder_len :: TxInsBuilder -> Number
foreign import txInsBuilder_addRequiredSigner :: TxInsBuilder -> Ed25519KeyHash -> Effect Unit
foreign import txInsBuilder_addRequiredSigners :: TxInsBuilder -> Ed25519KeyHashes -> Effect Unit
foreign import txInsBuilder_totalValue :: TxInsBuilder -> Value
foreign import txInsBuilder_ins :: TxInsBuilder -> TxIns
foreign import txInsBuilder_insOption :: TxInsBuilder -> Maybe TxIns

type TxInsBuilderClass = { free :: TxInsBuilder -> Effect Unit, new :: Effect TxInsBuilder, addKeyIn :: TxInsBuilder -> Ed25519KeyHash -> TxIn -> Value -> Effect Unit, addScriptIn :: TxInsBuilder -> ScriptHash -> TxIn -> Value -> Effect Unit, addNativeScriptIn :: TxInsBuilder -> NativeScript -> TxIn -> Value -> Effect Unit, addPlutusScriptIn :: TxInsBuilder -> PlutusWitness -> TxIn -> Value -> Effect Unit, addBootstrapIn :: TxInsBuilder -> ByronAddress -> TxIn -> Value -> Effect Unit, addIn :: TxInsBuilder -> Address -> TxIn -> Value -> Effect Unit, countMissingInScripts :: TxInsBuilder -> Number, addRequiredNativeInScripts :: TxInsBuilder -> NativeScripts -> Number, addRequiredPlutusInScripts :: TxInsBuilder -> PlutusWitnesses -> Number, getRefIns :: TxInsBuilder -> TxIns, getNativeInScripts :: TxInsBuilder -> Maybe NativeScripts, getPlutusInScripts :: TxInsBuilder -> Maybe PlutusWitnesses, len :: TxInsBuilder -> Number, addRequiredSigner :: TxInsBuilder -> Ed25519KeyHash -> Effect Unit, addRequiredSigners :: TxInsBuilder -> Ed25519KeyHashes -> Effect Unit, totalValue :: TxInsBuilder -> Value, ins :: TxInsBuilder -> TxIns, insOption :: TxInsBuilder -> Maybe TxIns }

txInsBuilder :: TxInsBuilderClass
txInsBuilder = { free: txInsBuilder_free, new: txInsBuilder_new, addKeyIn: txInsBuilder_addKeyIn, addScriptIn: txInsBuilder_addScriptIn, addNativeScriptIn: txInsBuilder_addNativeScriptIn, addPlutusScriptIn: txInsBuilder_addPlutusScriptIn, addBootstrapIn: txInsBuilder_addBootstrapIn, addIn: txInsBuilder_addIn, countMissingInScripts: txInsBuilder_countMissingInScripts, addRequiredNativeInScripts: txInsBuilder_addRequiredNativeInScripts, addRequiredPlutusInScripts: txInsBuilder_addRequiredPlutusInScripts, getRefIns: txInsBuilder_getRefIns, getNativeInScripts: txInsBuilder_getNativeInScripts, getPlutusInScripts: txInsBuilder_getPlutusInScripts, len: txInsBuilder_len, addRequiredSigner: txInsBuilder_addRequiredSigner, addRequiredSigners: txInsBuilder_addRequiredSigners, totalValue: txInsBuilder_totalValue, ins: txInsBuilder_ins, insOption: txInsBuilder_insOption }

-------------------------------------------------------------------------------------
-- uRL

foreign import uRL_free :: URL -> Effect Unit
foreign import uRL_toBytes :: URL -> Bytes
foreign import uRL_fromBytes :: Bytes -> URL
foreign import uRL_toHex :: URL -> String
foreign import uRL_fromHex :: String -> URL
foreign import uRL_toJson :: URL -> String
foreign import uRL_toJsValue :: URL -> URLJs
foreign import uRL_fromJson :: String -> URL
foreign import uRL_new :: String -> URL
foreign import uRL_url :: URL -> String

type URLClass = { free :: URL -> Effect Unit, toBytes :: URL -> Bytes, fromBytes :: Bytes -> URL, toHex :: URL -> String, fromHex :: String -> URL, toJson :: URL -> String, toJsValue :: URL -> URLJs, fromJson :: String -> URL, new :: String -> URL, url :: URL -> String }

uRL :: URLClass
uRL = { free: uRL_free, toBytes: uRL_toBytes, fromBytes: uRL_fromBytes, toHex: uRL_toHex, fromHex: uRL_fromHex, toJson: uRL_toJson, toJsValue: uRL_toJsValue, fromJson: uRL_fromJson, new: uRL_new, url: uRL_url }

-------------------------------------------------------------------------------------
-- unitInterval

foreign import unitInterval_free :: UnitInterval -> Effect Unit
foreign import unitInterval_toBytes :: UnitInterval -> Bytes
foreign import unitInterval_fromBytes :: Bytes -> UnitInterval
foreign import unitInterval_toHex :: UnitInterval -> String
foreign import unitInterval_fromHex :: String -> UnitInterval
foreign import unitInterval_toJson :: UnitInterval -> String
foreign import unitInterval_toJsValue :: UnitInterval -> UnitIntervalJs
foreign import unitInterval_fromJson :: String -> UnitInterval
foreign import unitInterval_numerator :: UnitInterval -> BigNum
foreign import unitInterval_denominator :: UnitInterval -> BigNum
foreign import unitInterval_new :: BigNum -> BigNum -> UnitInterval

type UnitIntervalClass = { free :: UnitInterval -> Effect Unit, toBytes :: UnitInterval -> Bytes, fromBytes :: Bytes -> UnitInterval, toHex :: UnitInterval -> String, fromHex :: String -> UnitInterval, toJson :: UnitInterval -> String, toJsValue :: UnitInterval -> UnitIntervalJs, fromJson :: String -> UnitInterval, numerator :: UnitInterval -> BigNum, denominator :: UnitInterval -> BigNum, new :: BigNum -> BigNum -> UnitInterval }

unitInterval :: UnitIntervalClass
unitInterval = { free: unitInterval_free, toBytes: unitInterval_toBytes, fromBytes: unitInterval_fromBytes, toHex: unitInterval_toHex, fromHex: unitInterval_fromHex, toJson: unitInterval_toJson, toJsValue: unitInterval_toJsValue, fromJson: unitInterval_fromJson, numerator: unitInterval_numerator, denominator: unitInterval_denominator, new: unitInterval_new }

-------------------------------------------------------------------------------------
-- update

foreign import update_free :: Update -> Effect Unit
foreign import update_toBytes :: Update -> Bytes
foreign import update_fromBytes :: Bytes -> Update
foreign import update_toHex :: Update -> String
foreign import update_fromHex :: String -> Update
foreign import update_toJson :: Update -> String
foreign import update_toJsValue :: Update -> UpdateJs
foreign import update_fromJson :: String -> Update
foreign import update_proposedProtocolParameterUpdates :: Update -> ProposedProtocolParameterUpdates
foreign import update_epoch :: Update -> Number
foreign import update_new :: ProposedProtocolParameterUpdates -> Number -> Update

type UpdateClass = { free :: Update -> Effect Unit, toBytes :: Update -> Bytes, fromBytes :: Bytes -> Update, toHex :: Update -> String, fromHex :: String -> Update, toJson :: Update -> String, toJsValue :: Update -> UpdateJs, fromJson :: String -> Update, proposedProtocolParameterUpdates :: Update -> ProposedProtocolParameterUpdates, epoch :: Update -> Number, new :: ProposedProtocolParameterUpdates -> Number -> Update }

update :: UpdateClass
update = { free: update_free, toBytes: update_toBytes, fromBytes: update_fromBytes, toHex: update_toHex, fromHex: update_fromHex, toJson: update_toJson, toJsValue: update_toJsValue, fromJson: update_fromJson, proposedProtocolParameterUpdates: update_proposedProtocolParameterUpdates, epoch: update_epoch, new: update_new }

-------------------------------------------------------------------------------------
-- vRFCert

foreign import vRFCert_free :: VRFCert -> Effect Unit
foreign import vRFCert_toBytes :: VRFCert -> Bytes
foreign import vRFCert_fromBytes :: Bytes -> VRFCert
foreign import vRFCert_toHex :: VRFCert -> String
foreign import vRFCert_fromHex :: String -> VRFCert
foreign import vRFCert_toJson :: VRFCert -> String
foreign import vRFCert_toJsValue :: VRFCert -> VRFCertJs
foreign import vRFCert_fromJson :: String -> VRFCert
foreign import vRFCert_out :: VRFCert -> Bytes
foreign import vRFCert_proof :: VRFCert -> Bytes
foreign import vRFCert_new :: Bytes -> Bytes -> VRFCert

type VRFCertClass = { free :: VRFCert -> Effect Unit, toBytes :: VRFCert -> Bytes, fromBytes :: Bytes -> VRFCert, toHex :: VRFCert -> String, fromHex :: String -> VRFCert, toJson :: VRFCert -> String, toJsValue :: VRFCert -> VRFCertJs, fromJson :: String -> VRFCert, out :: VRFCert -> Bytes, proof :: VRFCert -> Bytes, new :: Bytes -> Bytes -> VRFCert }

vRFCert :: VRFCertClass
vRFCert = { free: vRFCert_free, toBytes: vRFCert_toBytes, fromBytes: vRFCert_fromBytes, toHex: vRFCert_toHex, fromHex: vRFCert_fromHex, toJson: vRFCert_toJson, toJsValue: vRFCert_toJsValue, fromJson: vRFCert_fromJson, out: vRFCert_out, proof: vRFCert_proof, new: vRFCert_new }

-------------------------------------------------------------------------------------
-- vRFKeyHash

foreign import vRFKeyHash_free :: VRFKeyHash -> Effect Unit
foreign import vRFKeyHash_fromBytes :: Bytes -> VRFKeyHash
foreign import vRFKeyHash_toBytes :: VRFKeyHash -> Bytes
foreign import vRFKeyHash_toBech32 :: VRFKeyHash -> String -> String
foreign import vRFKeyHash_fromBech32 :: String -> VRFKeyHash
foreign import vRFKeyHash_toHex :: VRFKeyHash -> String
foreign import vRFKeyHash_fromHex :: String -> VRFKeyHash

type VRFKeyHashClass = { free :: VRFKeyHash -> Effect Unit, fromBytes :: Bytes -> VRFKeyHash, toBytes :: VRFKeyHash -> Bytes, toBech32 :: VRFKeyHash -> String -> String, fromBech32 :: String -> VRFKeyHash, toHex :: VRFKeyHash -> String, fromHex :: String -> VRFKeyHash }

vRFKeyHash :: VRFKeyHashClass
vRFKeyHash = { free: vRFKeyHash_free, fromBytes: vRFKeyHash_fromBytes, toBytes: vRFKeyHash_toBytes, toBech32: vRFKeyHash_toBech32, fromBech32: vRFKeyHash_fromBech32, toHex: vRFKeyHash_toHex, fromHex: vRFKeyHash_fromHex }

-------------------------------------------------------------------------------------
-- vRFVKey

foreign import vRFVKey_free :: VRFVKey -> Effect Unit
foreign import vRFVKey_fromBytes :: Bytes -> VRFVKey
foreign import vRFVKey_toBytes :: VRFVKey -> Bytes
foreign import vRFVKey_toBech32 :: VRFVKey -> String -> String
foreign import vRFVKey_fromBech32 :: String -> VRFVKey
foreign import vRFVKey_toHex :: VRFVKey -> String
foreign import vRFVKey_fromHex :: String -> VRFVKey

type VRFVKeyClass = { free :: VRFVKey -> Effect Unit, fromBytes :: Bytes -> VRFVKey, toBytes :: VRFVKey -> Bytes, toBech32 :: VRFVKey -> String -> String, fromBech32 :: String -> VRFVKey, toHex :: VRFVKey -> String, fromHex :: String -> VRFVKey }

vRFVKey :: VRFVKeyClass
vRFVKey = { free: vRFVKey_free, fromBytes: vRFVKey_fromBytes, toBytes: vRFVKey_toBytes, toBech32: vRFVKey_toBech32, fromBech32: vRFVKey_fromBech32, toHex: vRFVKey_toHex, fromHex: vRFVKey_fromHex }

-------------------------------------------------------------------------------------
-- value

foreign import value_free :: Value -> Effect Unit
foreign import value_toBytes :: Value -> Bytes
foreign import value_fromBytes :: Bytes -> Value
foreign import value_toHex :: Value -> String
foreign import value_fromHex :: String -> Value
foreign import value_toJson :: Value -> String
foreign import value_toJsValue :: Value -> ValueJs
foreign import value_fromJson :: String -> Value
foreign import value_new :: BigNum -> Value
foreign import value_newFromAssets :: MultiAsset -> Value
foreign import value_newWithAssets :: BigNum -> MultiAsset -> Value
foreign import value_zero :: Value
foreign import value_isZero :: Value -> Boolean
foreign import value_coin :: Value -> BigNum
foreign import value_setCoin :: Value -> BigNum -> Effect Unit
foreign import value_multiasset :: Value -> Maybe MultiAsset
foreign import value_setMultiasset :: Value -> MultiAsset -> Effect Unit
foreign import value_checkedAdd :: Value -> Value -> Value
foreign import value_checkedSub :: Value -> Value -> Value
foreign import value_clampedSub :: Value -> Value -> Value
foreign import value_compare :: Value -> Value -> Maybe Number

type ValueClass = { free :: Value -> Effect Unit, toBytes :: Value -> Bytes, fromBytes :: Bytes -> Value, toHex :: Value -> String, fromHex :: String -> Value, toJson :: Value -> String, toJsValue :: Value -> ValueJs, fromJson :: String -> Value, new :: BigNum -> Value, newFromAssets :: MultiAsset -> Value, newWithAssets :: BigNum -> MultiAsset -> Value, zero :: Value, isZero :: Value -> Boolean, coin :: Value -> BigNum, setCoin :: Value -> BigNum -> Effect Unit, multiasset :: Value -> Maybe MultiAsset, setMultiasset :: Value -> MultiAsset -> Effect Unit, checkedAdd :: Value -> Value -> Value, checkedSub :: Value -> Value -> Value, clampedSub :: Value -> Value -> Value, compare :: Value -> Value -> Maybe Number }

value :: ValueClass
value = { free: value_free, toBytes: value_toBytes, fromBytes: value_fromBytes, toHex: value_toHex, fromHex: value_fromHex, toJson: value_toJson, toJsValue: value_toJsValue, fromJson: value_fromJson, new: value_new, newFromAssets: value_newFromAssets, newWithAssets: value_newWithAssets, zero: value_zero, isZero: value_isZero, coin: value_coin, setCoin: value_setCoin, multiasset: value_multiasset, setMultiasset: value_setMultiasset, checkedAdd: value_checkedAdd, checkedSub: value_checkedSub, clampedSub: value_clampedSub, compare: value_compare }

-------------------------------------------------------------------------------------
-- vkey

foreign import vkey_free :: Vkey -> Effect Unit
foreign import vkey_toBytes :: Vkey -> Bytes
foreign import vkey_fromBytes :: Bytes -> Vkey
foreign import vkey_toHex :: Vkey -> String
foreign import vkey_fromHex :: String -> Vkey
foreign import vkey_toJson :: Vkey -> String
foreign import vkey_toJsValue :: Vkey -> VkeyJs
foreign import vkey_fromJson :: String -> Vkey
foreign import vkey_new :: PublicKey -> Vkey
foreign import vkey_publicKey :: Vkey -> PublicKey

type VkeyClass = { free :: Vkey -> Effect Unit, toBytes :: Vkey -> Bytes, fromBytes :: Bytes -> Vkey, toHex :: Vkey -> String, fromHex :: String -> Vkey, toJson :: Vkey -> String, toJsValue :: Vkey -> VkeyJs, fromJson :: String -> Vkey, new :: PublicKey -> Vkey, publicKey :: Vkey -> PublicKey }

vkey :: VkeyClass
vkey = { free: vkey_free, toBytes: vkey_toBytes, fromBytes: vkey_fromBytes, toHex: vkey_toHex, fromHex: vkey_fromHex, toJson: vkey_toJson, toJsValue: vkey_toJsValue, fromJson: vkey_fromJson, new: vkey_new, publicKey: vkey_publicKey }

-------------------------------------------------------------------------------------
-- vkeys

foreign import vkeys_free :: Vkeys -> Effect Unit
foreign import vkeys_new :: Vkeys
foreign import vkeys_len :: Vkeys -> Number
foreign import vkeys_get :: Vkeys -> Number -> Vkey
foreign import vkeys_add :: Vkeys -> Vkey -> Effect Unit

type VkeysClass = { free :: Vkeys -> Effect Unit, new :: Vkeys, len :: Vkeys -> Number, get :: Vkeys -> Number -> Vkey, add :: Vkeys -> Vkey -> Effect Unit }

vkeys :: VkeysClass
vkeys = { free: vkeys_free, new: vkeys_new, len: vkeys_len, get: vkeys_get, add: vkeys_add }

-------------------------------------------------------------------------------------
-- vkeywitness

foreign import vkeywitness_free :: Vkeywitness -> Effect Unit
foreign import vkeywitness_toBytes :: Vkeywitness -> Bytes
foreign import vkeywitness_fromBytes :: Bytes -> Vkeywitness
foreign import vkeywitness_toHex :: Vkeywitness -> String
foreign import vkeywitness_fromHex :: String -> Vkeywitness
foreign import vkeywitness_toJson :: Vkeywitness -> String
foreign import vkeywitness_toJsValue :: Vkeywitness -> VkeywitnessJs
foreign import vkeywitness_fromJson :: String -> Vkeywitness
foreign import vkeywitness_new :: Vkey -> Ed25519Signature -> Vkeywitness
foreign import vkeywitness_vkey :: Vkeywitness -> Vkey
foreign import vkeywitness_signature :: Vkeywitness -> Ed25519Signature

type VkeywitnessClass = { free :: Vkeywitness -> Effect Unit, toBytes :: Vkeywitness -> Bytes, fromBytes :: Bytes -> Vkeywitness, toHex :: Vkeywitness -> String, fromHex :: String -> Vkeywitness, toJson :: Vkeywitness -> String, toJsValue :: Vkeywitness -> VkeywitnessJs, fromJson :: String -> Vkeywitness, new :: Vkey -> Ed25519Signature -> Vkeywitness, vkey :: Vkeywitness -> Vkey, signature :: Vkeywitness -> Ed25519Signature }

vkeywitness :: VkeywitnessClass
vkeywitness = { free: vkeywitness_free, toBytes: vkeywitness_toBytes, fromBytes: vkeywitness_fromBytes, toHex: vkeywitness_toHex, fromHex: vkeywitness_fromHex, toJson: vkeywitness_toJson, toJsValue: vkeywitness_toJsValue, fromJson: vkeywitness_fromJson, new: vkeywitness_new, vkey: vkeywitness_vkey, signature: vkeywitness_signature }

-------------------------------------------------------------------------------------
-- vkeywitnesses

foreign import vkeywitnesses_free :: Vkeywitnesses -> Effect Unit
foreign import vkeywitnesses_new :: Vkeywitnesses
foreign import vkeywitnesses_len :: Vkeywitnesses -> Number
foreign import vkeywitnesses_get :: Vkeywitnesses -> Number -> Vkeywitness
foreign import vkeywitnesses_add :: Vkeywitnesses -> Vkeywitness -> Effect Unit

type VkeywitnessesClass = { free :: Vkeywitnesses -> Effect Unit, new :: Vkeywitnesses, len :: Vkeywitnesses -> Number, get :: Vkeywitnesses -> Number -> Vkeywitness, add :: Vkeywitnesses -> Vkeywitness -> Effect Unit }

vkeywitnesses :: VkeywitnessesClass
vkeywitnesses = { free: vkeywitnesses_free, new: vkeywitnesses_new, len: vkeywitnesses_len, get: vkeywitnesses_get, add: vkeywitnesses_add }

-------------------------------------------------------------------------------------
-- withdrawals

foreign import withdrawals_free :: Withdrawals -> Effect Unit
foreign import withdrawals_toBytes :: Withdrawals -> Bytes
foreign import withdrawals_fromBytes :: Bytes -> Withdrawals
foreign import withdrawals_toHex :: Withdrawals -> String
foreign import withdrawals_fromHex :: String -> Withdrawals
foreign import withdrawals_toJson :: Withdrawals -> String
foreign import withdrawals_toJsValue :: Withdrawals -> WithdrawalsJs
foreign import withdrawals_fromJson :: String -> Withdrawals
foreign import withdrawals_new :: Withdrawals
foreign import withdrawals_len :: Withdrawals -> Number
foreign import withdrawals_insert :: Withdrawals -> RewardAddress -> BigNum -> Maybe BigNum
foreign import withdrawals_get :: Withdrawals -> RewardAddress -> Maybe BigNum
foreign import withdrawals_keys :: Withdrawals -> RewardAddresses

type WithdrawalsClass = { free :: Withdrawals -> Effect Unit, toBytes :: Withdrawals -> Bytes, fromBytes :: Bytes -> Withdrawals, toHex :: Withdrawals -> String, fromHex :: String -> Withdrawals, toJson :: Withdrawals -> String, toJsValue :: Withdrawals -> WithdrawalsJs, fromJson :: String -> Withdrawals, new :: Withdrawals, len :: Withdrawals -> Number, insert :: Withdrawals -> RewardAddress -> BigNum -> Maybe BigNum, get :: Withdrawals -> RewardAddress -> Maybe BigNum, keys :: Withdrawals -> RewardAddresses }

withdrawals :: WithdrawalsClass
withdrawals = { free: withdrawals_free, toBytes: withdrawals_toBytes, fromBytes: withdrawals_fromBytes, toHex: withdrawals_toHex, fromHex: withdrawals_fromHex, toJson: withdrawals_toJson, toJsValue: withdrawals_toJsValue, fromJson: withdrawals_fromJson, new: withdrawals_new, len: withdrawals_len, insert: withdrawals_insert, get: withdrawals_get, keys: withdrawals_keys }


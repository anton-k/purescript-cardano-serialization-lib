-- | Common CSL types and functions that can be work as if they are pure
--
-- Missing parts
--  * generate JSON types and convertions
--  * Handle Maybes / Nullables
--  * explicit export list to hide raw FFI funs
module Csl
  ( Bytes
  , class IsHex, toHex, fromHex
  , class IsBech32, toBech32, fromBech32
  , class IsJson, toJson, fromJson
  , class IsStr, toStr, fromStr
  , class IsBytes, toBytes, fromBytes
  , class ToJsValue, toJsValue
  , class HasFree, free
  , class MutableLen, getLen
  , class MutableList, getItem, addItem, emptyList
  , toMutableList
  , minFee
  , calculateExUnitsCeilCost
  , minScriptFee
  , encryptWithPassword
  , decryptWithPassword
  , makeDaedalusBootstrapWitness
  , makeIcarusBootstrapWitness
  , makeVkeyWitness
  , hashAuxiliaryData
  , hashTx
  , hashPlutusData
  , hashScriptData
  , getImplicitIn
  , getDeposit
  , minAdaForOut
  , minAdaRequired
  , encodeJsonStrToNativeScript
  , encodeJsonStrToPlutusDatum
  , decodePlutusDatumToJsonStr
  , encodeArbitraryBytesAsMetadatum
  , decodeArbitraryBytesFromMetadatum
  , encodeJsonStrToMetadatum
  , decodeMetadatumToJsonStr
  , int
  , IntClass
  , Address
  , AddressClass
  , address
  , AddressJson
  , AssetName
  , AssetNameClass
  , assetName
  , AssetNameJson
  , AssetNames
  , AssetNamesClass
  , assetNames
  , AssetNamesJson
  , Assets
  , AssetsClass
  , assets
  , AssetsJson
  , AuxiliaryData
  , AuxiliaryDataClass
  , auxiliaryData
  , AuxiliaryDataHash
  , AuxiliaryDataHashClass
  , auxiliaryDataHash
  , AuxiliaryDataJson
  , AuxiliaryDataSet
  , AuxiliaryDataSetClass
  , auxiliaryDataSet
  , BaseAddress
  , BaseAddressClass
  , baseAddress
  , BigInt
  , BigIntClass
  , bigInt
  , BigIntJson
  , BigNum
  , BigNumClass
  , bigNum
  , BigNumJson
  , Bip32PrivateKey
  , Bip32PrivateKeyClass
  , bip32PrivateKey
  , Bip32PublicKey
  , Bip32PublicKeyClass
  , bip32PublicKey
  , Block
  , BlockClass
  , block
  , BlockHash
  , BlockHashClass
  , blockHash
  , BlockJson
  , BootstrapWitness
  , BootstrapWitnessClass
  , bootstrapWitness
  , BootstrapWitnessJson
  , BootstrapWitnesses
  , BootstrapWitnessesClass
  , bootstrapWitnesses
  , ByronAddress
  , ByronAddressClass
  , byronAddress
  , Certificate
  , CertificateClass
  , certificate
  , CertificateJson
  , Certificates
  , CertificatesClass
  , certificates
  , CertificatesJson
  , ConstrPlutusData
  , ConstrPlutusDataClass
  , constrPlutusData
  , ConstrPlutusDataJson
  , CostModel
  , CostModelClass
  , costModel
  , CostModelJson
  , Costmdls
  , CostmdlsClass
  , costmdls
  , CostmdlsJson
  , DNSRecordAorAAAA
  , DNSRecordAorAAAAClass
  , dnsRecordAorAAAA
  , DNSRecordAorAAAAJson
  , DNSRecordSRV
  , DNSRecordSRVClass
  , dnsRecordSRV
  , DNSRecordSRVJson
  , DataCost
  , DataCostClass
  , dataCost
  , DataHash
  , DataHashClass
  , dataHash
  , DatumSource
  , DatumSourceClass
  , datumSource
  , Ed25519KeyHash
  , Ed25519KeyHashClass
  , ed25519KeyHash
  , Ed25519KeyHashes
  , Ed25519KeyHashesClass
  , ed25519KeyHashes
  , Ed25519KeyHashesJson
  , Ed25519Signature
  , Ed25519SignatureClass
  , ed25519Signature
  , EnterpriseAddress
  , EnterpriseAddressClass
  , enterpriseAddress
  , ExUnitPrices
  , ExUnitPricesClass
  , exUnitPrices
  , ExUnitPricesJson
  , ExUnits
  , ExUnitsClass
  , exUnits
  , ExUnitsJson
  , GeneralTxMetadata
  , GeneralTxMetadataClass
  , generalTxMetadata
  , GeneralTxMetadataJson
  , GenesisDelegateHash
  , GenesisDelegateHashClass
  , genesisDelegateHash
  , GenesisHash
  , GenesisHashClass
  , genesisHash
  , GenesisHashes
  , GenesisHashesClass
  , genesisHashes
  , GenesisHashesJson
  , GenesisKeyDelegation
  , GenesisKeyDelegationClass
  , genesisKeyDelegation
  , GenesisKeyDelegationJson
  , Header
  , HeaderClass
  , header
  , HeaderBody
  , HeaderBodyClass
  , headerBody
  , HeaderBodyJson
  , HeaderJson
  , IntJson
  , Ipv4
  , Ipv4Class
  , ipv4
  , Ipv4Json
  , Ipv6
  , Ipv6Class
  , ipv6
  , Ipv6Json
  , KESSignature
  , KESSignatureClass
  , kesSignature
  , KESVKey
  , KESVKeyClass
  , kesvKey
  , Language
  , LanguageClass
  , language
  , LanguageJson
  , Languages
  , LanguagesClass
  , languages
  , LegacyDaedalusPrivateKey
  , LegacyDaedalusPrivateKeyClass
  , legacyDaedalusPrivateKey
  , LinearFee
  , LinearFeeClass
  , linearFee
  , MIRToStakeCredentials
  , MIRToStakeCredentialsClass
  , mirToStakeCredentials
  , MIRToStakeCredentialsJson
  , MetadataList
  , MetadataListClass
  , metadataList
  , MetadataMap
  , MetadataMapClass
  , metadataMap
  , Mint
  , MintClass
  , mint
  , MintAssets
  , MintAssetsClass
  , mintAssets
  , MintJson
  , MoveInstantaneousReward
  , MoveInstantaneousRewardClass
  , moveInstantaneousReward
  , MoveInstantaneousRewardJson
  , MoveInstantaneousRewardsCert
  , MoveInstantaneousRewardsCertClass
  , moveInstantaneousRewardsCert
  , MoveInstantaneousRewardsCertJson
  , MultiAsset
  , MultiAssetClass
  , multiAsset
  , MultiAssetJson
  , MultiHostName
  , MultiHostNameClass
  , multiHostName
  , MultiHostNameJson
  , NativeScript
  , NativeScriptClass
  , nativeScript
  , NativeScriptJson
  , NativeScripts
  , NativeScriptsClass
  , nativeScripts
  , NetworkId
  , NetworkIdClass
  , networkId
  , NetworkIdJson
  , NetworkInfo
  , NetworkInfoClass
  , networkInfo
  , Nonce
  , NonceClass
  , nonce
  , NonceJson
  , OperationalCert
  , OperationalCertClass
  , operationalCert
  , OperationalCertJson
  , PlutusData
  , PlutusDataClass
  , plutusData
  , PlutusDataJson
  , PlutusList
  , PlutusListClass
  , plutusList
  , PlutusListJson
  , PlutusMap
  , PlutusMapClass
  , plutusMap
  , PlutusMapJson
  , PlutusScript
  , PlutusScriptClass
  , plutusScript
  , PlutusScriptSource
  , PlutusScriptSourceClass
  , plutusScriptSource
  , PlutusScripts
  , PlutusScriptsClass
  , plutusScripts
  , PlutusScriptsJson
  , PlutusWitness
  , PlutusWitnessClass
  , plutusWitness
  , PlutusWitnesses
  , PlutusWitnessesClass
  , plutusWitnesses
  , Pointer
  , PointerClass
  , pointer
  , PointerAddress
  , PointerAddressClass
  , pointerAddress
  , PoolMetadata
  , PoolMetadataClass
  , poolMetadata
  , PoolMetadataHash
  , PoolMetadataHashClass
  , poolMetadataHash
  , PoolMetadataJson
  , PoolParams
  , PoolParamsClass
  , poolParams
  , PoolParamsJson
  , PoolRegistration
  , PoolRegistrationClass
  , poolRegistration
  , PoolRegistrationJson
  , PoolRetirement
  , PoolRetirementClass
  , poolRetirement
  , PoolRetirementJson
  , PrivateKey
  , PrivateKeyClass
  , privateKey
  , ProposedProtocolParameterUpdates
  , ProposedProtocolParameterUpdatesClass
  , proposedProtocolParameterUpdates
  , ProposedProtocolParameterUpdatesJson
  , ProtocolParamUpdate
  , ProtocolParamUpdateClass
  , protocolParamUpdate
  , ProtocolParamUpdateJson
  , ProtocolVersion
  , ProtocolVersionClass
  , protocolVersion
  , ProtocolVersionJson
  , PublicKey
  , PublicKeyClass
  , publicKey
  , PublicKeys
  , PublicKeysClass
  , publicKeys
  , Redeemer
  , RedeemerClass
  , redeemer
  , RedeemerJson
  , RedeemerTag
  , RedeemerTagClass
  , redeemerTag
  , RedeemerTagJson
  , Redeemers
  , RedeemersClass
  , redeemers
  , RedeemersJson
  , Relay
  , RelayClass
  , relay
  , RelayJson
  , Relays
  , RelaysClass
  , relays
  , RelaysJson
  , RewardAddress
  , RewardAddressClass
  , rewardAddress
  , RewardAddresses
  , RewardAddressesClass
  , rewardAddresses
  , RewardAddressesJson
  , ScriptAll
  , ScriptAllClass
  , scriptAll
  , ScriptAllJson
  , ScriptAny
  , ScriptAnyClass
  , scriptAny
  , ScriptAnyJson
  , ScriptDataHash
  , ScriptDataHashClass
  , scriptDataHash
  , ScriptHash
  , ScriptHashClass
  , scriptHash
  , ScriptHashes
  , ScriptHashesClass
  , scriptHashes
  , ScriptHashesJson
  , ScriptNOfK
  , ScriptNOfKClass
  , scriptNOfK
  , ScriptNOfKJson
  , ScriptPubkey
  , ScriptPubkeyClass
  , scriptPubkey
  , ScriptPubkeyJson
  , ScriptRef
  , ScriptRefClass
  , scriptRef
  , ScriptRefJson
  , SingleHostAddr
  , SingleHostAddrClass
  , singleHostAddr
  , SingleHostAddrJson
  , SingleHostName
  , SingleHostNameClass
  , singleHostName
  , SingleHostNameJson
  , StakeCredential
  , StakeCredentialClass
  , stakeCredential
  , StakeCredentialJson
  , StakeCredentials
  , StakeCredentialsClass
  , stakeCredentials
  , StakeCredentialsJson
  , StakeDelegation
  , StakeDelegationClass
  , stakeDelegation
  , StakeDelegationJson
  , StakeDeregistration
  , StakeDeregistrationClass
  , stakeDeregistration
  , StakeDeregistrationJson
  , StakeRegistration
  , StakeRegistrationClass
  , stakeRegistration
  , StakeRegistrationJson
  , Strings
  , StringsClass
  , strings
  , TimelockExpiry
  , TimelockExpiryClass
  , timelockExpiry
  , TimelockExpiryJson
  , TimelockStart
  , TimelockStartClass
  , timelockStart
  , TimelockStartJson
  , Tx
  , TxClass
  , tx
  , TxBodies
  , TxBodiesClass
  , txBodies
  , TxBodiesJson
  , TxBody
  , TxBodyClass
  , txBody
  , TxBodyJson
  , TxBuilder
  , TxBuilderClass
  , txBuilder
  , TxBuilderConfig
  , TxBuilderConfigClass
  , txBuilderConfig
  , TxBuilderConfigBuilder
  , TxBuilderConfigBuilderClass
  , txBuilderConfigBuilder
  , TxHash
  , TxHashClass
  , txHash
  , TxIn
  , TxInClass
  , txIn
  , TxInJson
  , TxIns
  , TxInsClass
  , txIns
  , TxInsJson
  , TxJson
  , TxMetadatum
  , TxMetadatumClass
  , txMetadatum
  , TxMetadatumLabels
  , TxMetadatumLabelsClass
  , txMetadatumLabels
  , TxOut
  , TxOutClass
  , txOut
  , TxOutAmountBuilder
  , TxOutAmountBuilderClass
  , txOutAmountBuilder
  , TxOutBuilder
  , TxOutBuilderClass
  , txOutBuilder
  , TxOutJson
  , TxOuts
  , TxOutsClass
  , txOuts
  , TxOutsJson
  , TxUnspentOut
  , TxUnspentOutClass
  , txUnspentOut
  , TxUnspentOutJson
  , TxUnspentOuts
  , TxUnspentOutsClass
  , txUnspentOuts
  , TxUnspentOutsJson
  , TxWitnessSet
  , TxWitnessSetClass
  , txWitnessSet
  , TxWitnessSetJson
  , TxWitnessSets
  , TxWitnessSetsClass
  , txWitnessSets
  , TxWitnessSetsJson
  , TxBuilderConstants
  , TxBuilderConstantsClass
  , txBuilderConstants
  , TxInsBuilder
  , TxInsBuilderClass
  , txInsBuilder
  , URL
  , URLClass
  , url
  , URLJson
  , Uint32Array
  , UnitInterval
  , UnitIntervalClass
  , unitInterval
  , UnitIntervalJson
  , Update
  , UpdateClass
  , update
  , UpdateJson
  , VRFCert
  , VRFCertClass
  , vrfCert
  , VRFCertJson
  , VRFKeyHash
  , VRFKeyHashClass
  , vrfKeyHash
  , VRFVKey
  , VRFVKeyClass
  , vrfvKey
  , Value
  , ValueClass
  , value
  , ValueJson
  , Vkey
  , VkeyClass
  , vkey
  , VkeyJson
  , Vkeys
  , VkeysClass
  , vkeys
  , Vkeywitness
  , VkeywitnessClass
  , vkeywitness
  , VkeywitnessJson
  , Vkeywitnesses
  , VkeywitnessesClass
  , vkeywitnesses
  , Withdrawals
  , WithdrawalsClass
  , withdrawals
  , WithdrawalsJson
  , This
  ) where

import Prelude
import Data.Foldable (traverse_)
import Data.ArrayBuffer.Types (Uint8Array)
import Effect (Effect)
import Data.Maybe (Maybe(..))
import Data.Argonaut.Core (Json)
import Data.Nullable (Nullable)
import Data.Nullable as Nullable

----------------------------------------------------------------------------
-- utils

type Bytes = Uint8Array

fromCompare :: Int -> Ordering
fromCompare n
  | n < 0 = LT
  | n > 0 = GT
  | otherwise = EQ

----------------------------------------------------------------------------
-- classes

class IsHex a where
  toHex :: a -> String
  fromHex :: String -> a

class IsStr a where
  toStr :: a -> String
  fromStr :: String -> a

class IsBech32 a where
  toBech32 :: a -> String
  fromBech32 :: String -> a

class IsJson a where
  toJson :: a -> String
  fromJson :: String -> a

class ToJsValue a where
  toJsValue :: a -> Json

class IsBytes a where
  toBytes :: a -> Bytes
  fromBytes :: Bytes -> a

class HasFree a where
  free :: a -> Effect Unit

class MutableLen list where
    getLen :: list -> Effect Int

class MutableList list elem | list -> elem where
  emptyList :: Effect list
  addItem :: list -> elem -> Effect Unit
  getItem :: list -> Int -> Effect elem

toMutableList
  :: forall (list :: Type) (a :: Type)
   . MutableList list a
  => Array a -> Effect list
toMutableList as = do
  res <- emptyList
  traverse_ (addItem res) as
  pure res

----------------------------------------------------------------------------
-- custom instances

-- BigNum

instance Semiring BigNum where
  add = bigNum.checkedAdd
  mul = bigNum.checkedMul
  one = bigNum.one
  zero = bigNum.zero

instance Ring BigNum where
  sub = bigNum.checkedSub

instance CommutativeRing BigNum

instance Eq BigNum where
  eq a b = bigNum.compare a b == 0

instance Ord BigNum where
  compare a b = fromCompare (bigNum.compare a b)

-- BigInt

instance Semiring BigInt where
  add = bigInt.add
  mul = bigInt.mul
  one = bigInt.one
  zero = bigInt.fromHex "zero undefined"

-- Value

instance Monoid Value where
  mempty = value.zero

instance Semigroup Value where
  append = value.checkedAdd

instance Eq Value where
  eq a b = value.compare a b == Just 0

----------------------------------------------------------------------------
-- functions

-- | Min fee
-- > minFee tx linearFee
foreign import minFee :: Tx -> LinearFee -> BigNum

-- | Calculate ex units ceil cost
-- > calculateExUnitsCeilCost exUnits exUnitPrices
foreign import calculateExUnitsCeilCost :: ExUnits -> ExUnitPrices -> BigNum

-- | Min script fee
-- > minScriptFee tx exUnitPrices
foreign import minScriptFee :: Tx -> ExUnitPrices -> BigNum

-- | Encrypt with password
-- > encryptWithPassword password salt nonce data
foreign import encryptWithPassword :: String -> String -> String -> String -> String

-- | Decrypt with password
-- > decryptWithPassword password data
foreign import decryptWithPassword :: String -> String -> String

-- | Make daedalus bootstrap witness
-- > makeDaedalusBootstrapWitness txBodyHash addr key
foreign import makeDaedalusBootstrapWitness :: TxHash -> ByronAddress -> LegacyDaedalusPrivateKey -> BootstrapWitness

-- | Make icarus bootstrap witness
-- > makeIcarusBootstrapWitness txBodyHash addr key
foreign import makeIcarusBootstrapWitness :: TxHash -> ByronAddress -> Bip32PrivateKey -> BootstrapWitness

-- | Make vkey witness
-- > makeVkeyWitness txBodyHash sk
foreign import makeVkeyWitness :: TxHash -> PrivateKey -> Vkeywitness

-- | Hash auxiliary data
-- > hashAuxiliaryData auxiliaryData
foreign import hashAuxiliaryData :: AuxiliaryData -> AuxiliaryDataHash

-- | Hash transaction
-- > hashTx txBody
foreign import hashTx :: TxBody -> TxHash

-- | Hash plutus data
-- > hashPlutusData plutusData
foreign import hashPlutusData :: PlutusData -> DataHash

-- | Hash script data
-- > hashScriptData redeemers costModels datums
foreign import hashScriptData :: Redeemers -> Costmdls -> PlutusList -> ScriptDataHash

-- | Get implicit input
-- > getImplicitIn txbody poolDeposit keyDeposit
foreign import getImplicitIn :: TxBody -> BigNum -> BigNum -> Value

-- | Get deposit
-- > getDeposit txbody poolDeposit keyDeposit
foreign import getDeposit :: TxBody -> BigNum -> BigNum -> BigNum

-- | Min ada for output
-- > minAdaForOut out dataCost
foreign import minAdaForOut :: TxOut -> DataCost -> BigNum

-- | Min ada required
-- > minAdaRequired assets hasDataHash coinsPerUtxoWord
foreign import minAdaRequired :: Value -> Boolean -> BigNum -> BigNum

-- | Encode json str to native script
-- > encodeJsonStrToNativeScript json selfXpub schema
foreign import encodeJsonStrToNativeScript :: String -> String -> Number -> NativeScript

-- | Encode json str to plutus datum
-- > encodeJsonStrToPlutusDatum json schema
foreign import encodeJsonStrToPlutusDatum :: String -> Number -> PlutusData

-- | Decode plutus datum to json str
-- > decodePlutusDatumToJsonStr datum schema
foreign import decodePlutusDatumToJsonStr :: PlutusData -> Number -> String

-- | Encode arbitrary bytes as metadatum
-- > encodeArbitraryBytesAsMetadatum bytes
foreign import encodeArbitraryBytesAsMetadatum :: Bytes -> TxMetadatum

-- | Decode arbitrary bytes from metadatum
-- > decodeArbitraryBytesFromMetadatum metadata
foreign import decodeArbitraryBytesFromMetadatum :: TxMetadatum -> Bytes

-- | Encode json str to metadatum
-- > encodeJsonStrToMetadatum json schema
foreign import encodeJsonStrToMetadatum :: String -> Number -> TxMetadatum

-- | Decode metadatum to json str
-- > decodeMetadatumToJsonStr metadatum schema
foreign import decodeMetadatumToJsonStr :: TxMetadatum -> Number -> String

----------------------------------------------------------------------------
-- types / classes

-- | Address
foreign import data Address :: Type

-- | Address json
type AddressJson = Json

-- | Asset name
foreign import data AssetName :: Type

-- | Asset name json
type AssetNameJson = Json

-- | Asset names
foreign import data AssetNames :: Type

-- | Asset names json
type AssetNamesJson = Json

-- | Assets
foreign import data Assets :: Type

-- | Assets json
type AssetsJson = Json

-- | Auxiliary data
foreign import data AuxiliaryData :: Type

-- | Auxiliary data hash
foreign import data AuxiliaryDataHash :: Type

-- | Auxiliary data json
type AuxiliaryDataJson = Json

-- | Auxiliary data set
foreign import data AuxiliaryDataSet :: Type

-- | Base address
foreign import data BaseAddress :: Type

-- | Big int
foreign import data BigInt :: Type

-- | Big int json
type BigIntJson = Json

-- | Big num
foreign import data BigNum :: Type

-- | Big num json
type BigNumJson = Json

-- | Bip32 private key
foreign import data Bip32PrivateKey :: Type

-- | Bip32 public key
foreign import data Bip32PublicKey :: Type

-- | Block
foreign import data Block :: Type

-- | Block hash
foreign import data BlockHash :: Type

-- | Block json
type BlockJson = Json

-- | Bootstrap witness
foreign import data BootstrapWitness :: Type

-- | Bootstrap witness json
type BootstrapWitnessJson = Json

-- | Bootstrap witnesses
foreign import data BootstrapWitnesses :: Type

-- | Byron address
foreign import data ByronAddress :: Type

-- | Certificate
foreign import data Certificate :: Type

-- | Certificate json
type CertificateJson = Json

-- | Certificates
foreign import data Certificates :: Type

-- | Certificates json
type CertificatesJson = Json

-- | Constr plutus data
foreign import data ConstrPlutusData :: Type

-- | Constr plutus data json
type ConstrPlutusDataJson = Json

-- | Cost model
foreign import data CostModel :: Type

-- | Cost model json
type CostModelJson = Json

-- | Costmdls
foreign import data Costmdls :: Type

-- | Costmdls json
type CostmdlsJson = Json

-- | DNSRecord aor aaaa
foreign import data DNSRecordAorAAAA :: Type

-- | DNSRecord aor aaaaJson
type DNSRecordAorAAAAJson = Json

-- | DNSRecord srv
foreign import data DNSRecordSRV :: Type

-- | DNSRecord srvJson
type DNSRecordSRVJson = Json

-- | Data cost
foreign import data DataCost :: Type

-- | Data hash
foreign import data DataHash :: Type

-- | Datum source
foreign import data DatumSource :: Type

-- | Ed25519 key hash
foreign import data Ed25519KeyHash :: Type

-- | Ed25519 key hashes
foreign import data Ed25519KeyHashes :: Type

-- | Ed25519 key hashes json
type Ed25519KeyHashesJson = Json

-- | Ed25519 signature
foreign import data Ed25519Signature :: Type

-- | Enterprise address
foreign import data EnterpriseAddress :: Type

-- | Ex unit prices
foreign import data ExUnitPrices :: Type

-- | Ex unit prices json
type ExUnitPricesJson = Json

-- | Ex units
foreign import data ExUnits :: Type

-- | Ex units json
type ExUnitsJson = Json

-- | General tx metadata
foreign import data GeneralTxMetadata :: Type

-- | General tx metadata json
type GeneralTxMetadataJson = Json

-- | Genesis delegate hash
foreign import data GenesisDelegateHash :: Type

-- | Genesis hash
foreign import data GenesisHash :: Type

-- | Genesis hashes
foreign import data GenesisHashes :: Type

-- | Genesis hashes json
type GenesisHashesJson = Json

-- | Genesis key delegation
foreign import data GenesisKeyDelegation :: Type

-- | Genesis key delegation json
type GenesisKeyDelegationJson = Json

-- | Header
foreign import data Header :: Type

-- | Header body
foreign import data HeaderBody :: Type

-- | Header body json
type HeaderBodyJson = Json

-- | Header json
type HeaderJson = Json

-- | Int json
type IntJson = Json

-- | Ipv4
foreign import data Ipv4 :: Type

-- | Ipv4 json
type Ipv4Json = Json

-- | Ipv6
foreign import data Ipv6 :: Type

-- | Ipv6 json
type Ipv6Json = Json

-- | KESSignature
foreign import data KESSignature :: Type

-- | KESVKey
foreign import data KESVKey :: Type

-- | Language
foreign import data Language :: Type

-- | Language json
type LanguageJson = Json

-- | Languages
foreign import data Languages :: Type

-- | Legacy daedalus private key
foreign import data LegacyDaedalusPrivateKey :: Type

-- | Linear fee
foreign import data LinearFee :: Type

-- | MIRTo stake credentials
foreign import data MIRToStakeCredentials :: Type

-- | MIRTo stake credentials json
type MIRToStakeCredentialsJson = Json

-- | Metadata list
foreign import data MetadataList :: Type

-- | Metadata map
foreign import data MetadataMap :: Type

-- | Mint
foreign import data Mint :: Type

-- | Mint assets
foreign import data MintAssets :: Type

-- | Mint json
type MintJson = Json

-- | Move instantaneous reward
foreign import data MoveInstantaneousReward :: Type

-- | Move instantaneous reward json
type MoveInstantaneousRewardJson = Json

-- | Move instantaneous rewards cert
foreign import data MoveInstantaneousRewardsCert :: Type

-- | Move instantaneous rewards cert json
type MoveInstantaneousRewardsCertJson = Json

-- | Multi asset
foreign import data MultiAsset :: Type

-- | Multi asset json
type MultiAssetJson = Json

-- | Multi host name
foreign import data MultiHostName :: Type

-- | Multi host name json
type MultiHostNameJson = Json

-- | Native script
foreign import data NativeScript :: Type

-- | Native script json
type NativeScriptJson = Json

-- | Native scripts
foreign import data NativeScripts :: Type

-- | Network id
foreign import data NetworkId :: Type

-- | Network id json
type NetworkIdJson = Json

-- | Network info
foreign import data NetworkInfo :: Type

-- | Nonce
foreign import data Nonce :: Type

-- | Nonce json
type NonceJson = Json

-- | Operational cert
foreign import data OperationalCert :: Type

-- | Operational cert json
type OperationalCertJson = Json

-- | Plutus data
foreign import data PlutusData :: Type

-- | Plutus data json
type PlutusDataJson = Json

-- | Plutus list
foreign import data PlutusList :: Type

-- | Plutus list json
type PlutusListJson = Json

-- | Plutus map
foreign import data PlutusMap :: Type

-- | Plutus map json
type PlutusMapJson = Json

-- | Plutus script
foreign import data PlutusScript :: Type

-- | Plutus script source
foreign import data PlutusScriptSource :: Type

-- | Plutus scripts
foreign import data PlutusScripts :: Type

-- | Plutus scripts json
type PlutusScriptsJson = Json

-- | Plutus witness
foreign import data PlutusWitness :: Type

-- | Plutus witnesses
foreign import data PlutusWitnesses :: Type

-- | Pointer
foreign import data Pointer :: Type

-- | Pointer address
foreign import data PointerAddress :: Type

-- | Pool metadata
foreign import data PoolMetadata :: Type

-- | Pool metadata hash
foreign import data PoolMetadataHash :: Type

-- | Pool metadata json
type PoolMetadataJson = Json

-- | Pool params
foreign import data PoolParams :: Type

-- | Pool params json
type PoolParamsJson = Json

-- | Pool registration
foreign import data PoolRegistration :: Type

-- | Pool registration json
type PoolRegistrationJson = Json

-- | Pool retirement
foreign import data PoolRetirement :: Type

-- | Pool retirement json
type PoolRetirementJson = Json

-- | Private key
foreign import data PrivateKey :: Type

-- | Proposed protocol parameter updates
foreign import data ProposedProtocolParameterUpdates :: Type

-- | Proposed protocol parameter updates json
type ProposedProtocolParameterUpdatesJson = Json

-- | Protocol param update
foreign import data ProtocolParamUpdate :: Type

-- | Protocol param update json
type ProtocolParamUpdateJson = Json

-- | Protocol version
foreign import data ProtocolVersion :: Type

-- | Protocol version json
type ProtocolVersionJson = Json

-- | Public key
foreign import data PublicKey :: Type

-- | Public keys
foreign import data PublicKeys :: Type

-- | Redeemer
foreign import data Redeemer :: Type

-- | Redeemer json
type RedeemerJson = Json

-- | Redeemer tag
foreign import data RedeemerTag :: Type

-- | Redeemer tag json
type RedeemerTagJson = Json

-- | Redeemers
foreign import data Redeemers :: Type

-- | Redeemers json
type RedeemersJson = Json

-- | Relay
foreign import data Relay :: Type

-- | Relay json
type RelayJson = Json

-- | Relays
foreign import data Relays :: Type

-- | Relays json
type RelaysJson = Json

-- | Reward address
foreign import data RewardAddress :: Type

-- | Reward addresses
foreign import data RewardAddresses :: Type

-- | Reward addresses json
type RewardAddressesJson = Json

-- | Script all
foreign import data ScriptAll :: Type

-- | Script all json
type ScriptAllJson = Json

-- | Script any
foreign import data ScriptAny :: Type

-- | Script any json
type ScriptAnyJson = Json

-- | Script data hash
foreign import data ScriptDataHash :: Type

-- | Script hash
foreign import data ScriptHash :: Type

-- | Script hashes
foreign import data ScriptHashes :: Type

-- | Script hashes json
type ScriptHashesJson = Json

-- | Script nOf k
foreign import data ScriptNOfK :: Type

-- | Script nOf kJson
type ScriptNOfKJson = Json

-- | Script pubkey
foreign import data ScriptPubkey :: Type

-- | Script pubkey json
type ScriptPubkeyJson = Json

-- | Script ref
foreign import data ScriptRef :: Type

-- | Script ref json
type ScriptRefJson = Json

-- | Single host addr
foreign import data SingleHostAddr :: Type

-- | Single host addr json
type SingleHostAddrJson = Json

-- | Single host name
foreign import data SingleHostName :: Type

-- | Single host name json
type SingleHostNameJson = Json

-- | Stake credential
foreign import data StakeCredential :: Type

-- | Stake credential json
type StakeCredentialJson = Json

-- | Stake credentials
foreign import data StakeCredentials :: Type

-- | Stake credentials json
type StakeCredentialsJson = Json

-- | Stake delegation
foreign import data StakeDelegation :: Type

-- | Stake delegation json
type StakeDelegationJson = Json

-- | Stake deregistration
foreign import data StakeDeregistration :: Type

-- | Stake deregistration json
type StakeDeregistrationJson = Json

-- | Stake registration
foreign import data StakeRegistration :: Type

-- | Stake registration json
type StakeRegistrationJson = Json

-- | Strings
foreign import data Strings :: Type

-- | Timelock expiry
foreign import data TimelockExpiry :: Type

-- | Timelock expiry json
type TimelockExpiryJson = Json

-- | Timelock start
foreign import data TimelockStart :: Type

-- | Timelock start json
type TimelockStartJson = Json

-- | Tx
foreign import data Tx :: Type

-- | Tx bodies
foreign import data TxBodies :: Type

-- | Tx bodies json
type TxBodiesJson = Json

-- | Tx body
foreign import data TxBody :: Type

-- | Tx body json
type TxBodyJson = Json

-- | Tx builder
foreign import data TxBuilder :: Type

-- | Tx builder config
foreign import data TxBuilderConfig :: Type

-- | Tx builder config builder
foreign import data TxBuilderConfigBuilder :: Type

-- | Tx hash
foreign import data TxHash :: Type

-- | Tx in
foreign import data TxIn :: Type

-- | Tx in json
type TxInJson = Json

-- | Tx ins
foreign import data TxIns :: Type

-- | Tx ins json
type TxInsJson = Json

-- | Tx json
type TxJson = Json

-- | Tx metadatum
foreign import data TxMetadatum :: Type

-- | Tx metadatum labels
foreign import data TxMetadatumLabels :: Type

-- | Tx out
foreign import data TxOut :: Type

-- | Tx out amount builder
foreign import data TxOutAmountBuilder :: Type

-- | Tx out builder
foreign import data TxOutBuilder :: Type

-- | Tx out json
type TxOutJson = Json

-- | Tx outs
foreign import data TxOuts :: Type

-- | Tx outs json
type TxOutsJson = Json

-- | Tx unspent out
foreign import data TxUnspentOut :: Type

-- | Tx unspent out json
type TxUnspentOutJson = Json

-- | Tx unspent outs
foreign import data TxUnspentOuts :: Type

-- | Tx unspent outs json
type TxUnspentOutsJson = Json

-- | Tx witness set
foreign import data TxWitnessSet :: Type

-- | Tx witness set json
type TxWitnessSetJson = Json

-- | Tx witness sets
foreign import data TxWitnessSets :: Type

-- | Tx witness sets json
type TxWitnessSetsJson = Json

-- | Tx builder constants
foreign import data TxBuilderConstants :: Type

-- | Tx ins builder
foreign import data TxInsBuilder :: Type

-- | URL
foreign import data URL :: Type

-- | URLJson
type URLJson = Json

-- | Uint32 array
foreign import data Uint32Array :: Type

-- | Unit interval
foreign import data UnitInterval :: Type

-- | Unit interval json
type UnitIntervalJson = Json

-- | Update
foreign import data Update :: Type

-- | Update json
type UpdateJson = Json

-- | VRFCert
foreign import data VRFCert :: Type

-- | VRFCert json
type VRFCertJson = Json

-- | VRFKey hash
foreign import data VRFKeyHash :: Type

-- | VRFVKey
foreign import data VRFVKey :: Type

-- | Value
foreign import data Value :: Type

-- | Value json
type ValueJson = Json

-- | Vkey
foreign import data Vkey :: Type

-- | Vkey json
type VkeyJson = Json

-- | Vkeys
foreign import data Vkeys :: Type

-- | Vkeywitness
foreign import data Vkeywitness :: Type

-- | Vkeywitness json
type VkeywitnessJson = Json

-- | Vkeywitnesses
foreign import data Vkeywitnesses :: Type

-- | Withdrawals
foreign import data Withdrawals :: Type

-- | Withdrawals json
type WithdrawalsJson = Json

-- | This
foreign import data This :: Type

-------------------------------------------------------------------------------------
-- Address

foreign import address_free :: Address -> Effect Unit
foreign import address_fromBytes :: Bytes -> Address
foreign import address_toJson :: Address -> String
foreign import address_toJsValue :: Address -> AddressJson
foreign import address_fromJson :: String -> Address
foreign import address_toHex :: Address -> String
foreign import address_fromHex :: String -> Address
foreign import address_toBytes :: Address -> Bytes
foreign import address_toBech32 :: Address -> String -> String
foreign import address_fromBech32 :: String -> Address
foreign import address_networkId :: Address -> Int

-- | Address class
type AddressClass =
  { free :: Address -> Effect Unit
    -- ^ Free
    -- > free self
  , fromBytes :: Bytes -> Address
    -- ^ From bytes
    -- > fromBytes data
  , toJson :: Address -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Address -> AddressJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Address
    -- ^ From json
    -- > fromJson json
  , toHex :: Address -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Address
    -- ^ From hex
    -- > fromHex hexStr
  , toBytes :: Address -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , toBech32 :: Address -> String -> String
    -- ^ To bech32
    -- > toBech32 self prefix
  , fromBech32 :: String -> Address
    -- ^ From bech32
    -- > fromBech32 bechStr
  , networkId :: Address -> Int
    -- ^ Network id
    -- > networkId self
  }

-- | Address class API
address :: AddressClass
address =
  { free: address_free
  , fromBytes: address_fromBytes
  , toJson: address_toJson
  , toJsValue: address_toJsValue
  , fromJson: address_fromJson
  , toHex: address_toHex
  , fromHex: address_fromHex
  , toBytes: address_toBytes
  , toBech32: address_toBech32
  , fromBech32: address_fromBech32
  , networkId: address_networkId
  }

instance HasFree Address where
  free = address.free

instance Show Address where
  show = address.toHex

instance ToJsValue Address where
  toJsValue = address.toJsValue

instance IsHex Address where
  toHex = address.toHex
  fromHex = address.fromHex

instance IsBytes Address where
  toBytes = address.toBytes
  fromBytes = address.fromBytes

instance IsJson Address where
  toJson = address.toJson
  fromJson = address.fromJson

-------------------------------------------------------------------------------------
-- Asset name

foreign import assetName_free :: AssetName -> Effect Unit
foreign import assetName_toBytes :: AssetName -> Bytes
foreign import assetName_fromBytes :: Bytes -> AssetName
foreign import assetName_toHex :: AssetName -> String
foreign import assetName_fromHex :: String -> AssetName
foreign import assetName_toJson :: AssetName -> String
foreign import assetName_toJsValue :: AssetName -> AssetNameJson
foreign import assetName_fromJson :: String -> AssetName
foreign import assetName_new :: Bytes -> AssetName
foreign import assetName_name :: AssetName -> Bytes

-- | Asset name class
type AssetNameClass =
  { free :: AssetName -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: AssetName -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> AssetName
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: AssetName -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> AssetName
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: AssetName -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: AssetName -> AssetNameJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> AssetName
    -- ^ From json
    -- > fromJson json
  , new :: Bytes -> AssetName
    -- ^ New
    -- > new name
  , name :: AssetName -> Bytes
    -- ^ Name
    -- > name self
  }

-- | Asset name class API
assetName :: AssetNameClass
assetName =
  { free: assetName_free
  , toBytes: assetName_toBytes
  , fromBytes: assetName_fromBytes
  , toHex: assetName_toHex
  , fromHex: assetName_fromHex
  , toJson: assetName_toJson
  , toJsValue: assetName_toJsValue
  , fromJson: assetName_fromJson
  , new: assetName_new
  , name: assetName_name
  }

instance HasFree AssetName where
  free = assetName.free

instance Show AssetName where
  show = assetName.toHex

instance ToJsValue AssetName where
  toJsValue = assetName.toJsValue

instance IsHex AssetName where
  toHex = assetName.toHex
  fromHex = assetName.fromHex

instance IsBytes AssetName where
  toBytes = assetName.toBytes
  fromBytes = assetName.fromBytes

instance IsJson AssetName where
  toJson = assetName.toJson
  fromJson = assetName.fromJson

-------------------------------------------------------------------------------------
-- Asset names

foreign import assetNames_free :: AssetNames -> Effect Unit
foreign import assetNames_toBytes :: AssetNames -> Bytes
foreign import assetNames_fromBytes :: Bytes -> AssetNames
foreign import assetNames_toHex :: AssetNames -> String
foreign import assetNames_fromHex :: String -> AssetNames
foreign import assetNames_toJson :: AssetNames -> String
foreign import assetNames_toJsValue :: AssetNames -> AssetNamesJson
foreign import assetNames_fromJson :: String -> AssetNames
foreign import assetNames_new :: Effect AssetNames
foreign import assetNames_len :: AssetNames -> Effect Int
foreign import assetNames_get :: AssetNames -> Int -> Effect AssetName
foreign import assetNames_add :: AssetNames -> AssetName -> Effect Unit

-- | Asset names class
type AssetNamesClass =
  { free :: AssetNames -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: AssetNames -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> AssetNames
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: AssetNames -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> AssetNames
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: AssetNames -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: AssetNames -> AssetNamesJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> AssetNames
    -- ^ From json
    -- > fromJson json
  , new :: Effect AssetNames
    -- ^ New
    -- > new
  , len :: AssetNames -> Effect Int
    -- ^ Len
    -- > len self
  , get :: AssetNames -> Int -> Effect AssetName
    -- ^ Get
    -- > get self index
  , add :: AssetNames -> AssetName -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Asset names class API
assetNames :: AssetNamesClass
assetNames =
  { free: assetNames_free
  , toBytes: assetNames_toBytes
  , fromBytes: assetNames_fromBytes
  , toHex: assetNames_toHex
  , fromHex: assetNames_fromHex
  , toJson: assetNames_toJson
  , toJsValue: assetNames_toJsValue
  , fromJson: assetNames_fromJson
  , new: assetNames_new
  , len: assetNames_len
  , get: assetNames_get
  , add: assetNames_add
  }

instance HasFree AssetNames where
  free = assetNames.free

instance Show AssetNames where
  show = assetNames.toHex

instance MutableList AssetNames AssetName where
  addItem = assetNames.add
  getItem = assetNames.get
  emptyList = assetNames.new

instance MutableLen AssetNames where
  getLen = assetNames.len


instance ToJsValue AssetNames where
  toJsValue = assetNames.toJsValue

instance IsHex AssetNames where
  toHex = assetNames.toHex
  fromHex = assetNames.fromHex

instance IsBytes AssetNames where
  toBytes = assetNames.toBytes
  fromBytes = assetNames.fromBytes

instance IsJson AssetNames where
  toJson = assetNames.toJson
  fromJson = assetNames.fromJson

-------------------------------------------------------------------------------------
-- Assets

foreign import assets_free :: Assets -> Effect Unit
foreign import assets_toBytes :: Assets -> Bytes
foreign import assets_fromBytes :: Bytes -> Assets
foreign import assets_toHex :: Assets -> String
foreign import assets_fromHex :: String -> Assets
foreign import assets_toJson :: Assets -> String
foreign import assets_toJsValue :: Assets -> AssetsJson
foreign import assets_fromJson :: String -> Assets
foreign import assets_new :: Effect Assets
foreign import assets_len :: Assets -> Effect Int
foreign import assets_insert :: Assets -> AssetName -> BigNum -> Effect (Nullable BigNum)
foreign import assets_get :: Assets -> AssetName -> Effect (Nullable BigNum)
foreign import assets_keys :: Assets -> Effect AssetNames

-- | Assets class
type AssetsClass =
  { free :: Assets -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Assets -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Assets
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Assets -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Assets
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Assets -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Assets -> AssetsJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Assets
    -- ^ From json
    -- > fromJson json
  , new :: Effect Assets
    -- ^ New
    -- > new
  , len :: Assets -> Effect Int
    -- ^ Len
    -- > len self
  , insert :: Assets -> AssetName -> BigNum -> Effect (Maybe BigNum)
    -- ^ Insert
    -- > insert self key value
  , get :: Assets -> AssetName -> Effect (Maybe BigNum)
    -- ^ Get
    -- > get self key
  , keys :: Assets -> Effect AssetNames
    -- ^ Keys
    -- > keys self
  }

-- | Assets class API
assets :: AssetsClass
assets =
  { free: assets_free
  , toBytes: assets_toBytes
  , fromBytes: assets_fromBytes
  , toHex: assets_toHex
  , fromHex: assets_fromHex
  , toJson: assets_toJson
  , toJsValue: assets_toJsValue
  , fromJson: assets_fromJson
  , new: assets_new
  , len: assets_len
  , insert: \a1 a2 a3 -> Nullable.toMaybe <$> assets_insert a1 a2 a3
  , get: \a1 a2 -> Nullable.toMaybe <$> assets_get a1 a2
  , keys: assets_keys
  }

instance HasFree Assets where
  free = assets.free

instance Show Assets where
  show = assets.toHex

instance ToJsValue Assets where
  toJsValue = assets.toJsValue

instance IsHex Assets where
  toHex = assets.toHex
  fromHex = assets.fromHex

instance IsBytes Assets where
  toBytes = assets.toBytes
  fromBytes = assets.fromBytes

instance IsJson Assets where
  toJson = assets.toJson
  fromJson = assets.fromJson

-------------------------------------------------------------------------------------
-- Auxiliary data

foreign import auxiliaryData_free :: AuxiliaryData -> Effect Unit
foreign import auxiliaryData_toBytes :: AuxiliaryData -> Bytes
foreign import auxiliaryData_fromBytes :: Bytes -> AuxiliaryData
foreign import auxiliaryData_toHex :: AuxiliaryData -> String
foreign import auxiliaryData_fromHex :: String -> AuxiliaryData
foreign import auxiliaryData_toJson :: AuxiliaryData -> String
foreign import auxiliaryData_toJsValue :: AuxiliaryData -> AuxiliaryDataJson
foreign import auxiliaryData_fromJson :: String -> AuxiliaryData
foreign import auxiliaryData_new :: Effect AuxiliaryData
foreign import auxiliaryData_metadata :: AuxiliaryData -> Nullable GeneralTxMetadata
foreign import auxiliaryData_setMetadata :: AuxiliaryData -> GeneralTxMetadata -> Effect Unit
foreign import auxiliaryData_nativeScripts :: AuxiliaryData -> Effect (Nullable NativeScripts)
foreign import auxiliaryData_setNativeScripts :: AuxiliaryData -> NativeScripts -> Effect Unit
foreign import auxiliaryData_plutusScripts :: AuxiliaryData -> Effect (Nullable PlutusScripts)
foreign import auxiliaryData_setPlutusScripts :: AuxiliaryData -> PlutusScripts -> Effect Unit

-- | Auxiliary data class
type AuxiliaryDataClass =
  { free :: AuxiliaryData -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: AuxiliaryData -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> AuxiliaryData
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: AuxiliaryData -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> AuxiliaryData
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: AuxiliaryData -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: AuxiliaryData -> AuxiliaryDataJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> AuxiliaryData
    -- ^ From json
    -- > fromJson json
  , new :: Effect AuxiliaryData
    -- ^ New
    -- > new
  , metadata :: AuxiliaryData -> Maybe GeneralTxMetadata
    -- ^ Metadata
    -- > metadata self
  , setMetadata :: AuxiliaryData -> GeneralTxMetadata -> Effect Unit
    -- ^ Set metadata
    -- > setMetadata self metadata
  , nativeScripts :: AuxiliaryData -> Effect (Maybe NativeScripts)
    -- ^ Native scripts
    -- > nativeScripts self
  , setNativeScripts :: AuxiliaryData -> NativeScripts -> Effect Unit
    -- ^ Set native scripts
    -- > setNativeScripts self nativeScripts
  , plutusScripts :: AuxiliaryData -> Effect (Maybe PlutusScripts)
    -- ^ Plutus scripts
    -- > plutusScripts self
  , setPlutusScripts :: AuxiliaryData -> PlutusScripts -> Effect Unit
    -- ^ Set plutus scripts
    -- > setPlutusScripts self plutusScripts
  }

-- | Auxiliary data class API
auxiliaryData :: AuxiliaryDataClass
auxiliaryData =
  { free: auxiliaryData_free
  , toBytes: auxiliaryData_toBytes
  , fromBytes: auxiliaryData_fromBytes
  , toHex: auxiliaryData_toHex
  , fromHex: auxiliaryData_fromHex
  , toJson: auxiliaryData_toJson
  , toJsValue: auxiliaryData_toJsValue
  , fromJson: auxiliaryData_fromJson
  , new: auxiliaryData_new
  , metadata: \a1 -> Nullable.toMaybe $ auxiliaryData_metadata a1
  , setMetadata: auxiliaryData_setMetadata
  , nativeScripts: \a1 -> Nullable.toMaybe <$> auxiliaryData_nativeScripts a1
  , setNativeScripts: auxiliaryData_setNativeScripts
  , plutusScripts: \a1 -> Nullable.toMaybe <$> auxiliaryData_plutusScripts a1
  , setPlutusScripts: auxiliaryData_setPlutusScripts
  }

instance HasFree AuxiliaryData where
  free = auxiliaryData.free

instance Show AuxiliaryData where
  show = auxiliaryData.toHex

instance ToJsValue AuxiliaryData where
  toJsValue = auxiliaryData.toJsValue

instance IsHex AuxiliaryData where
  toHex = auxiliaryData.toHex
  fromHex = auxiliaryData.fromHex

instance IsBytes AuxiliaryData where
  toBytes = auxiliaryData.toBytes
  fromBytes = auxiliaryData.fromBytes

instance IsJson AuxiliaryData where
  toJson = auxiliaryData.toJson
  fromJson = auxiliaryData.fromJson

-------------------------------------------------------------------------------------
-- Auxiliary data hash

foreign import auxiliaryDataHash_free :: AuxiliaryDataHash -> Effect Unit
foreign import auxiliaryDataHash_fromBytes :: Bytes -> AuxiliaryDataHash
foreign import auxiliaryDataHash_toBytes :: AuxiliaryDataHash -> Bytes
foreign import auxiliaryDataHash_toBech32 :: AuxiliaryDataHash -> String -> String
foreign import auxiliaryDataHash_fromBech32 :: String -> AuxiliaryDataHash
foreign import auxiliaryDataHash_toHex :: AuxiliaryDataHash -> String
foreign import auxiliaryDataHash_fromHex :: String -> AuxiliaryDataHash

-- | Auxiliary data hash class
type AuxiliaryDataHashClass =
  { free :: AuxiliaryDataHash -> Effect Unit
    -- ^ Free
    -- > free self
  , fromBytes :: Bytes -> AuxiliaryDataHash
    -- ^ From bytes
    -- > fromBytes bytes
  , toBytes :: AuxiliaryDataHash -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , toBech32 :: AuxiliaryDataHash -> String -> String
    -- ^ To bech32
    -- > toBech32 self prefix
  , fromBech32 :: String -> AuxiliaryDataHash
    -- ^ From bech32
    -- > fromBech32 bechStr
  , toHex :: AuxiliaryDataHash -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> AuxiliaryDataHash
    -- ^ From hex
    -- > fromHex hex
  }

-- | Auxiliary data hash class API
auxiliaryDataHash :: AuxiliaryDataHashClass
auxiliaryDataHash =
  { free: auxiliaryDataHash_free
  , fromBytes: auxiliaryDataHash_fromBytes
  , toBytes: auxiliaryDataHash_toBytes
  , toBech32: auxiliaryDataHash_toBech32
  , fromBech32: auxiliaryDataHash_fromBech32
  , toHex: auxiliaryDataHash_toHex
  , fromHex: auxiliaryDataHash_fromHex
  }

instance HasFree AuxiliaryDataHash where
  free = auxiliaryDataHash.free

instance Show AuxiliaryDataHash where
  show = auxiliaryDataHash.toHex

instance IsHex AuxiliaryDataHash where
  toHex = auxiliaryDataHash.toHex
  fromHex = auxiliaryDataHash.fromHex

instance IsBytes AuxiliaryDataHash where
  toBytes = auxiliaryDataHash.toBytes
  fromBytes = auxiliaryDataHash.fromBytes

-------------------------------------------------------------------------------------
-- Auxiliary data set

foreign import auxiliaryDataSet_free :: AuxiliaryDataSet -> Effect Unit
foreign import auxiliaryDataSet_new :: Effect AuxiliaryDataSet
foreign import auxiliaryDataSet_len :: AuxiliaryDataSet -> Int
foreign import auxiliaryDataSet_insert :: AuxiliaryDataSet -> Int -> AuxiliaryData -> Effect (Nullable AuxiliaryData)
foreign import auxiliaryDataSet_get :: AuxiliaryDataSet -> Int -> Effect (Nullable AuxiliaryData)
foreign import auxiliaryDataSet_indices :: AuxiliaryDataSet -> Effect Uint32Array

-- | Auxiliary data set class
type AuxiliaryDataSetClass =
  { free :: AuxiliaryDataSet -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: Effect AuxiliaryDataSet
    -- ^ New
    -- > new
  , len :: AuxiliaryDataSet -> Int
    -- ^ Len
    -- > len self
  , insert :: AuxiliaryDataSet -> Int -> AuxiliaryData -> Effect (Maybe AuxiliaryData)
    -- ^ Insert
    -- > insert self txIndex data
  , get :: AuxiliaryDataSet -> Int -> Effect (Maybe AuxiliaryData)
    -- ^ Get
    -- > get self txIndex
  , indices :: AuxiliaryDataSet -> Effect Uint32Array
    -- ^ Indices
    -- > indices self
  }

-- | Auxiliary data set class API
auxiliaryDataSet :: AuxiliaryDataSetClass
auxiliaryDataSet =
  { free: auxiliaryDataSet_free
  , new: auxiliaryDataSet_new
  , len: auxiliaryDataSet_len
  , insert: \a1 a2 a3 -> Nullable.toMaybe <$> auxiliaryDataSet_insert a1 a2 a3
  , get: \a1 a2 -> Nullable.toMaybe <$> auxiliaryDataSet_get a1 a2
  , indices: auxiliaryDataSet_indices
  }

instance HasFree AuxiliaryDataSet where
  free = auxiliaryDataSet.free

-------------------------------------------------------------------------------------
-- Base address

foreign import baseAddress_free :: BaseAddress -> Effect Unit
foreign import baseAddress_new :: Number -> StakeCredential -> StakeCredential -> BaseAddress
foreign import baseAddress_paymentCred :: BaseAddress -> StakeCredential
foreign import baseAddress_stakeCred :: BaseAddress -> StakeCredential
foreign import baseAddress_toAddress :: BaseAddress -> Address
foreign import baseAddress_fromAddress :: Address -> Nullable BaseAddress

-- | Base address class
type BaseAddressClass =
  { free :: BaseAddress -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: Number -> StakeCredential -> StakeCredential -> BaseAddress
    -- ^ New
    -- > new network payment stake
  , paymentCred :: BaseAddress -> StakeCredential
    -- ^ Payment cred
    -- > paymentCred self
  , stakeCred :: BaseAddress -> StakeCredential
    -- ^ Stake cred
    -- > stakeCred self
  , toAddress :: BaseAddress -> Address
    -- ^ To address
    -- > toAddress self
  , fromAddress :: Address -> Maybe BaseAddress
    -- ^ From address
    -- > fromAddress addr
  }

-- | Base address class API
baseAddress :: BaseAddressClass
baseAddress =
  { free: baseAddress_free
  , new: baseAddress_new
  , paymentCred: baseAddress_paymentCred
  , stakeCred: baseAddress_stakeCred
  , toAddress: baseAddress_toAddress
  , fromAddress: \a1 -> Nullable.toMaybe $ baseAddress_fromAddress a1
  }

instance HasFree BaseAddress where
  free = baseAddress.free

-------------------------------------------------------------------------------------
-- Big int

foreign import bigInt_free :: BigInt -> Effect Unit
foreign import bigInt_toBytes :: BigInt -> Bytes
foreign import bigInt_fromBytes :: Bytes -> BigInt
foreign import bigInt_toHex :: BigInt -> String
foreign import bigInt_fromHex :: String -> BigInt
foreign import bigInt_toJson :: BigInt -> String
foreign import bigInt_toJsValue :: BigInt -> BigIntJson
foreign import bigInt_fromJson :: String -> BigInt
foreign import bigInt_isZero :: BigInt -> Boolean
foreign import bigInt_asU64 :: BigInt -> Nullable BigNum
foreign import bigInt_asInt :: BigInt -> Nullable Int
foreign import bigInt_fromStr :: String -> BigInt
foreign import bigInt_toStr :: BigInt -> String
foreign import bigInt_add :: BigInt -> BigInt -> BigInt
foreign import bigInt_mul :: BigInt -> BigInt -> BigInt
foreign import bigInt_one :: BigInt
foreign import bigInt_increment :: BigInt -> BigInt
foreign import bigInt_divCeil :: BigInt -> BigInt -> BigInt

-- | Big int class
type BigIntClass =
  { free :: BigInt -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: BigInt -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> BigInt
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: BigInt -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> BigInt
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: BigInt -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: BigInt -> BigIntJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> BigInt
    -- ^ From json
    -- > fromJson json
  , isZero :: BigInt -> Boolean
    -- ^ Is zero
    -- > isZero self
  , asU64 :: BigInt -> Maybe BigNum
    -- ^ As u64
    -- > asU64 self
  , asInt :: BigInt -> Maybe Int
    -- ^ As int
    -- > asInt self
  , fromStr :: String -> BigInt
    -- ^ From str
    -- > fromStr text
  , toStr :: BigInt -> String
    -- ^ To str
    -- > toStr self
  , add :: BigInt -> BigInt -> BigInt
    -- ^ Add
    -- > add self other
  , mul :: BigInt -> BigInt -> BigInt
    -- ^ Mul
    -- > mul self other
  , one :: BigInt
    -- ^ One
    -- > one
  , increment :: BigInt -> BigInt
    -- ^ Increment
    -- > increment self
  , divCeil :: BigInt -> BigInt -> BigInt
    -- ^ Div ceil
    -- > divCeil self other
  }

-- | Big int class API
bigInt :: BigIntClass
bigInt =
  { free: bigInt_free
  , toBytes: bigInt_toBytes
  , fromBytes: bigInt_fromBytes
  , toHex: bigInt_toHex
  , fromHex: bigInt_fromHex
  , toJson: bigInt_toJson
  , toJsValue: bigInt_toJsValue
  , fromJson: bigInt_fromJson
  , isZero: bigInt_isZero
  , asU64: \a1 -> Nullable.toMaybe $ bigInt_asU64 a1
  , asInt: \a1 -> Nullable.toMaybe $ bigInt_asInt a1
  , fromStr: bigInt_fromStr
  , toStr: bigInt_toStr
  , add: bigInt_add
  , mul: bigInt_mul
  , one: bigInt_one
  , increment: bigInt_increment
  , divCeil: bigInt_divCeil
  }

instance HasFree BigInt where
  free = bigInt.free

instance Show BigInt where
  show = bigInt.toStr

instance ToJsValue BigInt where
  toJsValue = bigInt.toJsValue

instance IsHex BigInt where
  toHex = bigInt.toHex
  fromHex = bigInt.fromHex

instance IsStr BigInt where
  toStr = bigInt.toStr
  fromStr = bigInt.fromStr

instance IsBytes BigInt where
  toBytes = bigInt.toBytes
  fromBytes = bigInt.fromBytes

instance IsJson BigInt where
  toJson = bigInt.toJson
  fromJson = bigInt.fromJson

-------------------------------------------------------------------------------------
-- Big num

foreign import bigNum_free :: BigNum -> Effect Unit
foreign import bigNum_toBytes :: BigNum -> Bytes
foreign import bigNum_fromBytes :: Bytes -> BigNum
foreign import bigNum_toHex :: BigNum -> String
foreign import bigNum_fromHex :: String -> BigNum
foreign import bigNum_toJson :: BigNum -> String
foreign import bigNum_toJsValue :: BigNum -> BigNumJson
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
foreign import bigNum_compare :: BigNum -> BigNum -> Int
foreign import bigNum_lessThan :: BigNum -> BigNum -> Boolean
foreign import bigNum_max :: BigNum -> BigNum -> BigNum

-- | Big num class
type BigNumClass =
  { free :: BigNum -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: BigNum -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> BigNum
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: BigNum -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> BigNum
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: BigNum -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: BigNum -> BigNumJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> BigNum
    -- ^ From json
    -- > fromJson json
  , fromStr :: String -> BigNum
    -- ^ From str
    -- > fromStr string
  , toStr :: BigNum -> String
    -- ^ To str
    -- > toStr self
  , zero :: BigNum
    -- ^ Zero
    -- > zero
  , one :: BigNum
    -- ^ One
    -- > one
  , isZero :: BigNum -> Boolean
    -- ^ Is zero
    -- > isZero self
  , divFloor :: BigNum -> BigNum -> BigNum
    -- ^ Div floor
    -- > divFloor self other
  , checkedMul :: BigNum -> BigNum -> BigNum
    -- ^ Checked mul
    -- > checkedMul self other
  , checkedAdd :: BigNum -> BigNum -> BigNum
    -- ^ Checked add
    -- > checkedAdd self other
  , checkedSub :: BigNum -> BigNum -> BigNum
    -- ^ Checked sub
    -- > checkedSub self other
  , clampedSub :: BigNum -> BigNum -> BigNum
    -- ^ Clamped sub
    -- > clampedSub self other
  , compare :: BigNum -> BigNum -> Int
    -- ^ Compare
    -- > compare self rhsValue
  , lessThan :: BigNum -> BigNum -> Boolean
    -- ^ Less than
    -- > lessThan self rhsValue
  , max :: BigNum -> BigNum -> BigNum
    -- ^ Max
    -- > max a b
  }

-- | Big num class API
bigNum :: BigNumClass
bigNum =
  { free: bigNum_free
  , toBytes: bigNum_toBytes
  , fromBytes: bigNum_fromBytes
  , toHex: bigNum_toHex
  , fromHex: bigNum_fromHex
  , toJson: bigNum_toJson
  , toJsValue: bigNum_toJsValue
  , fromJson: bigNum_fromJson
  , fromStr: bigNum_fromStr
  , toStr: bigNum_toStr
  , zero: bigNum_zero
  , one: bigNum_one
  , isZero: bigNum_isZero
  , divFloor: bigNum_divFloor
  , checkedMul: bigNum_checkedMul
  , checkedAdd: bigNum_checkedAdd
  , checkedSub: bigNum_checkedSub
  , clampedSub: bigNum_clampedSub
  , compare: bigNum_compare
  , lessThan: bigNum_lessThan
  , max: bigNum_max
  }

instance HasFree BigNum where
  free = bigNum.free

instance Show BigNum where
  show = bigNum.toStr

instance ToJsValue BigNum where
  toJsValue = bigNum.toJsValue

instance IsHex BigNum where
  toHex = bigNum.toHex
  fromHex = bigNum.fromHex

instance IsStr BigNum where
  toStr = bigNum.toStr
  fromStr = bigNum.fromStr

instance IsBytes BigNum where
  toBytes = bigNum.toBytes
  fromBytes = bigNum.fromBytes

instance IsJson BigNum where
  toJson = bigNum.toJson
  fromJson = bigNum.fromJson

-------------------------------------------------------------------------------------
-- Bip32 private key

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

-- | Bip32 private key class
type Bip32PrivateKeyClass =
  { free :: Bip32PrivateKey -> Effect Unit
    -- ^ Free
    -- > free self
  , derive :: Bip32PrivateKey -> Number -> Bip32PrivateKey
    -- ^ Derive
    -- > derive self index
  , from128Xprv :: Bytes -> Bip32PrivateKey
    -- ^ From 128 xprv
    -- > from128Xprv bytes
  , to128Xprv :: Bip32PrivateKey -> Bytes
    -- ^ To 128 xprv
    -- > to128Xprv self
  , generateEd25519Bip32 :: Bip32PrivateKey
    -- ^ Generate ed25519 bip32
    -- > generateEd25519Bip32
  , toRawKey :: Bip32PrivateKey -> PrivateKey
    -- ^ To raw key
    -- > toRawKey self
  , toPublic :: Bip32PrivateKey -> Bip32PublicKey
    -- ^ To public
    -- > toPublic self
  , fromBytes :: Bytes -> Bip32PrivateKey
    -- ^ From bytes
    -- > fromBytes bytes
  , asBytes :: Bip32PrivateKey -> Bytes
    -- ^ As bytes
    -- > asBytes self
  , fromBech32 :: String -> Bip32PrivateKey
    -- ^ From bech32
    -- > fromBech32 bech32Str
  , toBech32 :: Bip32PrivateKey -> String
    -- ^ To bech32
    -- > toBech32 self
  , fromBip39Entropy :: Bytes -> Bytes -> Bip32PrivateKey
    -- ^ From bip39 entropy
    -- > fromBip39Entropy entropy password
  , chaincode :: Bip32PrivateKey -> Bytes
    -- ^ Chaincode
    -- > chaincode self
  , toHex :: Bip32PrivateKey -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Bip32PrivateKey
    -- ^ From hex
    -- > fromHex hexStr
  }

-- | Bip32 private key class API
bip32PrivateKey :: Bip32PrivateKeyClass
bip32PrivateKey =
  { free: bip32PrivateKey_free
  , derive: bip32PrivateKey_derive
  , from128Xprv: bip32PrivateKey_from128Xprv
  , to128Xprv: bip32PrivateKey_to128Xprv
  , generateEd25519Bip32: bip32PrivateKey_generateEd25519Bip32
  , toRawKey: bip32PrivateKey_toRawKey
  , toPublic: bip32PrivateKey_toPublic
  , fromBytes: bip32PrivateKey_fromBytes
  , asBytes: bip32PrivateKey_asBytes
  , fromBech32: bip32PrivateKey_fromBech32
  , toBech32: bip32PrivateKey_toBech32
  , fromBip39Entropy: bip32PrivateKey_fromBip39Entropy
  , chaincode: bip32PrivateKey_chaincode
  , toHex: bip32PrivateKey_toHex
  , fromHex: bip32PrivateKey_fromHex
  }

instance HasFree Bip32PrivateKey where
  free = bip32PrivateKey.free

instance Show Bip32PrivateKey where
  show = bip32PrivateKey.toHex

instance IsHex Bip32PrivateKey where
  toHex = bip32PrivateKey.toHex
  fromHex = bip32PrivateKey.fromHex

instance IsBech32 Bip32PrivateKey where
  toBech32 = bip32PrivateKey.toBech32
  fromBech32 = bip32PrivateKey.fromBech32

-------------------------------------------------------------------------------------
-- Bip32 public key

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

-- | Bip32 public key class
type Bip32PublicKeyClass =
  { free :: Bip32PublicKey -> Effect Unit
    -- ^ Free
    -- > free self
  , derive :: Bip32PublicKey -> Number -> Bip32PublicKey
    -- ^ Derive
    -- > derive self index
  , toRawKey :: Bip32PublicKey -> PublicKey
    -- ^ To raw key
    -- > toRawKey self
  , fromBytes :: Bytes -> Bip32PublicKey
    -- ^ From bytes
    -- > fromBytes bytes
  , asBytes :: Bip32PublicKey -> Bytes
    -- ^ As bytes
    -- > asBytes self
  , fromBech32 :: String -> Bip32PublicKey
    -- ^ From bech32
    -- > fromBech32 bech32Str
  , toBech32 :: Bip32PublicKey -> String
    -- ^ To bech32
    -- > toBech32 self
  , chaincode :: Bip32PublicKey -> Bytes
    -- ^ Chaincode
    -- > chaincode self
  , toHex :: Bip32PublicKey -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Bip32PublicKey
    -- ^ From hex
    -- > fromHex hexStr
  }

-- | Bip32 public key class API
bip32PublicKey :: Bip32PublicKeyClass
bip32PublicKey =
  { free: bip32PublicKey_free
  , derive: bip32PublicKey_derive
  , toRawKey: bip32PublicKey_toRawKey
  , fromBytes: bip32PublicKey_fromBytes
  , asBytes: bip32PublicKey_asBytes
  , fromBech32: bip32PublicKey_fromBech32
  , toBech32: bip32PublicKey_toBech32
  , chaincode: bip32PublicKey_chaincode
  , toHex: bip32PublicKey_toHex
  , fromHex: bip32PublicKey_fromHex
  }

instance HasFree Bip32PublicKey where
  free = bip32PublicKey.free

instance Show Bip32PublicKey where
  show = bip32PublicKey.toHex

instance IsHex Bip32PublicKey where
  toHex = bip32PublicKey.toHex
  fromHex = bip32PublicKey.fromHex

instance IsBech32 Bip32PublicKey where
  toBech32 = bip32PublicKey.toBech32
  fromBech32 = bip32PublicKey.fromBech32

-------------------------------------------------------------------------------------
-- Block

foreign import block_free :: Block -> Effect Unit
foreign import block_toBytes :: Block -> Bytes
foreign import block_fromBytes :: Bytes -> Block
foreign import block_toHex :: Block -> String
foreign import block_fromHex :: String -> Block
foreign import block_toJson :: Block -> String
foreign import block_toJsValue :: Block -> BlockJson
foreign import block_fromJson :: String -> Block
foreign import block_header :: Block -> Header
foreign import block_txBodies :: Block -> TxBodies
foreign import block_txWitnessSets :: Block -> TxWitnessSets
foreign import block_auxiliaryDataSet :: Block -> AuxiliaryDataSet
foreign import block_invalidTxs :: Block -> Uint32Array
foreign import block_new :: Header -> TxBodies -> TxWitnessSets -> AuxiliaryDataSet -> Uint32Array -> Block

-- | Block class
type BlockClass =
  { free :: Block -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Block -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Block
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Block -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Block
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Block -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Block -> BlockJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Block
    -- ^ From json
    -- > fromJson json
  , header :: Block -> Header
    -- ^ Header
    -- > header self
  , txBodies :: Block -> TxBodies
    -- ^ Transaction bodies
    -- > txBodies self
  , txWitnessSets :: Block -> TxWitnessSets
    -- ^ Transaction witness sets
    -- > txWitnessSets self
  , auxiliaryDataSet :: Block -> AuxiliaryDataSet
    -- ^ Auxiliary data set
    -- > auxiliaryDataSet self
  , invalidTxs :: Block -> Uint32Array
    -- ^ Invalid transactions
    -- > invalidTxs self
  , new :: Header -> TxBodies -> TxWitnessSets -> AuxiliaryDataSet -> Uint32Array -> Block
    -- ^ New
    -- > new header txBodies txWitnessSets auxiliaryDataSet invalidTxs
  }

-- | Block class API
block :: BlockClass
block =
  { free: block_free
  , toBytes: block_toBytes
  , fromBytes: block_fromBytes
  , toHex: block_toHex
  , fromHex: block_fromHex
  , toJson: block_toJson
  , toJsValue: block_toJsValue
  , fromJson: block_fromJson
  , header: block_header
  , txBodies: block_txBodies
  , txWitnessSets: block_txWitnessSets
  , auxiliaryDataSet: block_auxiliaryDataSet
  , invalidTxs: block_invalidTxs
  , new: block_new
  }

instance HasFree Block where
  free = block.free

instance Show Block where
  show = block.toHex

instance ToJsValue Block where
  toJsValue = block.toJsValue

instance IsHex Block where
  toHex = block.toHex
  fromHex = block.fromHex

instance IsBytes Block where
  toBytes = block.toBytes
  fromBytes = block.fromBytes

instance IsJson Block where
  toJson = block.toJson
  fromJson = block.fromJson

-------------------------------------------------------------------------------------
-- Block hash

foreign import blockHash_free :: BlockHash -> Effect Unit
foreign import blockHash_fromBytes :: Bytes -> BlockHash
foreign import blockHash_toBytes :: BlockHash -> Bytes
foreign import blockHash_toBech32 :: BlockHash -> String -> String
foreign import blockHash_fromBech32 :: String -> BlockHash
foreign import blockHash_toHex :: BlockHash -> String
foreign import blockHash_fromHex :: String -> BlockHash

-- | Block hash class
type BlockHashClass =
  { free :: BlockHash -> Effect Unit
    -- ^ Free
    -- > free self
  , fromBytes :: Bytes -> BlockHash
    -- ^ From bytes
    -- > fromBytes bytes
  , toBytes :: BlockHash -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , toBech32 :: BlockHash -> String -> String
    -- ^ To bech32
    -- > toBech32 self prefix
  , fromBech32 :: String -> BlockHash
    -- ^ From bech32
    -- > fromBech32 bechStr
  , toHex :: BlockHash -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> BlockHash
    -- ^ From hex
    -- > fromHex hex
  }

-- | Block hash class API
blockHash :: BlockHashClass
blockHash =
  { free: blockHash_free
  , fromBytes: blockHash_fromBytes
  , toBytes: blockHash_toBytes
  , toBech32: blockHash_toBech32
  , fromBech32: blockHash_fromBech32
  , toHex: blockHash_toHex
  , fromHex: blockHash_fromHex
  }

instance HasFree BlockHash where
  free = blockHash.free

instance Show BlockHash where
  show = blockHash.toHex

instance IsHex BlockHash where
  toHex = blockHash.toHex
  fromHex = blockHash.fromHex

instance IsBytes BlockHash where
  toBytes = blockHash.toBytes
  fromBytes = blockHash.fromBytes

-------------------------------------------------------------------------------------
-- Bootstrap witness

foreign import bootstrapWitness_free :: BootstrapWitness -> Effect Unit
foreign import bootstrapWitness_toBytes :: BootstrapWitness -> Bytes
foreign import bootstrapWitness_fromBytes :: Bytes -> BootstrapWitness
foreign import bootstrapWitness_toHex :: BootstrapWitness -> String
foreign import bootstrapWitness_fromHex :: String -> BootstrapWitness
foreign import bootstrapWitness_toJson :: BootstrapWitness -> String
foreign import bootstrapWitness_toJsValue :: BootstrapWitness -> BootstrapWitnessJson
foreign import bootstrapWitness_fromJson :: String -> BootstrapWitness
foreign import bootstrapWitness_vkey :: BootstrapWitness -> Vkey
foreign import bootstrapWitness_signature :: BootstrapWitness -> Ed25519Signature
foreign import bootstrapWitness_chainCode :: BootstrapWitness -> Bytes
foreign import bootstrapWitness_attributes :: BootstrapWitness -> Bytes
foreign import bootstrapWitness_new :: Vkey -> Ed25519Signature -> Bytes -> Bytes -> BootstrapWitness

-- | Bootstrap witness class
type BootstrapWitnessClass =
  { free :: BootstrapWitness -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: BootstrapWitness -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> BootstrapWitness
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: BootstrapWitness -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> BootstrapWitness
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: BootstrapWitness -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: BootstrapWitness -> BootstrapWitnessJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> BootstrapWitness
    -- ^ From json
    -- > fromJson json
  , vkey :: BootstrapWitness -> Vkey
    -- ^ Vkey
    -- > vkey self
  , signature :: BootstrapWitness -> Ed25519Signature
    -- ^ Signature
    -- > signature self
  , chainCode :: BootstrapWitness -> Bytes
    -- ^ Chain code
    -- > chainCode self
  , attributes :: BootstrapWitness -> Bytes
    -- ^ Attributes
    -- > attributes self
  , new :: Vkey -> Ed25519Signature -> Bytes -> Bytes -> BootstrapWitness
    -- ^ New
    -- > new vkey signature chainCode attributes
  }

-- | Bootstrap witness class API
bootstrapWitness :: BootstrapWitnessClass
bootstrapWitness =
  { free: bootstrapWitness_free
  , toBytes: bootstrapWitness_toBytes
  , fromBytes: bootstrapWitness_fromBytes
  , toHex: bootstrapWitness_toHex
  , fromHex: bootstrapWitness_fromHex
  , toJson: bootstrapWitness_toJson
  , toJsValue: bootstrapWitness_toJsValue
  , fromJson: bootstrapWitness_fromJson
  , vkey: bootstrapWitness_vkey
  , signature: bootstrapWitness_signature
  , chainCode: bootstrapWitness_chainCode
  , attributes: bootstrapWitness_attributes
  , new: bootstrapWitness_new
  }

instance HasFree BootstrapWitness where
  free = bootstrapWitness.free

instance Show BootstrapWitness where
  show = bootstrapWitness.toHex

instance ToJsValue BootstrapWitness where
  toJsValue = bootstrapWitness.toJsValue

instance IsHex BootstrapWitness where
  toHex = bootstrapWitness.toHex
  fromHex = bootstrapWitness.fromHex

instance IsBytes BootstrapWitness where
  toBytes = bootstrapWitness.toBytes
  fromBytes = bootstrapWitness.fromBytes

instance IsJson BootstrapWitness where
  toJson = bootstrapWitness.toJson
  fromJson = bootstrapWitness.fromJson

-------------------------------------------------------------------------------------
-- Bootstrap witnesses

foreign import bootstrapWitnesses_free :: BootstrapWitnesses -> Effect Unit
foreign import bootstrapWitnesses_new :: Effect BootstrapWitnesses
foreign import bootstrapWitnesses_len :: BootstrapWitnesses -> Effect Int
foreign import bootstrapWitnesses_get :: BootstrapWitnesses -> Int -> Effect BootstrapWitness
foreign import bootstrapWitnesses_add :: BootstrapWitnesses -> BootstrapWitness -> Effect Unit

-- | Bootstrap witnesses class
type BootstrapWitnessesClass =
  { free :: BootstrapWitnesses -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: Effect BootstrapWitnesses
    -- ^ New
    -- > new
  , len :: BootstrapWitnesses -> Effect Int
    -- ^ Len
    -- > len self
  , get :: BootstrapWitnesses -> Int -> Effect BootstrapWitness
    -- ^ Get
    -- > get self index
  , add :: BootstrapWitnesses -> BootstrapWitness -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Bootstrap witnesses class API
bootstrapWitnesses :: BootstrapWitnessesClass
bootstrapWitnesses =
  { free: bootstrapWitnesses_free
  , new: bootstrapWitnesses_new
  , len: bootstrapWitnesses_len
  , get: bootstrapWitnesses_get
  , add: bootstrapWitnesses_add
  }

instance HasFree BootstrapWitnesses where
  free = bootstrapWitnesses.free

instance MutableList BootstrapWitnesses BootstrapWitness where
  addItem = bootstrapWitnesses.add
  getItem = bootstrapWitnesses.get
  emptyList = bootstrapWitnesses.new

instance MutableLen BootstrapWitnesses where
  getLen = bootstrapWitnesses.len

-------------------------------------------------------------------------------------
-- Byron address

foreign import byronAddress_free :: ByronAddress -> Effect Unit
foreign import byronAddress_toBase58 :: ByronAddress -> String
foreign import byronAddress_toBytes :: ByronAddress -> Bytes
foreign import byronAddress_fromBytes :: Bytes -> ByronAddress
foreign import byronAddress_byronProtocolMagic :: ByronAddress -> Number
foreign import byronAddress_attributes :: ByronAddress -> Bytes
foreign import byronAddress_networkId :: ByronAddress -> Int
foreign import byronAddress_fromBase58 :: String -> ByronAddress
foreign import byronAddress_icarusFromKey :: Bip32PublicKey -> Number -> ByronAddress
foreign import byronAddress_isValid :: String -> Boolean
foreign import byronAddress_toAddress :: ByronAddress -> Address
foreign import byronAddress_fromAddress :: Address -> Nullable ByronAddress

-- | Byron address class
type ByronAddressClass =
  { free :: ByronAddress -> Effect Unit
    -- ^ Free
    -- > free self
  , toBase58 :: ByronAddress -> String
    -- ^ To base58
    -- > toBase58 self
  , toBytes :: ByronAddress -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> ByronAddress
    -- ^ From bytes
    -- > fromBytes bytes
  , byronProtocolMagic :: ByronAddress -> Number
    -- ^ Byron protocol magic
    -- > byronProtocolMagic self
  , attributes :: ByronAddress -> Bytes
    -- ^ Attributes
    -- > attributes self
  , networkId :: ByronAddress -> Int
    -- ^ Network id
    -- > networkId self
  , fromBase58 :: String -> ByronAddress
    -- ^ From base58
    -- > fromBase58 s
  , icarusFromKey :: Bip32PublicKey -> Number -> ByronAddress
    -- ^ Icarus from key
    -- > icarusFromKey key protocolMagic
  , isValid :: String -> Boolean
    -- ^ Is valid
    -- > isValid s
  , toAddress :: ByronAddress -> Address
    -- ^ To address
    -- > toAddress self
  , fromAddress :: Address -> Maybe ByronAddress
    -- ^ From address
    -- > fromAddress addr
  }

-- | Byron address class API
byronAddress :: ByronAddressClass
byronAddress =
  { free: byronAddress_free
  , toBase58: byronAddress_toBase58
  , toBytes: byronAddress_toBytes
  , fromBytes: byronAddress_fromBytes
  , byronProtocolMagic: byronAddress_byronProtocolMagic
  , attributes: byronAddress_attributes
  , networkId: byronAddress_networkId
  , fromBase58: byronAddress_fromBase58
  , icarusFromKey: byronAddress_icarusFromKey
  , isValid: byronAddress_isValid
  , toAddress: byronAddress_toAddress
  , fromAddress: \a1 -> Nullable.toMaybe $ byronAddress_fromAddress a1
  }

instance HasFree ByronAddress where
  free = byronAddress.free

instance IsBytes ByronAddress where
  toBytes = byronAddress.toBytes
  fromBytes = byronAddress.fromBytes

-------------------------------------------------------------------------------------
-- Certificate

foreign import certificate_free :: Certificate -> Effect Unit
foreign import certificate_toBytes :: Certificate -> Bytes
foreign import certificate_fromBytes :: Bytes -> Certificate
foreign import certificate_toHex :: Certificate -> String
foreign import certificate_fromHex :: String -> Certificate
foreign import certificate_toJson :: Certificate -> String
foreign import certificate_toJsValue :: Certificate -> CertificateJson
foreign import certificate_fromJson :: String -> Certificate
foreign import certificate_newStakeRegistration :: StakeRegistration -> Certificate
foreign import certificate_newStakeDeregistration :: StakeDeregistration -> Certificate
foreign import certificate_newStakeDelegation :: StakeDelegation -> Certificate
foreign import certificate_newPoolRegistration :: PoolRegistration -> Certificate
foreign import certificate_newPoolRetirement :: PoolRetirement -> Certificate
foreign import certificate_newGenesisKeyDelegation :: GenesisKeyDelegation -> Certificate
foreign import certificate_newMoveInstantaneousRewardsCert :: MoveInstantaneousRewardsCert -> Certificate
foreign import certificate_kind :: Certificate -> Number
foreign import certificate_asStakeRegistration :: Certificate -> Nullable StakeRegistration
foreign import certificate_asStakeDeregistration :: Certificate -> Nullable StakeDeregistration
foreign import certificate_asStakeDelegation :: Certificate -> Nullable StakeDelegation
foreign import certificate_asPoolRegistration :: Certificate -> Nullable PoolRegistration
foreign import certificate_asPoolRetirement :: Certificate -> Nullable PoolRetirement
foreign import certificate_asGenesisKeyDelegation :: Certificate -> Nullable GenesisKeyDelegation
foreign import certificate_asMoveInstantaneousRewardsCert :: Certificate -> Nullable MoveInstantaneousRewardsCert

-- | Certificate class
type CertificateClass =
  { free :: Certificate -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Certificate -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Certificate
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Certificate -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Certificate
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Certificate -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Certificate -> CertificateJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Certificate
    -- ^ From json
    -- > fromJson json
  , newStakeRegistration :: StakeRegistration -> Certificate
    -- ^ New stake registration
    -- > newStakeRegistration stakeRegistration
  , newStakeDeregistration :: StakeDeregistration -> Certificate
    -- ^ New stake deregistration
    -- > newStakeDeregistration stakeDeregistration
  , newStakeDelegation :: StakeDelegation -> Certificate
    -- ^ New stake delegation
    -- > newStakeDelegation stakeDelegation
  , newPoolRegistration :: PoolRegistration -> Certificate
    -- ^ New pool registration
    -- > newPoolRegistration poolRegistration
  , newPoolRetirement :: PoolRetirement -> Certificate
    -- ^ New pool retirement
    -- > newPoolRetirement poolRetirement
  , newGenesisKeyDelegation :: GenesisKeyDelegation -> Certificate
    -- ^ New genesis key delegation
    -- > newGenesisKeyDelegation genesisKeyDelegation
  , newMoveInstantaneousRewardsCert :: MoveInstantaneousRewardsCert -> Certificate
    -- ^ New move instantaneous rewards cert
    -- > newMoveInstantaneousRewardsCert moveInstantaneousRewardsCert
  , kind :: Certificate -> Number
    -- ^ Kind
    -- > kind self
  , asStakeRegistration :: Certificate -> Maybe StakeRegistration
    -- ^ As stake registration
    -- > asStakeRegistration self
  , asStakeDeregistration :: Certificate -> Maybe StakeDeregistration
    -- ^ As stake deregistration
    -- > asStakeDeregistration self
  , asStakeDelegation :: Certificate -> Maybe StakeDelegation
    -- ^ As stake delegation
    -- > asStakeDelegation self
  , asPoolRegistration :: Certificate -> Maybe PoolRegistration
    -- ^ As pool registration
    -- > asPoolRegistration self
  , asPoolRetirement :: Certificate -> Maybe PoolRetirement
    -- ^ As pool retirement
    -- > asPoolRetirement self
  , asGenesisKeyDelegation :: Certificate -> Maybe GenesisKeyDelegation
    -- ^ As genesis key delegation
    -- > asGenesisKeyDelegation self
  , asMoveInstantaneousRewardsCert :: Certificate -> Maybe MoveInstantaneousRewardsCert
    -- ^ As move instantaneous rewards cert
    -- > asMoveInstantaneousRewardsCert self
  }

-- | Certificate class API
certificate :: CertificateClass
certificate =
  { free: certificate_free
  , toBytes: certificate_toBytes
  , fromBytes: certificate_fromBytes
  , toHex: certificate_toHex
  , fromHex: certificate_fromHex
  , toJson: certificate_toJson
  , toJsValue: certificate_toJsValue
  , fromJson: certificate_fromJson
  , newStakeRegistration: certificate_newStakeRegistration
  , newStakeDeregistration: certificate_newStakeDeregistration
  , newStakeDelegation: certificate_newStakeDelegation
  , newPoolRegistration: certificate_newPoolRegistration
  , newPoolRetirement: certificate_newPoolRetirement
  , newGenesisKeyDelegation: certificate_newGenesisKeyDelegation
  , newMoveInstantaneousRewardsCert: certificate_newMoveInstantaneousRewardsCert
  , kind: certificate_kind
  , asStakeRegistration: \a1 -> Nullable.toMaybe $ certificate_asStakeRegistration a1
  , asStakeDeregistration: \a1 -> Nullable.toMaybe $ certificate_asStakeDeregistration a1
  , asStakeDelegation: \a1 -> Nullable.toMaybe $ certificate_asStakeDelegation a1
  , asPoolRegistration: \a1 -> Nullable.toMaybe $ certificate_asPoolRegistration a1
  , asPoolRetirement: \a1 -> Nullable.toMaybe $ certificate_asPoolRetirement a1
  , asGenesisKeyDelegation: \a1 -> Nullable.toMaybe $ certificate_asGenesisKeyDelegation a1
  , asMoveInstantaneousRewardsCert: \a1 -> Nullable.toMaybe $ certificate_asMoveInstantaneousRewardsCert a1
  }

instance HasFree Certificate where
  free = certificate.free

instance Show Certificate where
  show = certificate.toHex

instance ToJsValue Certificate where
  toJsValue = certificate.toJsValue

instance IsHex Certificate where
  toHex = certificate.toHex
  fromHex = certificate.fromHex

instance IsBytes Certificate where
  toBytes = certificate.toBytes
  fromBytes = certificate.fromBytes

instance IsJson Certificate where
  toJson = certificate.toJson
  fromJson = certificate.fromJson

-------------------------------------------------------------------------------------
-- Certificates

foreign import certificates_free :: Certificates -> Effect Unit
foreign import certificates_toBytes :: Certificates -> Bytes
foreign import certificates_fromBytes :: Bytes -> Certificates
foreign import certificates_toHex :: Certificates -> String
foreign import certificates_fromHex :: String -> Certificates
foreign import certificates_toJson :: Certificates -> String
foreign import certificates_toJsValue :: Certificates -> CertificatesJson
foreign import certificates_fromJson :: String -> Certificates
foreign import certificates_new :: Effect Certificates
foreign import certificates_len :: Certificates -> Effect Int
foreign import certificates_get :: Certificates -> Int -> Effect Certificate
foreign import certificates_add :: Certificates -> Certificate -> Effect Unit

-- | Certificates class
type CertificatesClass =
  { free :: Certificates -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Certificates -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Certificates
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Certificates -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Certificates
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Certificates -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Certificates -> CertificatesJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Certificates
    -- ^ From json
    -- > fromJson json
  , new :: Effect Certificates
    -- ^ New
    -- > new
  , len :: Certificates -> Effect Int
    -- ^ Len
    -- > len self
  , get :: Certificates -> Int -> Effect Certificate
    -- ^ Get
    -- > get self index
  , add :: Certificates -> Certificate -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Certificates class API
certificates :: CertificatesClass
certificates =
  { free: certificates_free
  , toBytes: certificates_toBytes
  , fromBytes: certificates_fromBytes
  , toHex: certificates_toHex
  , fromHex: certificates_fromHex
  , toJson: certificates_toJson
  , toJsValue: certificates_toJsValue
  , fromJson: certificates_fromJson
  , new: certificates_new
  , len: certificates_len
  , get: certificates_get
  , add: certificates_add
  }

instance HasFree Certificates where
  free = certificates.free

instance Show Certificates where
  show = certificates.toHex

instance MutableList Certificates Certificate where
  addItem = certificates.add
  getItem = certificates.get
  emptyList = certificates.new

instance MutableLen Certificates where
  getLen = certificates.len


instance ToJsValue Certificates where
  toJsValue = certificates.toJsValue

instance IsHex Certificates where
  toHex = certificates.toHex
  fromHex = certificates.fromHex

instance IsBytes Certificates where
  toBytes = certificates.toBytes
  fromBytes = certificates.fromBytes

instance IsJson Certificates where
  toJson = certificates.toJson
  fromJson = certificates.fromJson

-------------------------------------------------------------------------------------
-- Constr plutus data

foreign import constrPlutusData_free :: ConstrPlutusData -> Effect Unit
foreign import constrPlutusData_toBytes :: ConstrPlutusData -> Bytes
foreign import constrPlutusData_fromBytes :: Bytes -> ConstrPlutusData
foreign import constrPlutusData_toHex :: ConstrPlutusData -> String
foreign import constrPlutusData_fromHex :: String -> ConstrPlutusData
foreign import constrPlutusData_toJson :: ConstrPlutusData -> String
foreign import constrPlutusData_toJsValue :: ConstrPlutusData -> ConstrPlutusDataJson
foreign import constrPlutusData_fromJson :: String -> ConstrPlutusData
foreign import constrPlutusData_alternative :: ConstrPlutusData -> BigNum
foreign import constrPlutusData_data :: ConstrPlutusData -> PlutusList
foreign import constrPlutusData_new :: BigNum -> PlutusList -> ConstrPlutusData

-- | Constr plutus data class
type ConstrPlutusDataClass =
  { free :: ConstrPlutusData -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: ConstrPlutusData -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> ConstrPlutusData
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: ConstrPlutusData -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> ConstrPlutusData
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: ConstrPlutusData -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: ConstrPlutusData -> ConstrPlutusDataJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> ConstrPlutusData
    -- ^ From json
    -- > fromJson json
  , alternative :: ConstrPlutusData -> BigNum
    -- ^ Alternative
    -- > alternative self
  , data :: ConstrPlutusData -> PlutusList
    -- ^ Data
    -- > data self
  , new :: BigNum -> PlutusList -> ConstrPlutusData
    -- ^ New
    -- > new alternative data
  }

-- | Constr plutus data class API
constrPlutusData :: ConstrPlutusDataClass
constrPlutusData =
  { free: constrPlutusData_free
  , toBytes: constrPlutusData_toBytes
  , fromBytes: constrPlutusData_fromBytes
  , toHex: constrPlutusData_toHex
  , fromHex: constrPlutusData_fromHex
  , toJson: constrPlutusData_toJson
  , toJsValue: constrPlutusData_toJsValue
  , fromJson: constrPlutusData_fromJson
  , alternative: constrPlutusData_alternative
  , data: constrPlutusData_data
  , new: constrPlutusData_new
  }

instance HasFree ConstrPlutusData where
  free = constrPlutusData.free

instance Show ConstrPlutusData where
  show = constrPlutusData.toHex

instance ToJsValue ConstrPlutusData where
  toJsValue = constrPlutusData.toJsValue

instance IsHex ConstrPlutusData where
  toHex = constrPlutusData.toHex
  fromHex = constrPlutusData.fromHex

instance IsBytes ConstrPlutusData where
  toBytes = constrPlutusData.toBytes
  fromBytes = constrPlutusData.fromBytes

instance IsJson ConstrPlutusData where
  toJson = constrPlutusData.toJson
  fromJson = constrPlutusData.fromJson

-------------------------------------------------------------------------------------
-- Cost model

foreign import costModel_free :: CostModel -> Effect Unit
foreign import costModel_toBytes :: CostModel -> Bytes
foreign import costModel_fromBytes :: Bytes -> CostModel
foreign import costModel_toHex :: CostModel -> String
foreign import costModel_fromHex :: String -> CostModel
foreign import costModel_toJson :: CostModel -> String
foreign import costModel_toJsValue :: CostModel -> CostModelJson
foreign import costModel_fromJson :: String -> CostModel
foreign import costModel_new :: Effect CostModel
foreign import costModel_set :: CostModel -> Int -> Int -> Effect Int
foreign import costModel_get :: CostModel -> Int -> Effect Int
foreign import costModel_len :: CostModel -> Effect Int

-- | Cost model class
type CostModelClass =
  { free :: CostModel -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: CostModel -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> CostModel
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: CostModel -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> CostModel
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: CostModel -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: CostModel -> CostModelJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> CostModel
    -- ^ From json
    -- > fromJson json
  , new :: Effect CostModel
    -- ^ New
    -- > new
  , set :: CostModel -> Int -> Int -> Effect Int
    -- ^ Set
    -- > set self operation cost
  , get :: CostModel -> Int -> Effect Int
    -- ^ Get
    -- > get self operation
  , len :: CostModel -> Effect Int
    -- ^ Len
    -- > len self
  }

-- | Cost model class API
costModel :: CostModelClass
costModel =
  { free: costModel_free
  , toBytes: costModel_toBytes
  , fromBytes: costModel_fromBytes
  , toHex: costModel_toHex
  , fromHex: costModel_fromHex
  , toJson: costModel_toJson
  , toJsValue: costModel_toJsValue
  , fromJson: costModel_fromJson
  , new: costModel_new
  , set: costModel_set
  , get: costModel_get
  , len: costModel_len
  }

instance HasFree CostModel where
  free = costModel.free

instance Show CostModel where
  show = costModel.toHex

instance ToJsValue CostModel where
  toJsValue = costModel.toJsValue

instance IsHex CostModel where
  toHex = costModel.toHex
  fromHex = costModel.fromHex

instance IsBytes CostModel where
  toBytes = costModel.toBytes
  fromBytes = costModel.fromBytes

instance IsJson CostModel where
  toJson = costModel.toJson
  fromJson = costModel.fromJson

-------------------------------------------------------------------------------------
-- Costmdls

foreign import costmdls_free :: Costmdls -> Effect Unit
foreign import costmdls_toBytes :: Costmdls -> Bytes
foreign import costmdls_fromBytes :: Bytes -> Costmdls
foreign import costmdls_toHex :: Costmdls -> String
foreign import costmdls_fromHex :: String -> Costmdls
foreign import costmdls_toJson :: Costmdls -> String
foreign import costmdls_toJsValue :: Costmdls -> CostmdlsJson
foreign import costmdls_fromJson :: String -> Costmdls
foreign import costmdls_new :: Effect Costmdls
foreign import costmdls_len :: Costmdls -> Effect Int
foreign import costmdls_insert :: Costmdls -> Language -> CostModel -> Effect (Nullable CostModel)
foreign import costmdls_get :: Costmdls -> Language -> Effect (Nullable CostModel)
foreign import costmdls_keys :: Costmdls -> Effect Languages
foreign import costmdls_retainLanguageVersions :: Costmdls -> Languages -> Costmdls

-- | Costmdls class
type CostmdlsClass =
  { free :: Costmdls -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Costmdls -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Costmdls
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Costmdls -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Costmdls
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Costmdls -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Costmdls -> CostmdlsJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Costmdls
    -- ^ From json
    -- > fromJson json
  , new :: Effect Costmdls
    -- ^ New
    -- > new
  , len :: Costmdls -> Effect Int
    -- ^ Len
    -- > len self
  , insert :: Costmdls -> Language -> CostModel -> Effect (Maybe CostModel)
    -- ^ Insert
    -- > insert self key value
  , get :: Costmdls -> Language -> Effect (Maybe CostModel)
    -- ^ Get
    -- > get self key
  , keys :: Costmdls -> Effect Languages
    -- ^ Keys
    -- > keys self
  , retainLanguageVersions :: Costmdls -> Languages -> Costmdls
    -- ^ Retain language versions
    -- > retainLanguageVersions self languages
  }

-- | Costmdls class API
costmdls :: CostmdlsClass
costmdls =
  { free: costmdls_free
  , toBytes: costmdls_toBytes
  , fromBytes: costmdls_fromBytes
  , toHex: costmdls_toHex
  , fromHex: costmdls_fromHex
  , toJson: costmdls_toJson
  , toJsValue: costmdls_toJsValue
  , fromJson: costmdls_fromJson
  , new: costmdls_new
  , len: costmdls_len
  , insert: \a1 a2 a3 -> Nullable.toMaybe <$> costmdls_insert a1 a2 a3
  , get: \a1 a2 -> Nullable.toMaybe <$> costmdls_get a1 a2
  , keys: costmdls_keys
  , retainLanguageVersions: costmdls_retainLanguageVersions
  }

instance HasFree Costmdls where
  free = costmdls.free

instance Show Costmdls where
  show = costmdls.toHex

instance ToJsValue Costmdls where
  toJsValue = costmdls.toJsValue

instance IsHex Costmdls where
  toHex = costmdls.toHex
  fromHex = costmdls.fromHex

instance IsBytes Costmdls where
  toBytes = costmdls.toBytes
  fromBytes = costmdls.fromBytes

instance IsJson Costmdls where
  toJson = costmdls.toJson
  fromJson = costmdls.fromJson

-------------------------------------------------------------------------------------
-- DNSRecord aor aaaa

foreign import dnsRecordAorAAAA_free :: DNSRecordAorAAAA -> Effect Unit
foreign import dnsRecordAorAAAA_toBytes :: DNSRecordAorAAAA -> Bytes
foreign import dnsRecordAorAAAA_fromBytes :: Bytes -> DNSRecordAorAAAA
foreign import dnsRecordAorAAAA_toHex :: DNSRecordAorAAAA -> String
foreign import dnsRecordAorAAAA_fromHex :: String -> DNSRecordAorAAAA
foreign import dnsRecordAorAAAA_toJson :: DNSRecordAorAAAA -> String
foreign import dnsRecordAorAAAA_toJsValue :: DNSRecordAorAAAA -> DNSRecordAorAAAAJson
foreign import dnsRecordAorAAAA_fromJson :: String -> DNSRecordAorAAAA
foreign import dnsRecordAorAAAA_new :: String -> DNSRecordAorAAAA
foreign import dnsRecordAorAAAA_record :: DNSRecordAorAAAA -> String

-- | DNSRecord aor aaaa class
type DNSRecordAorAAAAClass =
  { free :: DNSRecordAorAAAA -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: DNSRecordAorAAAA -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> DNSRecordAorAAAA
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: DNSRecordAorAAAA -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> DNSRecordAorAAAA
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: DNSRecordAorAAAA -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: DNSRecordAorAAAA -> DNSRecordAorAAAAJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> DNSRecordAorAAAA
    -- ^ From json
    -- > fromJson json
  , new :: String -> DNSRecordAorAAAA
    -- ^ New
    -- > new dnsName
  , record :: DNSRecordAorAAAA -> String
    -- ^ Record
    -- > record self
  }

-- | DNSRecord aor aaaa class API
dnsRecordAorAAAA :: DNSRecordAorAAAAClass
dnsRecordAorAAAA =
  { free: dnsRecordAorAAAA_free
  , toBytes: dnsRecordAorAAAA_toBytes
  , fromBytes: dnsRecordAorAAAA_fromBytes
  , toHex: dnsRecordAorAAAA_toHex
  , fromHex: dnsRecordAorAAAA_fromHex
  , toJson: dnsRecordAorAAAA_toJson
  , toJsValue: dnsRecordAorAAAA_toJsValue
  , fromJson: dnsRecordAorAAAA_fromJson
  , new: dnsRecordAorAAAA_new
  , record: dnsRecordAorAAAA_record
  }

instance HasFree DNSRecordAorAAAA where
  free = dnsRecordAorAAAA.free

instance Show DNSRecordAorAAAA where
  show = dnsRecordAorAAAA.toHex

instance ToJsValue DNSRecordAorAAAA where
  toJsValue = dnsRecordAorAAAA.toJsValue

instance IsHex DNSRecordAorAAAA where
  toHex = dnsRecordAorAAAA.toHex
  fromHex = dnsRecordAorAAAA.fromHex

instance IsBytes DNSRecordAorAAAA where
  toBytes = dnsRecordAorAAAA.toBytes
  fromBytes = dnsRecordAorAAAA.fromBytes

instance IsJson DNSRecordAorAAAA where
  toJson = dnsRecordAorAAAA.toJson
  fromJson = dnsRecordAorAAAA.fromJson

-------------------------------------------------------------------------------------
-- DNSRecord srv

foreign import dnsRecordSRV_free :: DNSRecordSRV -> Effect Unit
foreign import dnsRecordSRV_toBytes :: DNSRecordSRV -> Bytes
foreign import dnsRecordSRV_fromBytes :: Bytes -> DNSRecordSRV
foreign import dnsRecordSRV_toHex :: DNSRecordSRV -> String
foreign import dnsRecordSRV_fromHex :: String -> DNSRecordSRV
foreign import dnsRecordSRV_toJson :: DNSRecordSRV -> String
foreign import dnsRecordSRV_toJsValue :: DNSRecordSRV -> DNSRecordSRVJson
foreign import dnsRecordSRV_fromJson :: String -> DNSRecordSRV
foreign import dnsRecordSRV_new :: String -> DNSRecordSRV
foreign import dnsRecordSRV_record :: DNSRecordSRV -> String

-- | DNSRecord srv class
type DNSRecordSRVClass =
  { free :: DNSRecordSRV -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: DNSRecordSRV -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> DNSRecordSRV
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: DNSRecordSRV -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> DNSRecordSRV
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: DNSRecordSRV -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: DNSRecordSRV -> DNSRecordSRVJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> DNSRecordSRV
    -- ^ From json
    -- > fromJson json
  , new :: String -> DNSRecordSRV
    -- ^ New
    -- > new dnsName
  , record :: DNSRecordSRV -> String
    -- ^ Record
    -- > record self
  }

-- | DNSRecord srv class API
dnsRecordSRV :: DNSRecordSRVClass
dnsRecordSRV =
  { free: dnsRecordSRV_free
  , toBytes: dnsRecordSRV_toBytes
  , fromBytes: dnsRecordSRV_fromBytes
  , toHex: dnsRecordSRV_toHex
  , fromHex: dnsRecordSRV_fromHex
  , toJson: dnsRecordSRV_toJson
  , toJsValue: dnsRecordSRV_toJsValue
  , fromJson: dnsRecordSRV_fromJson
  , new: dnsRecordSRV_new
  , record: dnsRecordSRV_record
  }

instance HasFree DNSRecordSRV where
  free = dnsRecordSRV.free

instance Show DNSRecordSRV where
  show = dnsRecordSRV.toHex

instance ToJsValue DNSRecordSRV where
  toJsValue = dnsRecordSRV.toJsValue

instance IsHex DNSRecordSRV where
  toHex = dnsRecordSRV.toHex
  fromHex = dnsRecordSRV.fromHex

instance IsBytes DNSRecordSRV where
  toBytes = dnsRecordSRV.toBytes
  fromBytes = dnsRecordSRV.fromBytes

instance IsJson DNSRecordSRV where
  toJson = dnsRecordSRV.toJson
  fromJson = dnsRecordSRV.fromJson

-------------------------------------------------------------------------------------
-- Data cost

foreign import dataCost_free :: DataCost -> Effect Unit
foreign import dataCost_newCoinsPerWord :: BigNum -> DataCost
foreign import dataCost_newCoinsPerByte :: BigNum -> DataCost
foreign import dataCost_coinsPerByte :: DataCost -> BigNum

-- | Data cost class
type DataCostClass =
  { free :: DataCost -> Effect Unit
    -- ^ Free
    -- > free self
  , newCoinsPerWord :: BigNum -> DataCost
    -- ^ New coins per word
    -- > newCoinsPerWord coinsPerWord
  , newCoinsPerByte :: BigNum -> DataCost
    -- ^ New coins per byte
    -- > newCoinsPerByte coinsPerByte
  , coinsPerByte :: DataCost -> BigNum
    -- ^ Coins per byte
    -- > coinsPerByte self
  }

-- | Data cost class API
dataCost :: DataCostClass
dataCost =
  { free: dataCost_free
  , newCoinsPerWord: dataCost_newCoinsPerWord
  , newCoinsPerByte: dataCost_newCoinsPerByte
  , coinsPerByte: dataCost_coinsPerByte
  }

instance HasFree DataCost where
  free = dataCost.free

-------------------------------------------------------------------------------------
-- Data hash

foreign import dataHash_free :: DataHash -> Effect Unit
foreign import dataHash_fromBytes :: Bytes -> DataHash
foreign import dataHash_toBytes :: DataHash -> Bytes
foreign import dataHash_toBech32 :: DataHash -> String -> String
foreign import dataHash_fromBech32 :: String -> DataHash
foreign import dataHash_toHex :: DataHash -> String
foreign import dataHash_fromHex :: String -> DataHash

-- | Data hash class
type DataHashClass =
  { free :: DataHash -> Effect Unit
    -- ^ Free
    -- > free self
  , fromBytes :: Bytes -> DataHash
    -- ^ From bytes
    -- > fromBytes bytes
  , toBytes :: DataHash -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , toBech32 :: DataHash -> String -> String
    -- ^ To bech32
    -- > toBech32 self prefix
  , fromBech32 :: String -> DataHash
    -- ^ From bech32
    -- > fromBech32 bechStr
  , toHex :: DataHash -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> DataHash
    -- ^ From hex
    -- > fromHex hex
  }

-- | Data hash class API
dataHash :: DataHashClass
dataHash =
  { free: dataHash_free
  , fromBytes: dataHash_fromBytes
  , toBytes: dataHash_toBytes
  , toBech32: dataHash_toBech32
  , fromBech32: dataHash_fromBech32
  , toHex: dataHash_toHex
  , fromHex: dataHash_fromHex
  }

instance HasFree DataHash where
  free = dataHash.free

instance Show DataHash where
  show = dataHash.toHex

instance IsHex DataHash where
  toHex = dataHash.toHex
  fromHex = dataHash.fromHex

instance IsBytes DataHash where
  toBytes = dataHash.toBytes
  fromBytes = dataHash.fromBytes

-------------------------------------------------------------------------------------
-- Datum source

foreign import datumSource_free :: DatumSource -> Effect Unit
foreign import datumSource_new :: PlutusData -> DatumSource
foreign import datumSource_newRefIn :: TxIn -> DatumSource

-- | Datum source class
type DatumSourceClass =
  { free :: DatumSource -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: PlutusData -> DatumSource
    -- ^ New
    -- > new datum
  , newRefIn :: TxIn -> DatumSource
    -- ^ New ref input
    -- > newRefIn in
  }

-- | Datum source class API
datumSource :: DatumSourceClass
datumSource =
  { free: datumSource_free
  , new: datumSource_new
  , newRefIn: datumSource_newRefIn
  }

instance HasFree DatumSource where
  free = datumSource.free

-------------------------------------------------------------------------------------
-- Ed25519 key hash

foreign import ed25519KeyHash_free :: Ed25519KeyHash -> Effect Unit
foreign import ed25519KeyHash_fromBytes :: Bytes -> Ed25519KeyHash
foreign import ed25519KeyHash_toBytes :: Ed25519KeyHash -> Bytes
foreign import ed25519KeyHash_toBech32 :: Ed25519KeyHash -> String -> String
foreign import ed25519KeyHash_fromBech32 :: String -> Ed25519KeyHash
foreign import ed25519KeyHash_toHex :: Ed25519KeyHash -> String
foreign import ed25519KeyHash_fromHex :: String -> Ed25519KeyHash

-- | Ed25519 key hash class
type Ed25519KeyHashClass =
  { free :: Ed25519KeyHash -> Effect Unit
    -- ^ Free
    -- > free self
  , fromBytes :: Bytes -> Ed25519KeyHash
    -- ^ From bytes
    -- > fromBytes bytes
  , toBytes :: Ed25519KeyHash -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , toBech32 :: Ed25519KeyHash -> String -> String
    -- ^ To bech32
    -- > toBech32 self prefix
  , fromBech32 :: String -> Ed25519KeyHash
    -- ^ From bech32
    -- > fromBech32 bechStr
  , toHex :: Ed25519KeyHash -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Ed25519KeyHash
    -- ^ From hex
    -- > fromHex hex
  }

-- | Ed25519 key hash class API
ed25519KeyHash :: Ed25519KeyHashClass
ed25519KeyHash =
  { free: ed25519KeyHash_free
  , fromBytes: ed25519KeyHash_fromBytes
  , toBytes: ed25519KeyHash_toBytes
  , toBech32: ed25519KeyHash_toBech32
  , fromBech32: ed25519KeyHash_fromBech32
  , toHex: ed25519KeyHash_toHex
  , fromHex: ed25519KeyHash_fromHex
  }

instance HasFree Ed25519KeyHash where
  free = ed25519KeyHash.free

instance Show Ed25519KeyHash where
  show = ed25519KeyHash.toHex

instance IsHex Ed25519KeyHash where
  toHex = ed25519KeyHash.toHex
  fromHex = ed25519KeyHash.fromHex

instance IsBytes Ed25519KeyHash where
  toBytes = ed25519KeyHash.toBytes
  fromBytes = ed25519KeyHash.fromBytes

-------------------------------------------------------------------------------------
-- Ed25519 key hashes

foreign import ed25519KeyHashes_free :: Ed25519KeyHashes -> Effect Unit
foreign import ed25519KeyHashes_toBytes :: Ed25519KeyHashes -> Bytes
foreign import ed25519KeyHashes_fromBytes :: Bytes -> Ed25519KeyHashes
foreign import ed25519KeyHashes_toHex :: Ed25519KeyHashes -> String
foreign import ed25519KeyHashes_fromHex :: String -> Ed25519KeyHashes
foreign import ed25519KeyHashes_toJson :: Ed25519KeyHashes -> String
foreign import ed25519KeyHashes_toJsValue :: Ed25519KeyHashes -> Ed25519KeyHashesJson
foreign import ed25519KeyHashes_fromJson :: String -> Ed25519KeyHashes
foreign import ed25519KeyHashes_new :: Ed25519KeyHashes
foreign import ed25519KeyHashes_len :: Ed25519KeyHashes -> Number
foreign import ed25519KeyHashes_get :: Ed25519KeyHashes -> Number -> Ed25519KeyHash
foreign import ed25519KeyHashes_add :: Ed25519KeyHashes -> Ed25519KeyHash -> Effect Unit
foreign import ed25519KeyHashes_toOption :: Ed25519KeyHashes -> Nullable Ed25519KeyHashes

-- | Ed25519 key hashes class
type Ed25519KeyHashesClass =
  { free :: Ed25519KeyHashes -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Ed25519KeyHashes -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Ed25519KeyHashes
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Ed25519KeyHashes -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Ed25519KeyHashes
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Ed25519KeyHashes -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Ed25519KeyHashes -> Ed25519KeyHashesJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Ed25519KeyHashes
    -- ^ From json
    -- > fromJson json
  , new :: Ed25519KeyHashes
    -- ^ New
    -- > new
  , len :: Ed25519KeyHashes -> Number
    -- ^ Len
    -- > len self
  , get :: Ed25519KeyHashes -> Number -> Ed25519KeyHash
    -- ^ Get
    -- > get self index
  , add :: Ed25519KeyHashes -> Ed25519KeyHash -> Effect Unit
    -- ^ Add
    -- > add self elem
  , toOption :: Ed25519KeyHashes -> Maybe Ed25519KeyHashes
    -- ^ To option
    -- > toOption self
  }

-- | Ed25519 key hashes class API
ed25519KeyHashes :: Ed25519KeyHashesClass
ed25519KeyHashes =
  { free: ed25519KeyHashes_free
  , toBytes: ed25519KeyHashes_toBytes
  , fromBytes: ed25519KeyHashes_fromBytes
  , toHex: ed25519KeyHashes_toHex
  , fromHex: ed25519KeyHashes_fromHex
  , toJson: ed25519KeyHashes_toJson
  , toJsValue: ed25519KeyHashes_toJsValue
  , fromJson: ed25519KeyHashes_fromJson
  , new: ed25519KeyHashes_new
  , len: ed25519KeyHashes_len
  , get: ed25519KeyHashes_get
  , add: ed25519KeyHashes_add
  , toOption: \a1 -> Nullable.toMaybe $ ed25519KeyHashes_toOption a1
  }

instance HasFree Ed25519KeyHashes where
  free = ed25519KeyHashes.free

instance Show Ed25519KeyHashes where
  show = ed25519KeyHashes.toHex

instance ToJsValue Ed25519KeyHashes where
  toJsValue = ed25519KeyHashes.toJsValue

instance IsHex Ed25519KeyHashes where
  toHex = ed25519KeyHashes.toHex
  fromHex = ed25519KeyHashes.fromHex

instance IsBytes Ed25519KeyHashes where
  toBytes = ed25519KeyHashes.toBytes
  fromBytes = ed25519KeyHashes.fromBytes

instance IsJson Ed25519KeyHashes where
  toJson = ed25519KeyHashes.toJson
  fromJson = ed25519KeyHashes.fromJson

-------------------------------------------------------------------------------------
-- Ed25519 signature

foreign import ed25519Signature_free :: Ed25519Signature -> Effect Unit
foreign import ed25519Signature_toBytes :: Ed25519Signature -> Bytes
foreign import ed25519Signature_toBech32 :: Ed25519Signature -> String
foreign import ed25519Signature_toHex :: Ed25519Signature -> String
foreign import ed25519Signature_fromBech32 :: String -> Ed25519Signature
foreign import ed25519Signature_fromHex :: String -> Ed25519Signature
foreign import ed25519Signature_fromBytes :: Bytes -> Ed25519Signature

-- | Ed25519 signature class
type Ed25519SignatureClass =
  { free :: Ed25519Signature -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Ed25519Signature -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , toBech32 :: Ed25519Signature -> String
    -- ^ To bech32
    -- > toBech32 self
  , toHex :: Ed25519Signature -> String
    -- ^ To hex
    -- > toHex self
  , fromBech32 :: String -> Ed25519Signature
    -- ^ From bech32
    -- > fromBech32 bech32Str
  , fromHex :: String -> Ed25519Signature
    -- ^ From hex
    -- > fromHex in
  , fromBytes :: Bytes -> Ed25519Signature
    -- ^ From bytes
    -- > fromBytes bytes
  }

-- | Ed25519 signature class API
ed25519Signature :: Ed25519SignatureClass
ed25519Signature =
  { free: ed25519Signature_free
  , toBytes: ed25519Signature_toBytes
  , toBech32: ed25519Signature_toBech32
  , toHex: ed25519Signature_toHex
  , fromBech32: ed25519Signature_fromBech32
  , fromHex: ed25519Signature_fromHex
  , fromBytes: ed25519Signature_fromBytes
  }

instance HasFree Ed25519Signature where
  free = ed25519Signature.free

instance Show Ed25519Signature where
  show = ed25519Signature.toHex

instance IsHex Ed25519Signature where
  toHex = ed25519Signature.toHex
  fromHex = ed25519Signature.fromHex

instance IsBech32 Ed25519Signature where
  toBech32 = ed25519Signature.toBech32
  fromBech32 = ed25519Signature.fromBech32

instance IsBytes Ed25519Signature where
  toBytes = ed25519Signature.toBytes
  fromBytes = ed25519Signature.fromBytes

-------------------------------------------------------------------------------------
-- Enterprise address

foreign import enterpriseAddress_free :: EnterpriseAddress -> Effect Unit
foreign import enterpriseAddress_new :: Number -> StakeCredential -> EnterpriseAddress
foreign import enterpriseAddress_paymentCred :: EnterpriseAddress -> StakeCredential
foreign import enterpriseAddress_toAddress :: EnterpriseAddress -> Address
foreign import enterpriseAddress_fromAddress :: Address -> Nullable EnterpriseAddress

-- | Enterprise address class
type EnterpriseAddressClass =
  { free :: EnterpriseAddress -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: Number -> StakeCredential -> EnterpriseAddress
    -- ^ New
    -- > new network payment
  , paymentCred :: EnterpriseAddress -> StakeCredential
    -- ^ Payment cred
    -- > paymentCred self
  , toAddress :: EnterpriseAddress -> Address
    -- ^ To address
    -- > toAddress self
  , fromAddress :: Address -> Maybe EnterpriseAddress
    -- ^ From address
    -- > fromAddress addr
  }

-- | Enterprise address class API
enterpriseAddress :: EnterpriseAddressClass
enterpriseAddress =
  { free: enterpriseAddress_free
  , new: enterpriseAddress_new
  , paymentCred: enterpriseAddress_paymentCred
  , toAddress: enterpriseAddress_toAddress
  , fromAddress: \a1 -> Nullable.toMaybe $ enterpriseAddress_fromAddress a1
  }

instance HasFree EnterpriseAddress where
  free = enterpriseAddress.free

-------------------------------------------------------------------------------------
-- Ex unit prices

foreign import exUnitPrices_free :: ExUnitPrices -> Effect Unit
foreign import exUnitPrices_toBytes :: ExUnitPrices -> Bytes
foreign import exUnitPrices_fromBytes :: Bytes -> ExUnitPrices
foreign import exUnitPrices_toHex :: ExUnitPrices -> String
foreign import exUnitPrices_fromHex :: String -> ExUnitPrices
foreign import exUnitPrices_toJson :: ExUnitPrices -> String
foreign import exUnitPrices_toJsValue :: ExUnitPrices -> ExUnitPricesJson
foreign import exUnitPrices_fromJson :: String -> ExUnitPrices
foreign import exUnitPrices_memPrice :: ExUnitPrices -> UnitInterval
foreign import exUnitPrices_stepPrice :: ExUnitPrices -> UnitInterval
foreign import exUnitPrices_new :: UnitInterval -> UnitInterval -> ExUnitPrices

-- | Ex unit prices class
type ExUnitPricesClass =
  { free :: ExUnitPrices -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: ExUnitPrices -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> ExUnitPrices
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: ExUnitPrices -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> ExUnitPrices
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: ExUnitPrices -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: ExUnitPrices -> ExUnitPricesJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> ExUnitPrices
    -- ^ From json
    -- > fromJson json
  , memPrice :: ExUnitPrices -> UnitInterval
    -- ^ Mem price
    -- > memPrice self
  , stepPrice :: ExUnitPrices -> UnitInterval
    -- ^ Step price
    -- > stepPrice self
  , new :: UnitInterval -> UnitInterval -> ExUnitPrices
    -- ^ New
    -- > new memPrice stepPrice
  }

-- | Ex unit prices class API
exUnitPrices :: ExUnitPricesClass
exUnitPrices =
  { free: exUnitPrices_free
  , toBytes: exUnitPrices_toBytes
  , fromBytes: exUnitPrices_fromBytes
  , toHex: exUnitPrices_toHex
  , fromHex: exUnitPrices_fromHex
  , toJson: exUnitPrices_toJson
  , toJsValue: exUnitPrices_toJsValue
  , fromJson: exUnitPrices_fromJson
  , memPrice: exUnitPrices_memPrice
  , stepPrice: exUnitPrices_stepPrice
  , new: exUnitPrices_new
  }

instance HasFree ExUnitPrices where
  free = exUnitPrices.free

instance Show ExUnitPrices where
  show = exUnitPrices.toHex

instance ToJsValue ExUnitPrices where
  toJsValue = exUnitPrices.toJsValue

instance IsHex ExUnitPrices where
  toHex = exUnitPrices.toHex
  fromHex = exUnitPrices.fromHex

instance IsBytes ExUnitPrices where
  toBytes = exUnitPrices.toBytes
  fromBytes = exUnitPrices.fromBytes

instance IsJson ExUnitPrices where
  toJson = exUnitPrices.toJson
  fromJson = exUnitPrices.fromJson

-------------------------------------------------------------------------------------
-- Ex units

foreign import exUnits_free :: ExUnits -> Effect Unit
foreign import exUnits_toBytes :: ExUnits -> Bytes
foreign import exUnits_fromBytes :: Bytes -> ExUnits
foreign import exUnits_toHex :: ExUnits -> String
foreign import exUnits_fromHex :: String -> ExUnits
foreign import exUnits_toJson :: ExUnits -> String
foreign import exUnits_toJsValue :: ExUnits -> ExUnitsJson
foreign import exUnits_fromJson :: String -> ExUnits
foreign import exUnits_mem :: ExUnits -> BigNum
foreign import exUnits_steps :: ExUnits -> BigNum
foreign import exUnits_new :: BigNum -> BigNum -> ExUnits

-- | Ex units class
type ExUnitsClass =
  { free :: ExUnits -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: ExUnits -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> ExUnits
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: ExUnits -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> ExUnits
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: ExUnits -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: ExUnits -> ExUnitsJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> ExUnits
    -- ^ From json
    -- > fromJson json
  , mem :: ExUnits -> BigNum
    -- ^ Mem
    -- > mem self
  , steps :: ExUnits -> BigNum
    -- ^ Steps
    -- > steps self
  , new :: BigNum -> BigNum -> ExUnits
    -- ^ New
    -- > new mem steps
  }

-- | Ex units class API
exUnits :: ExUnitsClass
exUnits =
  { free: exUnits_free
  , toBytes: exUnits_toBytes
  , fromBytes: exUnits_fromBytes
  , toHex: exUnits_toHex
  , fromHex: exUnits_fromHex
  , toJson: exUnits_toJson
  , toJsValue: exUnits_toJsValue
  , fromJson: exUnits_fromJson
  , mem: exUnits_mem
  , steps: exUnits_steps
  , new: exUnits_new
  }

instance HasFree ExUnits where
  free = exUnits.free

instance Show ExUnits where
  show = exUnits.toHex

instance ToJsValue ExUnits where
  toJsValue = exUnits.toJsValue

instance IsHex ExUnits where
  toHex = exUnits.toHex
  fromHex = exUnits.fromHex

instance IsBytes ExUnits where
  toBytes = exUnits.toBytes
  fromBytes = exUnits.fromBytes

instance IsJson ExUnits where
  toJson = exUnits.toJson
  fromJson = exUnits.fromJson

-------------------------------------------------------------------------------------
-- General transaction metadata

foreign import generalTxMetadata_free :: GeneralTxMetadata -> Effect Unit
foreign import generalTxMetadata_toBytes :: GeneralTxMetadata -> Bytes
foreign import generalTxMetadata_fromBytes :: Bytes -> GeneralTxMetadata
foreign import generalTxMetadata_toHex :: GeneralTxMetadata -> String
foreign import generalTxMetadata_fromHex :: String -> GeneralTxMetadata
foreign import generalTxMetadata_toJson :: GeneralTxMetadata -> String
foreign import generalTxMetadata_toJsValue :: GeneralTxMetadata -> GeneralTxMetadataJson
foreign import generalTxMetadata_fromJson :: String -> GeneralTxMetadata
foreign import generalTxMetadata_new :: Effect GeneralTxMetadata
foreign import generalTxMetadata_len :: GeneralTxMetadata -> Effect Int
foreign import generalTxMetadata_insert :: GeneralTxMetadata -> BigNum -> TxMetadatum -> Effect (Nullable TxMetadatum)
foreign import generalTxMetadata_get :: GeneralTxMetadata -> BigNum -> Effect (Nullable TxMetadatum)
foreign import generalTxMetadata_keys :: GeneralTxMetadata -> Effect TxMetadatumLabels

-- | General transaction metadata class
type GeneralTxMetadataClass =
  { free :: GeneralTxMetadata -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: GeneralTxMetadata -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> GeneralTxMetadata
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: GeneralTxMetadata -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> GeneralTxMetadata
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: GeneralTxMetadata -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: GeneralTxMetadata -> GeneralTxMetadataJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> GeneralTxMetadata
    -- ^ From json
    -- > fromJson json
  , new :: Effect GeneralTxMetadata
    -- ^ New
    -- > new
  , len :: GeneralTxMetadata -> Effect Int
    -- ^ Len
    -- > len self
  , insert :: GeneralTxMetadata -> BigNum -> TxMetadatum -> Effect (Maybe TxMetadatum)
    -- ^ Insert
    -- > insert self key value
  , get :: GeneralTxMetadata -> BigNum -> Effect (Maybe TxMetadatum)
    -- ^ Get
    -- > get self key
  , keys :: GeneralTxMetadata -> Effect TxMetadatumLabels
    -- ^ Keys
    -- > keys self
  }

-- | General transaction metadata class API
generalTxMetadata :: GeneralTxMetadataClass
generalTxMetadata =
  { free: generalTxMetadata_free
  , toBytes: generalTxMetadata_toBytes
  , fromBytes: generalTxMetadata_fromBytes
  , toHex: generalTxMetadata_toHex
  , fromHex: generalTxMetadata_fromHex
  , toJson: generalTxMetadata_toJson
  , toJsValue: generalTxMetadata_toJsValue
  , fromJson: generalTxMetadata_fromJson
  , new: generalTxMetadata_new
  , len: generalTxMetadata_len
  , insert: \a1 a2 a3 -> Nullable.toMaybe <$> generalTxMetadata_insert a1 a2 a3
  , get: \a1 a2 -> Nullable.toMaybe <$> generalTxMetadata_get a1 a2
  , keys: generalTxMetadata_keys
  }

instance HasFree GeneralTxMetadata where
  free = generalTxMetadata.free

instance Show GeneralTxMetadata where
  show = generalTxMetadata.toHex

instance ToJsValue GeneralTxMetadata where
  toJsValue = generalTxMetadata.toJsValue

instance IsHex GeneralTxMetadata where
  toHex = generalTxMetadata.toHex
  fromHex = generalTxMetadata.fromHex

instance IsBytes GeneralTxMetadata where
  toBytes = generalTxMetadata.toBytes
  fromBytes = generalTxMetadata.fromBytes

instance IsJson GeneralTxMetadata where
  toJson = generalTxMetadata.toJson
  fromJson = generalTxMetadata.fromJson

-------------------------------------------------------------------------------------
-- Genesis delegate hash

foreign import genesisDelegateHash_free :: GenesisDelegateHash -> Effect Unit
foreign import genesisDelegateHash_fromBytes :: Bytes -> GenesisDelegateHash
foreign import genesisDelegateHash_toBytes :: GenesisDelegateHash -> Bytes
foreign import genesisDelegateHash_toBech32 :: GenesisDelegateHash -> String -> String
foreign import genesisDelegateHash_fromBech32 :: String -> GenesisDelegateHash
foreign import genesisDelegateHash_toHex :: GenesisDelegateHash -> String
foreign import genesisDelegateHash_fromHex :: String -> GenesisDelegateHash

-- | Genesis delegate hash class
type GenesisDelegateHashClass =
  { free :: GenesisDelegateHash -> Effect Unit
    -- ^ Free
    -- > free self
  , fromBytes :: Bytes -> GenesisDelegateHash
    -- ^ From bytes
    -- > fromBytes bytes
  , toBytes :: GenesisDelegateHash -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , toBech32 :: GenesisDelegateHash -> String -> String
    -- ^ To bech32
    -- > toBech32 self prefix
  , fromBech32 :: String -> GenesisDelegateHash
    -- ^ From bech32
    -- > fromBech32 bechStr
  , toHex :: GenesisDelegateHash -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> GenesisDelegateHash
    -- ^ From hex
    -- > fromHex hex
  }

-- | Genesis delegate hash class API
genesisDelegateHash :: GenesisDelegateHashClass
genesisDelegateHash =
  { free: genesisDelegateHash_free
  , fromBytes: genesisDelegateHash_fromBytes
  , toBytes: genesisDelegateHash_toBytes
  , toBech32: genesisDelegateHash_toBech32
  , fromBech32: genesisDelegateHash_fromBech32
  , toHex: genesisDelegateHash_toHex
  , fromHex: genesisDelegateHash_fromHex
  }

instance HasFree GenesisDelegateHash where
  free = genesisDelegateHash.free

instance Show GenesisDelegateHash where
  show = genesisDelegateHash.toHex

instance IsHex GenesisDelegateHash where
  toHex = genesisDelegateHash.toHex
  fromHex = genesisDelegateHash.fromHex

instance IsBytes GenesisDelegateHash where
  toBytes = genesisDelegateHash.toBytes
  fromBytes = genesisDelegateHash.fromBytes

-------------------------------------------------------------------------------------
-- Genesis hash

foreign import genesisHash_free :: GenesisHash -> Effect Unit
foreign import genesisHash_fromBytes :: Bytes -> GenesisHash
foreign import genesisHash_toBytes :: GenesisHash -> Bytes
foreign import genesisHash_toBech32 :: GenesisHash -> String -> String
foreign import genesisHash_fromBech32 :: String -> GenesisHash
foreign import genesisHash_toHex :: GenesisHash -> String
foreign import genesisHash_fromHex :: String -> GenesisHash

-- | Genesis hash class
type GenesisHashClass =
  { free :: GenesisHash -> Effect Unit
    -- ^ Free
    -- > free self
  , fromBytes :: Bytes -> GenesisHash
    -- ^ From bytes
    -- > fromBytes bytes
  , toBytes :: GenesisHash -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , toBech32 :: GenesisHash -> String -> String
    -- ^ To bech32
    -- > toBech32 self prefix
  , fromBech32 :: String -> GenesisHash
    -- ^ From bech32
    -- > fromBech32 bechStr
  , toHex :: GenesisHash -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> GenesisHash
    -- ^ From hex
    -- > fromHex hex
  }

-- | Genesis hash class API
genesisHash :: GenesisHashClass
genesisHash =
  { free: genesisHash_free
  , fromBytes: genesisHash_fromBytes
  , toBytes: genesisHash_toBytes
  , toBech32: genesisHash_toBech32
  , fromBech32: genesisHash_fromBech32
  , toHex: genesisHash_toHex
  , fromHex: genesisHash_fromHex
  }

instance HasFree GenesisHash where
  free = genesisHash.free

instance Show GenesisHash where
  show = genesisHash.toHex

instance IsHex GenesisHash where
  toHex = genesisHash.toHex
  fromHex = genesisHash.fromHex

instance IsBytes GenesisHash where
  toBytes = genesisHash.toBytes
  fromBytes = genesisHash.fromBytes

-------------------------------------------------------------------------------------
-- Genesis hashes

foreign import genesisHashes_free :: GenesisHashes -> Effect Unit
foreign import genesisHashes_toBytes :: GenesisHashes -> Bytes
foreign import genesisHashes_fromBytes :: Bytes -> GenesisHashes
foreign import genesisHashes_toHex :: GenesisHashes -> String
foreign import genesisHashes_fromHex :: String -> GenesisHashes
foreign import genesisHashes_toJson :: GenesisHashes -> String
foreign import genesisHashes_toJsValue :: GenesisHashes -> GenesisHashesJson
foreign import genesisHashes_fromJson :: String -> GenesisHashes
foreign import genesisHashes_new :: Effect GenesisHashes
foreign import genesisHashes_len :: GenesisHashes -> Effect Int
foreign import genesisHashes_get :: GenesisHashes -> Int -> Effect GenesisHash
foreign import genesisHashes_add :: GenesisHashes -> GenesisHash -> Effect Unit

-- | Genesis hashes class
type GenesisHashesClass =
  { free :: GenesisHashes -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: GenesisHashes -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> GenesisHashes
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: GenesisHashes -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> GenesisHashes
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: GenesisHashes -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: GenesisHashes -> GenesisHashesJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> GenesisHashes
    -- ^ From json
    -- > fromJson json
  , new :: Effect GenesisHashes
    -- ^ New
    -- > new
  , len :: GenesisHashes -> Effect Int
    -- ^ Len
    -- > len self
  , get :: GenesisHashes -> Int -> Effect GenesisHash
    -- ^ Get
    -- > get self index
  , add :: GenesisHashes -> GenesisHash -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Genesis hashes class API
genesisHashes :: GenesisHashesClass
genesisHashes =
  { free: genesisHashes_free
  , toBytes: genesisHashes_toBytes
  , fromBytes: genesisHashes_fromBytes
  , toHex: genesisHashes_toHex
  , fromHex: genesisHashes_fromHex
  , toJson: genesisHashes_toJson
  , toJsValue: genesisHashes_toJsValue
  , fromJson: genesisHashes_fromJson
  , new: genesisHashes_new
  , len: genesisHashes_len
  , get: genesisHashes_get
  , add: genesisHashes_add
  }

instance HasFree GenesisHashes where
  free = genesisHashes.free

instance Show GenesisHashes where
  show = genesisHashes.toHex

instance MutableList GenesisHashes GenesisHash where
  addItem = genesisHashes.add
  getItem = genesisHashes.get
  emptyList = genesisHashes.new

instance MutableLen GenesisHashes where
  getLen = genesisHashes.len


instance ToJsValue GenesisHashes where
  toJsValue = genesisHashes.toJsValue

instance IsHex GenesisHashes where
  toHex = genesisHashes.toHex
  fromHex = genesisHashes.fromHex

instance IsBytes GenesisHashes where
  toBytes = genesisHashes.toBytes
  fromBytes = genesisHashes.fromBytes

instance IsJson GenesisHashes where
  toJson = genesisHashes.toJson
  fromJson = genesisHashes.fromJson

-------------------------------------------------------------------------------------
-- Genesis key delegation

foreign import genesisKeyDelegation_free :: GenesisKeyDelegation -> Effect Unit
foreign import genesisKeyDelegation_toBytes :: GenesisKeyDelegation -> Bytes
foreign import genesisKeyDelegation_fromBytes :: Bytes -> GenesisKeyDelegation
foreign import genesisKeyDelegation_toHex :: GenesisKeyDelegation -> String
foreign import genesisKeyDelegation_fromHex :: String -> GenesisKeyDelegation
foreign import genesisKeyDelegation_toJson :: GenesisKeyDelegation -> String
foreign import genesisKeyDelegation_toJsValue :: GenesisKeyDelegation -> GenesisKeyDelegationJson
foreign import genesisKeyDelegation_fromJson :: String -> GenesisKeyDelegation
foreign import genesisKeyDelegation_genesishash :: GenesisKeyDelegation -> GenesisHash
foreign import genesisKeyDelegation_genesisDelegateHash :: GenesisKeyDelegation -> GenesisDelegateHash
foreign import genesisKeyDelegation_vrfKeyhash :: GenesisKeyDelegation -> VRFKeyHash
foreign import genesisKeyDelegation_new :: GenesisHash -> GenesisDelegateHash -> VRFKeyHash -> GenesisKeyDelegation

-- | Genesis key delegation class
type GenesisKeyDelegationClass =
  { free :: GenesisKeyDelegation -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: GenesisKeyDelegation -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> GenesisKeyDelegation
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: GenesisKeyDelegation -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> GenesisKeyDelegation
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: GenesisKeyDelegation -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: GenesisKeyDelegation -> GenesisKeyDelegationJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> GenesisKeyDelegation
    -- ^ From json
    -- > fromJson json
  , genesishash :: GenesisKeyDelegation -> GenesisHash
    -- ^ Genesishash
    -- > genesishash self
  , genesisDelegateHash :: GenesisKeyDelegation -> GenesisDelegateHash
    -- ^ Genesis delegate hash
    -- > genesisDelegateHash self
  , vrfKeyhash :: GenesisKeyDelegation -> VRFKeyHash
    -- ^ Vrf keyhash
    -- > vrfKeyhash self
  , new :: GenesisHash -> GenesisDelegateHash -> VRFKeyHash -> GenesisKeyDelegation
    -- ^ New
    -- > new genesishash genesisDelegateHash vrfKeyhash
  }

-- | Genesis key delegation class API
genesisKeyDelegation :: GenesisKeyDelegationClass
genesisKeyDelegation =
  { free: genesisKeyDelegation_free
  , toBytes: genesisKeyDelegation_toBytes
  , fromBytes: genesisKeyDelegation_fromBytes
  , toHex: genesisKeyDelegation_toHex
  , fromHex: genesisKeyDelegation_fromHex
  , toJson: genesisKeyDelegation_toJson
  , toJsValue: genesisKeyDelegation_toJsValue
  , fromJson: genesisKeyDelegation_fromJson
  , genesishash: genesisKeyDelegation_genesishash
  , genesisDelegateHash: genesisKeyDelegation_genesisDelegateHash
  , vrfKeyhash: genesisKeyDelegation_vrfKeyhash
  , new: genesisKeyDelegation_new
  }

instance HasFree GenesisKeyDelegation where
  free = genesisKeyDelegation.free

instance Show GenesisKeyDelegation where
  show = genesisKeyDelegation.toHex

instance ToJsValue GenesisKeyDelegation where
  toJsValue = genesisKeyDelegation.toJsValue

instance IsHex GenesisKeyDelegation where
  toHex = genesisKeyDelegation.toHex
  fromHex = genesisKeyDelegation.fromHex

instance IsBytes GenesisKeyDelegation where
  toBytes = genesisKeyDelegation.toBytes
  fromBytes = genesisKeyDelegation.fromBytes

instance IsJson GenesisKeyDelegation where
  toJson = genesisKeyDelegation.toJson
  fromJson = genesisKeyDelegation.fromJson

-------------------------------------------------------------------------------------
-- Header

foreign import header_free :: Header -> Effect Unit
foreign import header_toBytes :: Header -> Bytes
foreign import header_fromBytes :: Bytes -> Header
foreign import header_toHex :: Header -> String
foreign import header_fromHex :: String -> Header
foreign import header_toJson :: Header -> String
foreign import header_toJsValue :: Header -> HeaderJson
foreign import header_fromJson :: String -> Header
foreign import header_headerBody :: Header -> HeaderBody
foreign import header_bodySignature :: Header -> KESSignature
foreign import header_new :: HeaderBody -> KESSignature -> Header

-- | Header class
type HeaderClass =
  { free :: Header -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Header -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Header
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Header -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Header
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Header -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Header -> HeaderJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Header
    -- ^ From json
    -- > fromJson json
  , headerBody :: Header -> HeaderBody
    -- ^ Header body
    -- > headerBody self
  , bodySignature :: Header -> KESSignature
    -- ^ Body signature
    -- > bodySignature self
  , new :: HeaderBody -> KESSignature -> Header
    -- ^ New
    -- > new headerBody bodySignature
  }

-- | Header class API
header :: HeaderClass
header =
  { free: header_free
  , toBytes: header_toBytes
  , fromBytes: header_fromBytes
  , toHex: header_toHex
  , fromHex: header_fromHex
  , toJson: header_toJson
  , toJsValue: header_toJsValue
  , fromJson: header_fromJson
  , headerBody: header_headerBody
  , bodySignature: header_bodySignature
  , new: header_new
  }

instance HasFree Header where
  free = header.free

instance Show Header where
  show = header.toHex

instance ToJsValue Header where
  toJsValue = header.toJsValue

instance IsHex Header where
  toHex = header.toHex
  fromHex = header.fromHex

instance IsBytes Header where
  toBytes = header.toBytes
  fromBytes = header.fromBytes

instance IsJson Header where
  toJson = header.toJson
  fromJson = header.fromJson

-------------------------------------------------------------------------------------
-- Header body

foreign import headerBody_free :: HeaderBody -> Effect Unit
foreign import headerBody_toBytes :: HeaderBody -> Bytes
foreign import headerBody_fromBytes :: Bytes -> HeaderBody
foreign import headerBody_toHex :: HeaderBody -> String
foreign import headerBody_fromHex :: String -> HeaderBody
foreign import headerBody_toJson :: HeaderBody -> String
foreign import headerBody_toJsValue :: HeaderBody -> HeaderBodyJson
foreign import headerBody_fromJson :: String -> HeaderBody
foreign import headerBody_blockNumber :: HeaderBody -> Int
foreign import headerBody_slot :: HeaderBody -> Int
foreign import headerBody_slotBignum :: HeaderBody -> BigNum
foreign import headerBody_prevHash :: HeaderBody -> Nullable BlockHash
foreign import headerBody_issuerVkey :: HeaderBody -> Vkey
foreign import headerBody_vrfVkey :: HeaderBody -> VRFVKey
foreign import headerBody_hasNonceAndLeaderVrf :: HeaderBody -> Boolean
foreign import headerBody_nonceVrfOrNothing :: HeaderBody -> Nullable VRFCert
foreign import headerBody_leaderVrfOrNothing :: HeaderBody -> Nullable VRFCert
foreign import headerBody_hasVrfResult :: HeaderBody -> Boolean
foreign import headerBody_vrfResultOrNothing :: HeaderBody -> Nullable VRFCert
foreign import headerBody_blockBodySize :: HeaderBody -> Int
foreign import headerBody_blockBodyHash :: HeaderBody -> BlockHash
foreign import headerBody_operationalCert :: HeaderBody -> OperationalCert
foreign import headerBody_protocolVersion :: HeaderBody -> ProtocolVersion
foreign import headerBody_new :: Int -> Int -> Nullable BlockHash -> Vkey -> VRFVKey -> VRFCert -> Int -> BlockHash -> OperationalCert -> ProtocolVersion -> HeaderBody
foreign import headerBody_newHeaderbody :: Number -> BigNum -> Nullable BlockHash -> Vkey -> VRFVKey -> VRFCert -> Number -> BlockHash -> OperationalCert -> ProtocolVersion -> HeaderBody

-- | Header body class
type HeaderBodyClass =
  { free :: HeaderBody -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: HeaderBody -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> HeaderBody
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: HeaderBody -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> HeaderBody
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: HeaderBody -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: HeaderBody -> HeaderBodyJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> HeaderBody
    -- ^ From json
    -- > fromJson json
  , blockNumber :: HeaderBody -> Int
    -- ^ Block number
    -- > blockNumber self
  , slot :: HeaderBody -> Int
    -- ^ Slot
    -- > slot self
  , slotBignum :: HeaderBody -> BigNum
    -- ^ Slot bignum
    -- > slotBignum self
  , prevHash :: HeaderBody -> Maybe BlockHash
    -- ^ Prev hash
    -- > prevHash self
  , issuerVkey :: HeaderBody -> Vkey
    -- ^ Issuer vkey
    -- > issuerVkey self
  , vrfVkey :: HeaderBody -> VRFVKey
    -- ^ Vrf vkey
    -- > vrfVkey self
  , hasNonceAndLeaderVrf :: HeaderBody -> Boolean
    -- ^ Has nonce and leader vrf
    -- > hasNonceAndLeaderVrf self
  , nonceVrfOrNothing :: HeaderBody -> Maybe VRFCert
    -- ^ Nonce vrf or nothing
    -- > nonceVrfOrNothing self
  , leaderVrfOrNothing :: HeaderBody -> Maybe VRFCert
    -- ^ Leader vrf or nothing
    -- > leaderVrfOrNothing self
  , hasVrfResult :: HeaderBody -> Boolean
    -- ^ Has vrf result
    -- > hasVrfResult self
  , vrfResultOrNothing :: HeaderBody -> Maybe VRFCert
    -- ^ Vrf result or nothing
    -- > vrfResultOrNothing self
  , blockBodySize :: HeaderBody -> Int
    -- ^ Block body size
    -- > blockBodySize self
  , blockBodyHash :: HeaderBody -> BlockHash
    -- ^ Block body hash
    -- > blockBodyHash self
  , operationalCert :: HeaderBody -> OperationalCert
    -- ^ Operational cert
    -- > operationalCert self
  , protocolVersion :: HeaderBody -> ProtocolVersion
    -- ^ Protocol version
    -- > protocolVersion self
  , new :: Int -> Int -> Maybe BlockHash -> Vkey -> VRFVKey -> VRFCert -> Int -> BlockHash -> OperationalCert -> ProtocolVersion -> HeaderBody
    -- ^ New
    -- > new blockNumber slot prevHash issuerVkey vrfVkey vrfResult blockBodySize blockBodyHash operationalCert protocolVersion
  , newHeaderbody :: Number -> BigNum -> Maybe BlockHash -> Vkey -> VRFVKey -> VRFCert -> Number -> BlockHash -> OperationalCert -> ProtocolVersion -> HeaderBody
    -- ^ New headerbody
    -- > newHeaderbody blockNumber slot prevHash issuerVkey vrfVkey vrfResult blockBodySize blockBodyHash operationalCert protocolVersion
  }

-- | Header body class API
headerBody :: HeaderBodyClass
headerBody =
  { free: headerBody_free
  , toBytes: headerBody_toBytes
  , fromBytes: headerBody_fromBytes
  , toHex: headerBody_toHex
  , fromHex: headerBody_fromHex
  , toJson: headerBody_toJson
  , toJsValue: headerBody_toJsValue
  , fromJson: headerBody_fromJson
  , blockNumber: headerBody_blockNumber
  , slot: headerBody_slot
  , slotBignum: headerBody_slotBignum
  , prevHash: \a1 -> Nullable.toMaybe $ headerBody_prevHash a1
  , issuerVkey: headerBody_issuerVkey
  , vrfVkey: headerBody_vrfVkey
  , hasNonceAndLeaderVrf: headerBody_hasNonceAndLeaderVrf
  , nonceVrfOrNothing: \a1 -> Nullable.toMaybe $ headerBody_nonceVrfOrNothing a1
  , leaderVrfOrNothing: \a1 -> Nullable.toMaybe $ headerBody_leaderVrfOrNothing a1
  , hasVrfResult: headerBody_hasVrfResult
  , vrfResultOrNothing: \a1 -> Nullable.toMaybe $ headerBody_vrfResultOrNothing a1
  , blockBodySize: headerBody_blockBodySize
  , blockBodyHash: headerBody_blockBodyHash
  , operationalCert: headerBody_operationalCert
  , protocolVersion: headerBody_protocolVersion
  , new: \a1 a2 a3 a4 a5 a6 a7 a8 a9 a10 -> headerBody_new a1 a2 (Nullable.toNullable a3) a4 a5 a6 a7 a8 a9 a10
  , newHeaderbody: \a1 a2 a3 a4 a5 a6 a7 a8 a9 a10 -> headerBody_newHeaderbody a1 a2 (Nullable.toNullable a3) a4 a5 a6 a7 a8 a9 a10
  }

instance HasFree HeaderBody where
  free = headerBody.free

instance Show HeaderBody where
  show = headerBody.toHex

instance ToJsValue HeaderBody where
  toJsValue = headerBody.toJsValue

instance IsHex HeaderBody where
  toHex = headerBody.toHex
  fromHex = headerBody.fromHex

instance IsBytes HeaderBody where
  toBytes = headerBody.toBytes
  fromBytes = headerBody.fromBytes

instance IsJson HeaderBody where
  toJson = headerBody.toJson
  fromJson = headerBody.fromJson

-------------------------------------------------------------------------------------
-- Int

foreign import int_free :: Int -> Effect Unit
foreign import int_toBytes :: Int -> Bytes
foreign import int_fromBytes :: Bytes -> Int
foreign import int_toHex :: Int -> String
foreign import int_fromHex :: String -> Int
foreign import int_toJson :: Int -> String
foreign import int_toJsValue :: Int -> IntJson
foreign import int_fromJson :: String -> Int
foreign import int_new :: BigNum -> Int
foreign import int_newNegative :: BigNum -> Int
foreign import int_newI32 :: Number -> Int
foreign import int_isPositive :: Int -> Boolean
foreign import int_asPositive :: Int -> Nullable BigNum
foreign import int_asNegative :: Int -> Nullable BigNum
foreign import int_asI32 :: Int -> Nullable Number
foreign import int_asI32OrNothing :: Int -> Nullable Number
foreign import int_asI32OrFail :: Int -> Number
foreign import int_toStr :: Int -> String
foreign import int_fromStr :: String -> Int

-- | Int class
type IntClass =
  { free :: Int -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Int -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Int
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Int -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Int
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Int -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Int -> IntJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Int
    -- ^ From json
    -- > fromJson json
  , new :: BigNum -> Int
    -- ^ New
    -- > new x
  , newNegative :: BigNum -> Int
    -- ^ New negative
    -- > newNegative x
  , newI32 :: Number -> Int
    -- ^ New i32
    -- > newI32 x
  , isPositive :: Int -> Boolean
    -- ^ Is positive
    -- > isPositive self
  , asPositive :: Int -> Maybe BigNum
    -- ^ As positive
    -- > asPositive self
  , asNegative :: Int -> Maybe BigNum
    -- ^ As negative
    -- > asNegative self
  , asI32 :: Int -> Maybe Number
    -- ^ As i32
    -- > asI32 self
  , asI32OrNothing :: Int -> Maybe Number
    -- ^ As i32 or nothing
    -- > asI32OrNothing self
  , asI32OrFail :: Int -> Number
    -- ^ As i32 or fail
    -- > asI32OrFail self
  , toStr :: Int -> String
    -- ^ To str
    -- > toStr self
  , fromStr :: String -> Int
    -- ^ From str
    -- > fromStr string
  }

-- | Int class API
int :: IntClass
int =
  { free: int_free
  , toBytes: int_toBytes
  , fromBytes: int_fromBytes
  , toHex: int_toHex
  , fromHex: int_fromHex
  , toJson: int_toJson
  , toJsValue: int_toJsValue
  , fromJson: int_fromJson
  , new: int_new
  , newNegative: int_newNegative
  , newI32: int_newI32
  , isPositive: int_isPositive
  , asPositive: \a1 -> Nullable.toMaybe $ int_asPositive a1
  , asNegative: \a1 -> Nullable.toMaybe $ int_asNegative a1
  , asI32: \a1 -> Nullable.toMaybe $ int_asI32 a1
  , asI32OrNothing: \a1 -> Nullable.toMaybe $ int_asI32OrNothing a1
  , asI32OrFail: int_asI32OrFail
  , toStr: int_toStr
  , fromStr: int_fromStr
  }



-------------------------------------------------------------------------------------
-- Ipv4

foreign import ipv4_free :: Ipv4 -> Effect Unit
foreign import ipv4_toBytes :: Ipv4 -> Bytes
foreign import ipv4_fromBytes :: Bytes -> Ipv4
foreign import ipv4_toHex :: Ipv4 -> String
foreign import ipv4_fromHex :: String -> Ipv4
foreign import ipv4_toJson :: Ipv4 -> String
foreign import ipv4_toJsValue :: Ipv4 -> Ipv4Json
foreign import ipv4_fromJson :: String -> Ipv4
foreign import ipv4_new :: Bytes -> Ipv4
foreign import ipv4_ip :: Ipv4 -> Bytes

-- | Ipv4 class
type Ipv4Class =
  { free :: Ipv4 -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Ipv4 -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Ipv4
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Ipv4 -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Ipv4
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Ipv4 -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Ipv4 -> Ipv4Json
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Ipv4
    -- ^ From json
    -- > fromJson json
  , new :: Bytes -> Ipv4
    -- ^ New
    -- > new data
  , ip :: Ipv4 -> Bytes
    -- ^ Ip
    -- > ip self
  }

-- | Ipv4 class API
ipv4 :: Ipv4Class
ipv4 =
  { free: ipv4_free
  , toBytes: ipv4_toBytes
  , fromBytes: ipv4_fromBytes
  , toHex: ipv4_toHex
  , fromHex: ipv4_fromHex
  , toJson: ipv4_toJson
  , toJsValue: ipv4_toJsValue
  , fromJson: ipv4_fromJson
  , new: ipv4_new
  , ip: ipv4_ip
  }

instance HasFree Ipv4 where
  free = ipv4.free

instance Show Ipv4 where
  show = ipv4.toHex

instance ToJsValue Ipv4 where
  toJsValue = ipv4.toJsValue

instance IsHex Ipv4 where
  toHex = ipv4.toHex
  fromHex = ipv4.fromHex

instance IsBytes Ipv4 where
  toBytes = ipv4.toBytes
  fromBytes = ipv4.fromBytes

instance IsJson Ipv4 where
  toJson = ipv4.toJson
  fromJson = ipv4.fromJson

-------------------------------------------------------------------------------------
-- Ipv6

foreign import ipv6_free :: Ipv6 -> Effect Unit
foreign import ipv6_toBytes :: Ipv6 -> Bytes
foreign import ipv6_fromBytes :: Bytes -> Ipv6
foreign import ipv6_toHex :: Ipv6 -> String
foreign import ipv6_fromHex :: String -> Ipv6
foreign import ipv6_toJson :: Ipv6 -> String
foreign import ipv6_toJsValue :: Ipv6 -> Ipv6Json
foreign import ipv6_fromJson :: String -> Ipv6
foreign import ipv6_new :: Bytes -> Ipv6
foreign import ipv6_ip :: Ipv6 -> Bytes

-- | Ipv6 class
type Ipv6Class =
  { free :: Ipv6 -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Ipv6 -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Ipv6
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Ipv6 -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Ipv6
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Ipv6 -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Ipv6 -> Ipv6Json
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Ipv6
    -- ^ From json
    -- > fromJson json
  , new :: Bytes -> Ipv6
    -- ^ New
    -- > new data
  , ip :: Ipv6 -> Bytes
    -- ^ Ip
    -- > ip self
  }

-- | Ipv6 class API
ipv6 :: Ipv6Class
ipv6 =
  { free: ipv6_free
  , toBytes: ipv6_toBytes
  , fromBytes: ipv6_fromBytes
  , toHex: ipv6_toHex
  , fromHex: ipv6_fromHex
  , toJson: ipv6_toJson
  , toJsValue: ipv6_toJsValue
  , fromJson: ipv6_fromJson
  , new: ipv6_new
  , ip: ipv6_ip
  }

instance HasFree Ipv6 where
  free = ipv6.free

instance Show Ipv6 where
  show = ipv6.toHex

instance ToJsValue Ipv6 where
  toJsValue = ipv6.toJsValue

instance IsHex Ipv6 where
  toHex = ipv6.toHex
  fromHex = ipv6.fromHex

instance IsBytes Ipv6 where
  toBytes = ipv6.toBytes
  fromBytes = ipv6.fromBytes

instance IsJson Ipv6 where
  toJson = ipv6.toJson
  fromJson = ipv6.fromJson

-------------------------------------------------------------------------------------
-- KESSignature

foreign import kesSignature_free :: KESSignature -> Effect Unit
foreign import kesSignature_toBytes :: KESSignature -> Bytes
foreign import kesSignature_fromBytes :: Bytes -> KESSignature

-- | KESSignature class
type KESSignatureClass =
  { free :: KESSignature -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: KESSignature -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> KESSignature
    -- ^ From bytes
    -- > fromBytes bytes
  }

-- | KESSignature class API
kesSignature :: KESSignatureClass
kesSignature =
  { free: kesSignature_free
  , toBytes: kesSignature_toBytes
  , fromBytes: kesSignature_fromBytes
  }

instance HasFree KESSignature where
  free = kesSignature.free

instance IsBytes KESSignature where
  toBytes = kesSignature.toBytes
  fromBytes = kesSignature.fromBytes

-------------------------------------------------------------------------------------
-- KESVKey

foreign import kesvKey_free :: KESVKey -> Effect Unit
foreign import kesvKey_fromBytes :: Bytes -> KESVKey
foreign import kesvKey_toBytes :: KESVKey -> Bytes
foreign import kesvKey_toBech32 :: KESVKey -> String -> String
foreign import kesvKey_fromBech32 :: String -> KESVKey
foreign import kesvKey_toHex :: KESVKey -> String
foreign import kesvKey_fromHex :: String -> KESVKey

-- | KESVKey class
type KESVKeyClass =
  { free :: KESVKey -> Effect Unit
    -- ^ Free
    -- > free self
  , fromBytes :: Bytes -> KESVKey
    -- ^ From bytes
    -- > fromBytes bytes
  , toBytes :: KESVKey -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , toBech32 :: KESVKey -> String -> String
    -- ^ To bech32
    -- > toBech32 self prefix
  , fromBech32 :: String -> KESVKey
    -- ^ From bech32
    -- > fromBech32 bechStr
  , toHex :: KESVKey -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> KESVKey
    -- ^ From hex
    -- > fromHex hex
  }

-- | KESVKey class API
kesvKey :: KESVKeyClass
kesvKey =
  { free: kesvKey_free
  , fromBytes: kesvKey_fromBytes
  , toBytes: kesvKey_toBytes
  , toBech32: kesvKey_toBech32
  , fromBech32: kesvKey_fromBech32
  , toHex: kesvKey_toHex
  , fromHex: kesvKey_fromHex
  }

instance HasFree KESVKey where
  free = kesvKey.free

instance Show KESVKey where
  show = kesvKey.toHex

instance IsHex KESVKey where
  toHex = kesvKey.toHex
  fromHex = kesvKey.fromHex

instance IsBytes KESVKey where
  toBytes = kesvKey.toBytes
  fromBytes = kesvKey.fromBytes

-------------------------------------------------------------------------------------
-- Language

foreign import language_free :: Language -> Effect Unit
foreign import language_toBytes :: Language -> Bytes
foreign import language_fromBytes :: Bytes -> Language
foreign import language_toHex :: Language -> String
foreign import language_fromHex :: String -> Language
foreign import language_toJson :: Language -> String
foreign import language_toJsValue :: Language -> LanguageJson
foreign import language_fromJson :: String -> Language
foreign import language_newPlutusV1 :: Language
foreign import language_newPlutusV2 :: Language
foreign import language_kind :: Language -> Number

-- | Language class
type LanguageClass =
  { free :: Language -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Language -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Language
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Language -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Language
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Language -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Language -> LanguageJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Language
    -- ^ From json
    -- > fromJson json
  , newPlutusV1 :: Language
    -- ^ New plutus v1
    -- > newPlutusV1
  , newPlutusV2 :: Language
    -- ^ New plutus v2
    -- > newPlutusV2
  , kind :: Language -> Number
    -- ^ Kind
    -- > kind self
  }

-- | Language class API
language :: LanguageClass
language =
  { free: language_free
  , toBytes: language_toBytes
  , fromBytes: language_fromBytes
  , toHex: language_toHex
  , fromHex: language_fromHex
  , toJson: language_toJson
  , toJsValue: language_toJsValue
  , fromJson: language_fromJson
  , newPlutusV1: language_newPlutusV1
  , newPlutusV2: language_newPlutusV2
  , kind: language_kind
  }

instance HasFree Language where
  free = language.free

instance Show Language where
  show = language.toHex

instance ToJsValue Language where
  toJsValue = language.toJsValue

instance IsHex Language where
  toHex = language.toHex
  fromHex = language.fromHex

instance IsBytes Language where
  toBytes = language.toBytes
  fromBytes = language.fromBytes

instance IsJson Language where
  toJson = language.toJson
  fromJson = language.fromJson

-------------------------------------------------------------------------------------
-- Languages

foreign import languages_free :: Languages -> Effect Unit
foreign import languages_new :: Effect Languages
foreign import languages_len :: Languages -> Effect Int
foreign import languages_get :: Languages -> Int -> Effect Language
foreign import languages_add :: Languages -> Language -> Effect Unit

-- | Languages class
type LanguagesClass =
  { free :: Languages -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: Effect Languages
    -- ^ New
    -- > new
  , len :: Languages -> Effect Int
    -- ^ Len
    -- > len self
  , get :: Languages -> Int -> Effect Language
    -- ^ Get
    -- > get self index
  , add :: Languages -> Language -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Languages class API
languages :: LanguagesClass
languages =
  { free: languages_free
  , new: languages_new
  , len: languages_len
  , get: languages_get
  , add: languages_add
  }

instance HasFree Languages where
  free = languages.free

instance MutableList Languages Language where
  addItem = languages.add
  getItem = languages.get
  emptyList = languages.new

instance MutableLen Languages where
  getLen = languages.len

-------------------------------------------------------------------------------------
-- Legacy daedalus private key

foreign import legacyDaedalusPrivateKey_free :: LegacyDaedalusPrivateKey -> Effect Unit
foreign import legacyDaedalusPrivateKey_fromBytes :: Bytes -> LegacyDaedalusPrivateKey
foreign import legacyDaedalusPrivateKey_asBytes :: LegacyDaedalusPrivateKey -> Bytes
foreign import legacyDaedalusPrivateKey_chaincode :: LegacyDaedalusPrivateKey -> Bytes

-- | Legacy daedalus private key class
type LegacyDaedalusPrivateKeyClass =
  { free :: LegacyDaedalusPrivateKey -> Effect Unit
    -- ^ Free
    -- > free self
  , fromBytes :: Bytes -> LegacyDaedalusPrivateKey
    -- ^ From bytes
    -- > fromBytes bytes
  , asBytes :: LegacyDaedalusPrivateKey -> Bytes
    -- ^ As bytes
    -- > asBytes self
  , chaincode :: LegacyDaedalusPrivateKey -> Bytes
    -- ^ Chaincode
    -- > chaincode self
  }

-- | Legacy daedalus private key class API
legacyDaedalusPrivateKey :: LegacyDaedalusPrivateKeyClass
legacyDaedalusPrivateKey =
  { free: legacyDaedalusPrivateKey_free
  , fromBytes: legacyDaedalusPrivateKey_fromBytes
  , asBytes: legacyDaedalusPrivateKey_asBytes
  , chaincode: legacyDaedalusPrivateKey_chaincode
  }

instance HasFree LegacyDaedalusPrivateKey where
  free = legacyDaedalusPrivateKey.free

-------------------------------------------------------------------------------------
-- Linear fee

foreign import linearFee_free :: LinearFee -> Effect Unit
foreign import linearFee_constant :: LinearFee -> BigNum
foreign import linearFee_coefficient :: LinearFee -> BigNum
foreign import linearFee_new :: BigNum -> BigNum -> LinearFee

-- | Linear fee class
type LinearFeeClass =
  { free :: LinearFee -> Effect Unit
    -- ^ Free
    -- > free self
  , constant :: LinearFee -> BigNum
    -- ^ Constant
    -- > constant self
  , coefficient :: LinearFee -> BigNum
    -- ^ Coefficient
    -- > coefficient self
  , new :: BigNum -> BigNum -> LinearFee
    -- ^ New
    -- > new coefficient constant
  }

-- | Linear fee class API
linearFee :: LinearFeeClass
linearFee =
  { free: linearFee_free
  , constant: linearFee_constant
  , coefficient: linearFee_coefficient
  , new: linearFee_new
  }

instance HasFree LinearFee where
  free = linearFee.free

-------------------------------------------------------------------------------------
-- MIRTo stake credentials

foreign import mirToStakeCredentials_free :: MIRToStakeCredentials -> Effect Unit
foreign import mirToStakeCredentials_toBytes :: MIRToStakeCredentials -> Bytes
foreign import mirToStakeCredentials_fromBytes :: Bytes -> MIRToStakeCredentials
foreign import mirToStakeCredentials_toHex :: MIRToStakeCredentials -> String
foreign import mirToStakeCredentials_fromHex :: String -> MIRToStakeCredentials
foreign import mirToStakeCredentials_toJson :: MIRToStakeCredentials -> String
foreign import mirToStakeCredentials_toJsValue :: MIRToStakeCredentials -> MIRToStakeCredentialsJson
foreign import mirToStakeCredentials_fromJson :: String -> MIRToStakeCredentials
foreign import mirToStakeCredentials_new :: Effect MIRToStakeCredentials
foreign import mirToStakeCredentials_len :: MIRToStakeCredentials -> Effect Number
foreign import mirToStakeCredentials_insert :: MIRToStakeCredentials -> StakeCredential -> Int -> Effect (Nullable Int)
foreign import mirToStakeCredentials_get :: MIRToStakeCredentials -> StakeCredential -> Effect (Nullable Int)
foreign import mirToStakeCredentials_keys :: MIRToStakeCredentials -> Effect StakeCredentials

-- | MIRTo stake credentials class
type MIRToStakeCredentialsClass =
  { free :: MIRToStakeCredentials -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: MIRToStakeCredentials -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> MIRToStakeCredentials
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: MIRToStakeCredentials -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> MIRToStakeCredentials
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: MIRToStakeCredentials -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: MIRToStakeCredentials -> MIRToStakeCredentialsJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> MIRToStakeCredentials
    -- ^ From json
    -- > fromJson json
  , new :: Effect MIRToStakeCredentials
    -- ^ New
    -- > new
  , len :: MIRToStakeCredentials -> Effect Number
    -- ^ Len
    -- > len self
  , insert :: MIRToStakeCredentials -> StakeCredential -> Int -> Effect (Maybe Int)
    -- ^ Insert
    -- > insert self cred delta
  , get :: MIRToStakeCredentials -> StakeCredential -> Effect (Maybe Int)
    -- ^ Get
    -- > get self cred
  , keys :: MIRToStakeCredentials -> Effect StakeCredentials
    -- ^ Keys
    -- > keys self
  }

-- | MIRTo stake credentials class API
mirToStakeCredentials :: MIRToStakeCredentialsClass
mirToStakeCredentials =
  { free: mirToStakeCredentials_free
  , toBytes: mirToStakeCredentials_toBytes
  , fromBytes: mirToStakeCredentials_fromBytes
  , toHex: mirToStakeCredentials_toHex
  , fromHex: mirToStakeCredentials_fromHex
  , toJson: mirToStakeCredentials_toJson
  , toJsValue: mirToStakeCredentials_toJsValue
  , fromJson: mirToStakeCredentials_fromJson
  , new: mirToStakeCredentials_new
  , len: mirToStakeCredentials_len
  , insert: \a1 a2 a3 -> Nullable.toMaybe <$> mirToStakeCredentials_insert a1 a2 a3
  , get: \a1 a2 -> Nullable.toMaybe <$> mirToStakeCredentials_get a1 a2
  , keys: mirToStakeCredentials_keys
  }

instance HasFree MIRToStakeCredentials where
  free = mirToStakeCredentials.free

instance Show MIRToStakeCredentials where
  show = mirToStakeCredentials.toHex

instance ToJsValue MIRToStakeCredentials where
  toJsValue = mirToStakeCredentials.toJsValue

instance IsHex MIRToStakeCredentials where
  toHex = mirToStakeCredentials.toHex
  fromHex = mirToStakeCredentials.fromHex

instance IsBytes MIRToStakeCredentials where
  toBytes = mirToStakeCredentials.toBytes
  fromBytes = mirToStakeCredentials.fromBytes

instance IsJson MIRToStakeCredentials where
  toJson = mirToStakeCredentials.toJson
  fromJson = mirToStakeCredentials.fromJson

-------------------------------------------------------------------------------------
-- Metadata list

foreign import metadataList_free :: MetadataList -> Effect Unit
foreign import metadataList_toBytes :: MetadataList -> Bytes
foreign import metadataList_fromBytes :: Bytes -> MetadataList
foreign import metadataList_toHex :: MetadataList -> String
foreign import metadataList_fromHex :: String -> MetadataList
foreign import metadataList_new :: Effect MetadataList
foreign import metadataList_len :: MetadataList -> Effect Int
foreign import metadataList_get :: MetadataList -> Int -> Effect TxMetadatum
foreign import metadataList_add :: MetadataList -> TxMetadatum -> Effect Unit

-- | Metadata list class
type MetadataListClass =
  { free :: MetadataList -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: MetadataList -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> MetadataList
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: MetadataList -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> MetadataList
    -- ^ From hex
    -- > fromHex hexStr
  , new :: Effect MetadataList
    -- ^ New
    -- > new
  , len :: MetadataList -> Effect Int
    -- ^ Len
    -- > len self
  , get :: MetadataList -> Int -> Effect TxMetadatum
    -- ^ Get
    -- > get self index
  , add :: MetadataList -> TxMetadatum -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Metadata list class API
metadataList :: MetadataListClass
metadataList =
  { free: metadataList_free
  , toBytes: metadataList_toBytes
  , fromBytes: metadataList_fromBytes
  , toHex: metadataList_toHex
  , fromHex: metadataList_fromHex
  , new: metadataList_new
  , len: metadataList_len
  , get: metadataList_get
  , add: metadataList_add
  }

instance HasFree MetadataList where
  free = metadataList.free

instance Show MetadataList where
  show = metadataList.toHex

instance MutableList MetadataList TxMetadatum where
  addItem = metadataList.add
  getItem = metadataList.get
  emptyList = metadataList.new

instance MutableLen MetadataList where
  getLen = metadataList.len


instance IsHex MetadataList where
  toHex = metadataList.toHex
  fromHex = metadataList.fromHex

instance IsBytes MetadataList where
  toBytes = metadataList.toBytes
  fromBytes = metadataList.fromBytes

-------------------------------------------------------------------------------------
-- Metadata map

foreign import metadataMap_free :: MetadataMap -> Effect Unit
foreign import metadataMap_toBytes :: MetadataMap -> Bytes
foreign import metadataMap_fromBytes :: Bytes -> MetadataMap
foreign import metadataMap_toHex :: MetadataMap -> String
foreign import metadataMap_fromHex :: String -> MetadataMap
foreign import metadataMap_new :: Effect MetadataMap
foreign import metadataMap_len :: MetadataMap -> Int
foreign import metadataMap_insert :: MetadataMap -> TxMetadatum -> TxMetadatum -> Effect (Nullable TxMetadatum)
foreign import metadataMap_insertStr :: MetadataMap -> String -> TxMetadatum -> Effect (Nullable TxMetadatum)
foreign import metadataMap_insertI32 :: MetadataMap -> Number -> TxMetadatum -> Effect (Nullable TxMetadatum)
foreign import metadataMap_get :: MetadataMap -> TxMetadatum -> Effect TxMetadatum
foreign import metadataMap_getStr :: MetadataMap -> String -> Effect TxMetadatum
foreign import metadataMap_getI32 :: MetadataMap -> Number -> Effect TxMetadatum
foreign import metadataMap_has :: MetadataMap -> TxMetadatum -> Effect Boolean
foreign import metadataMap_keys :: MetadataMap -> Effect MetadataList

-- | Metadata map class
type MetadataMapClass =
  { free :: MetadataMap -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: MetadataMap -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> MetadataMap
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: MetadataMap -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> MetadataMap
    -- ^ From hex
    -- > fromHex hexStr
  , new :: Effect MetadataMap
    -- ^ New
    -- > new
  , len :: MetadataMap -> Int
    -- ^ Len
    -- > len self
  , insert :: MetadataMap -> TxMetadatum -> TxMetadatum -> Effect (Maybe TxMetadatum)
    -- ^ Insert
    -- > insert self key value
  , insertStr :: MetadataMap -> String -> TxMetadatum -> Effect (Maybe TxMetadatum)
    -- ^ Insert str
    -- > insertStr self key value
  , insertI32 :: MetadataMap -> Number -> TxMetadatum -> Effect (Maybe TxMetadatum)
    -- ^ Insert i32
    -- > insertI32 self key value
  , get :: MetadataMap -> TxMetadatum -> Effect TxMetadatum
    -- ^ Get
    -- > get self key
  , getStr :: MetadataMap -> String -> Effect TxMetadatum
    -- ^ Get str
    -- > getStr self key
  , getI32 :: MetadataMap -> Number -> Effect TxMetadatum
    -- ^ Get i32
    -- > getI32 self key
  , has :: MetadataMap -> TxMetadatum -> Effect Boolean
    -- ^ Has
    -- > has self key
  , keys :: MetadataMap -> Effect MetadataList
    -- ^ Keys
    -- > keys self
  }

-- | Metadata map class API
metadataMap :: MetadataMapClass
metadataMap =
  { free: metadataMap_free
  , toBytes: metadataMap_toBytes
  , fromBytes: metadataMap_fromBytes
  , toHex: metadataMap_toHex
  , fromHex: metadataMap_fromHex
  , new: metadataMap_new
  , len: metadataMap_len
  , insert: \a1 a2 a3 -> Nullable.toMaybe <$> metadataMap_insert a1 a2 a3
  , insertStr: \a1 a2 a3 -> Nullable.toMaybe <$> metadataMap_insertStr a1 a2 a3
  , insertI32: \a1 a2 a3 -> Nullable.toMaybe <$> metadataMap_insertI32 a1 a2 a3
  , get: metadataMap_get
  , getStr: metadataMap_getStr
  , getI32: metadataMap_getI32
  , has: metadataMap_has
  , keys: metadataMap_keys
  }

instance HasFree MetadataMap where
  free = metadataMap.free

instance Show MetadataMap where
  show = metadataMap.toHex

instance IsHex MetadataMap where
  toHex = metadataMap.toHex
  fromHex = metadataMap.fromHex

instance IsBytes MetadataMap where
  toBytes = metadataMap.toBytes
  fromBytes = metadataMap.fromBytes

-------------------------------------------------------------------------------------
-- Mint

foreign import mint_free :: Mint -> Effect Unit
foreign import mint_toBytes :: Mint -> Bytes
foreign import mint_fromBytes :: Bytes -> Mint
foreign import mint_toHex :: Mint -> String
foreign import mint_fromHex :: String -> Mint
foreign import mint_toJson :: Mint -> String
foreign import mint_toJsValue :: Mint -> MintJson
foreign import mint_fromJson :: String -> Mint
foreign import mint_new :: Effect Mint
foreign import mint_newFromEntry :: ScriptHash -> MintAssets -> Effect Mint
foreign import mint_len :: Mint -> Effect Int
foreign import mint_insert :: Mint -> ScriptHash -> MintAssets -> Effect (Nullable MintAssets)
foreign import mint_get :: Mint -> ScriptHash -> Effect (Nullable MintAssets)
foreign import mint_keys :: Mint -> Effect ScriptHashes
foreign import mint_asPositiveMultiasset :: Mint -> Effect MultiAsset
foreign import mint_asNegativeMultiasset :: Mint -> Effect MultiAsset

-- | Mint class
type MintClass =
  { free :: Mint -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Mint -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Mint
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Mint -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Mint
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Mint -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Mint -> MintJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Mint
    -- ^ From json
    -- > fromJson json
  , new :: Effect Mint
    -- ^ New
    -- > new
  , newFromEntry :: ScriptHash -> MintAssets -> Effect Mint
    -- ^ New from entry
    -- > newFromEntry key value
  , len :: Mint -> Effect Int
    -- ^ Len
    -- > len self
  , insert :: Mint -> ScriptHash -> MintAssets -> Effect (Maybe MintAssets)
    -- ^ Insert
    -- > insert self key value
  , get :: Mint -> ScriptHash -> Effect (Maybe MintAssets)
    -- ^ Get
    -- > get self key
  , keys :: Mint -> Effect ScriptHashes
    -- ^ Keys
    -- > keys self
  , asPositiveMultiasset :: Mint -> Effect MultiAsset
    -- ^ As positive multiasset
    -- > asPositiveMultiasset self
  , asNegativeMultiasset :: Mint -> Effect MultiAsset
    -- ^ As negative multiasset
    -- > asNegativeMultiasset self
  }

-- | Mint class API
mint :: MintClass
mint =
  { free: mint_free
  , toBytes: mint_toBytes
  , fromBytes: mint_fromBytes
  , toHex: mint_toHex
  , fromHex: mint_fromHex
  , toJson: mint_toJson
  , toJsValue: mint_toJsValue
  , fromJson: mint_fromJson
  , new: mint_new
  , newFromEntry: mint_newFromEntry
  , len: mint_len
  , insert: \a1 a2 a3 -> Nullable.toMaybe <$> mint_insert a1 a2 a3
  , get: \a1 a2 -> Nullable.toMaybe <$> mint_get a1 a2
  , keys: mint_keys
  , asPositiveMultiasset: mint_asPositiveMultiasset
  , asNegativeMultiasset: mint_asNegativeMultiasset
  }

instance HasFree Mint where
  free = mint.free

instance Show Mint where
  show = mint.toHex

instance ToJsValue Mint where
  toJsValue = mint.toJsValue

instance IsHex Mint where
  toHex = mint.toHex
  fromHex = mint.fromHex

instance IsBytes Mint where
  toBytes = mint.toBytes
  fromBytes = mint.fromBytes

instance IsJson Mint where
  toJson = mint.toJson
  fromJson = mint.fromJson

-------------------------------------------------------------------------------------
-- Mint assets

foreign import mintAssets_free :: MintAssets -> Effect Unit
foreign import mintAssets_new :: Effect MintAssets
foreign import mintAssets_newFromEntry :: AssetName -> Int -> MintAssets
foreign import mintAssets_len :: MintAssets -> Effect Int
foreign import mintAssets_insert :: MintAssets -> AssetName -> Int -> Effect (Nullable Int)
foreign import mintAssets_get :: MintAssets -> AssetName -> Effect (Nullable Int)
foreign import mintAssets_keys :: MintAssets -> Effect AssetNames

-- | Mint assets class
type MintAssetsClass =
  { free :: MintAssets -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: Effect MintAssets
    -- ^ New
    -- > new
  , newFromEntry :: AssetName -> Int -> MintAssets
    -- ^ New from entry
    -- > newFromEntry key value
  , len :: MintAssets -> Effect Int
    -- ^ Len
    -- > len self
  , insert :: MintAssets -> AssetName -> Int -> Effect (Maybe Int)
    -- ^ Insert
    -- > insert self key value
  , get :: MintAssets -> AssetName -> Effect (Maybe Int)
    -- ^ Get
    -- > get self key
  , keys :: MintAssets -> Effect AssetNames
    -- ^ Keys
    -- > keys self
  }

-- | Mint assets class API
mintAssets :: MintAssetsClass
mintAssets =
  { free: mintAssets_free
  , new: mintAssets_new
  , newFromEntry: mintAssets_newFromEntry
  , len: mintAssets_len
  , insert: \a1 a2 a3 -> Nullable.toMaybe <$> mintAssets_insert a1 a2 a3
  , get: \a1 a2 -> Nullable.toMaybe <$> mintAssets_get a1 a2
  , keys: mintAssets_keys
  }

instance HasFree MintAssets where
  free = mintAssets.free

-------------------------------------------------------------------------------------
-- Move instantaneous reward

foreign import moveInstantaneousReward_free :: MoveInstantaneousReward -> Effect Unit
foreign import moveInstantaneousReward_toBytes :: MoveInstantaneousReward -> Bytes
foreign import moveInstantaneousReward_fromBytes :: Bytes -> MoveInstantaneousReward
foreign import moveInstantaneousReward_toHex :: MoveInstantaneousReward -> String
foreign import moveInstantaneousReward_fromHex :: String -> MoveInstantaneousReward
foreign import moveInstantaneousReward_toJson :: MoveInstantaneousReward -> String
foreign import moveInstantaneousReward_toJsValue :: MoveInstantaneousReward -> MoveInstantaneousRewardJson
foreign import moveInstantaneousReward_fromJson :: String -> MoveInstantaneousReward
foreign import moveInstantaneousReward_newToOtherPot :: Number -> BigNum -> MoveInstantaneousReward
foreign import moveInstantaneousReward_newToStakeCreds :: Number -> MIRToStakeCredentials -> MoveInstantaneousReward
foreign import moveInstantaneousReward_pot :: MoveInstantaneousReward -> Number
foreign import moveInstantaneousReward_kind :: MoveInstantaneousReward -> Number
foreign import moveInstantaneousReward_asToOtherPot :: MoveInstantaneousReward -> Nullable BigNum
foreign import moveInstantaneousReward_asToStakeCreds :: MoveInstantaneousReward -> Nullable MIRToStakeCredentials

-- | Move instantaneous reward class
type MoveInstantaneousRewardClass =
  { free :: MoveInstantaneousReward -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: MoveInstantaneousReward -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> MoveInstantaneousReward
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: MoveInstantaneousReward -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> MoveInstantaneousReward
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: MoveInstantaneousReward -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: MoveInstantaneousReward -> MoveInstantaneousRewardJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> MoveInstantaneousReward
    -- ^ From json
    -- > fromJson json
  , newToOtherPot :: Number -> BigNum -> MoveInstantaneousReward
    -- ^ New to other pot
    -- > newToOtherPot pot amount
  , newToStakeCreds :: Number -> MIRToStakeCredentials -> MoveInstantaneousReward
    -- ^ New to stake creds
    -- > newToStakeCreds pot amounts
  , pot :: MoveInstantaneousReward -> Number
    -- ^ Pot
    -- > pot self
  , kind :: MoveInstantaneousReward -> Number
    -- ^ Kind
    -- > kind self
  , asToOtherPot :: MoveInstantaneousReward -> Maybe BigNum
    -- ^ As to other pot
    -- > asToOtherPot self
  , asToStakeCreds :: MoveInstantaneousReward -> Maybe MIRToStakeCredentials
    -- ^ As to stake creds
    -- > asToStakeCreds self
  }

-- | Move instantaneous reward class API
moveInstantaneousReward :: MoveInstantaneousRewardClass
moveInstantaneousReward =
  { free: moveInstantaneousReward_free
  , toBytes: moveInstantaneousReward_toBytes
  , fromBytes: moveInstantaneousReward_fromBytes
  , toHex: moveInstantaneousReward_toHex
  , fromHex: moveInstantaneousReward_fromHex
  , toJson: moveInstantaneousReward_toJson
  , toJsValue: moveInstantaneousReward_toJsValue
  , fromJson: moveInstantaneousReward_fromJson
  , newToOtherPot: moveInstantaneousReward_newToOtherPot
  , newToStakeCreds: moveInstantaneousReward_newToStakeCreds
  , pot: moveInstantaneousReward_pot
  , kind: moveInstantaneousReward_kind
  , asToOtherPot: \a1 -> Nullable.toMaybe $ moveInstantaneousReward_asToOtherPot a1
  , asToStakeCreds: \a1 -> Nullable.toMaybe $ moveInstantaneousReward_asToStakeCreds a1
  }

instance HasFree MoveInstantaneousReward where
  free = moveInstantaneousReward.free

instance Show MoveInstantaneousReward where
  show = moveInstantaneousReward.toHex

instance ToJsValue MoveInstantaneousReward where
  toJsValue = moveInstantaneousReward.toJsValue

instance IsHex MoveInstantaneousReward where
  toHex = moveInstantaneousReward.toHex
  fromHex = moveInstantaneousReward.fromHex

instance IsBytes MoveInstantaneousReward where
  toBytes = moveInstantaneousReward.toBytes
  fromBytes = moveInstantaneousReward.fromBytes

instance IsJson MoveInstantaneousReward where
  toJson = moveInstantaneousReward.toJson
  fromJson = moveInstantaneousReward.fromJson

-------------------------------------------------------------------------------------
-- Move instantaneous rewards cert

foreign import moveInstantaneousRewardsCert_free :: MoveInstantaneousRewardsCert -> Effect Unit
foreign import moveInstantaneousRewardsCert_toBytes :: MoveInstantaneousRewardsCert -> Bytes
foreign import moveInstantaneousRewardsCert_fromBytes :: Bytes -> MoveInstantaneousRewardsCert
foreign import moveInstantaneousRewardsCert_toHex :: MoveInstantaneousRewardsCert -> String
foreign import moveInstantaneousRewardsCert_fromHex :: String -> MoveInstantaneousRewardsCert
foreign import moveInstantaneousRewardsCert_toJson :: MoveInstantaneousRewardsCert -> String
foreign import moveInstantaneousRewardsCert_toJsValue :: MoveInstantaneousRewardsCert -> MoveInstantaneousRewardsCertJson
foreign import moveInstantaneousRewardsCert_fromJson :: String -> MoveInstantaneousRewardsCert
foreign import moveInstantaneousRewardsCert_moveInstantaneousReward :: MoveInstantaneousRewardsCert -> MoveInstantaneousReward
foreign import moveInstantaneousRewardsCert_new :: MoveInstantaneousReward -> MoveInstantaneousRewardsCert

-- | Move instantaneous rewards cert class
type MoveInstantaneousRewardsCertClass =
  { free :: MoveInstantaneousRewardsCert -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: MoveInstantaneousRewardsCert -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> MoveInstantaneousRewardsCert
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: MoveInstantaneousRewardsCert -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> MoveInstantaneousRewardsCert
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: MoveInstantaneousRewardsCert -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: MoveInstantaneousRewardsCert -> MoveInstantaneousRewardsCertJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> MoveInstantaneousRewardsCert
    -- ^ From json
    -- > fromJson json
  , moveInstantaneousReward :: MoveInstantaneousRewardsCert -> MoveInstantaneousReward
    -- ^ Move instantaneous reward
    -- > moveInstantaneousReward self
  , new :: MoveInstantaneousReward -> MoveInstantaneousRewardsCert
    -- ^ New
    -- > new moveInstantaneousReward
  }

-- | Move instantaneous rewards cert class API
moveInstantaneousRewardsCert :: MoveInstantaneousRewardsCertClass
moveInstantaneousRewardsCert =
  { free: moveInstantaneousRewardsCert_free
  , toBytes: moveInstantaneousRewardsCert_toBytes
  , fromBytes: moveInstantaneousRewardsCert_fromBytes
  , toHex: moveInstantaneousRewardsCert_toHex
  , fromHex: moveInstantaneousRewardsCert_fromHex
  , toJson: moveInstantaneousRewardsCert_toJson
  , toJsValue: moveInstantaneousRewardsCert_toJsValue
  , fromJson: moveInstantaneousRewardsCert_fromJson
  , moveInstantaneousReward: moveInstantaneousRewardsCert_moveInstantaneousReward
  , new: moveInstantaneousRewardsCert_new
  }

instance HasFree MoveInstantaneousRewardsCert where
  free = moveInstantaneousRewardsCert.free

instance Show MoveInstantaneousRewardsCert where
  show = moveInstantaneousRewardsCert.toHex

instance ToJsValue MoveInstantaneousRewardsCert where
  toJsValue = moveInstantaneousRewardsCert.toJsValue

instance IsHex MoveInstantaneousRewardsCert where
  toHex = moveInstantaneousRewardsCert.toHex
  fromHex = moveInstantaneousRewardsCert.fromHex

instance IsBytes MoveInstantaneousRewardsCert where
  toBytes = moveInstantaneousRewardsCert.toBytes
  fromBytes = moveInstantaneousRewardsCert.fromBytes

instance IsJson MoveInstantaneousRewardsCert where
  toJson = moveInstantaneousRewardsCert.toJson
  fromJson = moveInstantaneousRewardsCert.fromJson

-------------------------------------------------------------------------------------
-- Multi asset

foreign import multiAsset_free :: MultiAsset -> Effect Unit
foreign import multiAsset_toBytes :: MultiAsset -> Bytes
foreign import multiAsset_fromBytes :: Bytes -> MultiAsset
foreign import multiAsset_toHex :: MultiAsset -> String
foreign import multiAsset_fromHex :: String -> MultiAsset
foreign import multiAsset_toJson :: MultiAsset -> String
foreign import multiAsset_toJsValue :: MultiAsset -> MultiAssetJson
foreign import multiAsset_fromJson :: String -> MultiAsset
foreign import multiAsset_new :: Effect MultiAsset
foreign import multiAsset_len :: MultiAsset -> Effect Int
foreign import multiAsset_insert :: MultiAsset -> ScriptHash -> Assets -> Nullable Assets
foreign import multiAsset_get :: MultiAsset -> ScriptHash -> Effect (Nullable Assets)
foreign import multiAsset_setAsset :: MultiAsset -> ScriptHash -> AssetName -> BigNum -> Effect (Nullable BigNum)
foreign import multiAsset_getAsset :: MultiAsset -> ScriptHash -> AssetName -> Effect BigNum
foreign import multiAsset_keys :: MultiAsset -> Effect ScriptHashes
foreign import multiAsset_sub :: MultiAsset -> MultiAsset -> Effect MultiAsset

-- | Multi asset class
type MultiAssetClass =
  { free :: MultiAsset -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: MultiAsset -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> MultiAsset
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: MultiAsset -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> MultiAsset
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: MultiAsset -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: MultiAsset -> MultiAssetJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> MultiAsset
    -- ^ From json
    -- > fromJson json
  , new :: Effect MultiAsset
    -- ^ New
    -- > new
  , len :: MultiAsset -> Effect Int
    -- ^ Len
    -- > len self
  , insert :: MultiAsset -> ScriptHash -> Assets -> Maybe Assets
    -- ^ Insert
    -- > insert self policyId assets
  , get :: MultiAsset -> ScriptHash -> Effect (Maybe Assets)
    -- ^ Get
    -- > get self policyId
  , setAsset :: MultiAsset -> ScriptHash -> AssetName -> BigNum -> Effect (Maybe BigNum)
    -- ^ Set asset
    -- > setAsset self policyId assetName value
  , getAsset :: MultiAsset -> ScriptHash -> AssetName -> Effect BigNum
    -- ^ Get asset
    -- > getAsset self policyId assetName
  , keys :: MultiAsset -> Effect ScriptHashes
    -- ^ Keys
    -- > keys self
  , sub :: MultiAsset -> MultiAsset -> Effect MultiAsset
    -- ^ Sub
    -- > sub self rhsMa
  }

-- | Multi asset class API
multiAsset :: MultiAssetClass
multiAsset =
  { free: multiAsset_free
  , toBytes: multiAsset_toBytes
  , fromBytes: multiAsset_fromBytes
  , toHex: multiAsset_toHex
  , fromHex: multiAsset_fromHex
  , toJson: multiAsset_toJson
  , toJsValue: multiAsset_toJsValue
  , fromJson: multiAsset_fromJson
  , new: multiAsset_new
  , len: multiAsset_len
  , insert: \a1 a2 a3 -> Nullable.toMaybe $ multiAsset_insert a1 a2 a3
  , get: \a1 a2 -> Nullable.toMaybe <$> multiAsset_get a1 a2
  , setAsset: \a1 a2 a3 a4 -> Nullable.toMaybe <$> multiAsset_setAsset a1 a2 a3 a4
  , getAsset: multiAsset_getAsset
  , keys: multiAsset_keys
  , sub: multiAsset_sub
  }

instance HasFree MultiAsset where
  free = multiAsset.free

instance Show MultiAsset where
  show = multiAsset.toHex

instance ToJsValue MultiAsset where
  toJsValue = multiAsset.toJsValue

instance IsHex MultiAsset where
  toHex = multiAsset.toHex
  fromHex = multiAsset.fromHex

instance IsBytes MultiAsset where
  toBytes = multiAsset.toBytes
  fromBytes = multiAsset.fromBytes

instance IsJson MultiAsset where
  toJson = multiAsset.toJson
  fromJson = multiAsset.fromJson

-------------------------------------------------------------------------------------
-- Multi host name

foreign import multiHostName_free :: MultiHostName -> Effect Unit
foreign import multiHostName_toBytes :: MultiHostName -> Bytes
foreign import multiHostName_fromBytes :: Bytes -> MultiHostName
foreign import multiHostName_toHex :: MultiHostName -> String
foreign import multiHostName_fromHex :: String -> MultiHostName
foreign import multiHostName_toJson :: MultiHostName -> String
foreign import multiHostName_toJsValue :: MultiHostName -> MultiHostNameJson
foreign import multiHostName_fromJson :: String -> MultiHostName
foreign import multiHostName_dnsName :: MultiHostName -> DNSRecordSRV
foreign import multiHostName_new :: DNSRecordSRV -> MultiHostName

-- | Multi host name class
type MultiHostNameClass =
  { free :: MultiHostName -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: MultiHostName -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> MultiHostName
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: MultiHostName -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> MultiHostName
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: MultiHostName -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: MultiHostName -> MultiHostNameJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> MultiHostName
    -- ^ From json
    -- > fromJson json
  , dnsName :: MultiHostName -> DNSRecordSRV
    -- ^ Dns name
    -- > dnsName self
  , new :: DNSRecordSRV -> MultiHostName
    -- ^ New
    -- > new dnsName
  }

-- | Multi host name class API
multiHostName :: MultiHostNameClass
multiHostName =
  { free: multiHostName_free
  , toBytes: multiHostName_toBytes
  , fromBytes: multiHostName_fromBytes
  , toHex: multiHostName_toHex
  , fromHex: multiHostName_fromHex
  , toJson: multiHostName_toJson
  , toJsValue: multiHostName_toJsValue
  , fromJson: multiHostName_fromJson
  , dnsName: multiHostName_dnsName
  , new: multiHostName_new
  }

instance HasFree MultiHostName where
  free = multiHostName.free

instance Show MultiHostName where
  show = multiHostName.toHex

instance ToJsValue MultiHostName where
  toJsValue = multiHostName.toJsValue

instance IsHex MultiHostName where
  toHex = multiHostName.toHex
  fromHex = multiHostName.fromHex

instance IsBytes MultiHostName where
  toBytes = multiHostName.toBytes
  fromBytes = multiHostName.fromBytes

instance IsJson MultiHostName where
  toJson = multiHostName.toJson
  fromJson = multiHostName.fromJson

-------------------------------------------------------------------------------------
-- Native script

foreign import nativeScript_free :: NativeScript -> Effect Unit
foreign import nativeScript_toBytes :: NativeScript -> Bytes
foreign import nativeScript_fromBytes :: Bytes -> NativeScript
foreign import nativeScript_toHex :: NativeScript -> String
foreign import nativeScript_fromHex :: String -> NativeScript
foreign import nativeScript_toJson :: NativeScript -> String
foreign import nativeScript_toJsValue :: NativeScript -> NativeScriptJson
foreign import nativeScript_fromJson :: String -> NativeScript
foreign import nativeScript_hash :: NativeScript -> ScriptHash
foreign import nativeScript_newScriptPubkey :: ScriptPubkey -> NativeScript
foreign import nativeScript_newScriptAll :: ScriptAll -> NativeScript
foreign import nativeScript_newScriptAny :: ScriptAny -> NativeScript
foreign import nativeScript_newScriptNOfK :: ScriptNOfK -> NativeScript
foreign import nativeScript_newTimelockStart :: TimelockStart -> NativeScript
foreign import nativeScript_newTimelockExpiry :: TimelockExpiry -> NativeScript
foreign import nativeScript_kind :: NativeScript -> Number
foreign import nativeScript_asScriptPubkey :: NativeScript -> Nullable ScriptPubkey
foreign import nativeScript_asScriptAll :: NativeScript -> Nullable ScriptAll
foreign import nativeScript_asScriptAny :: NativeScript -> Nullable ScriptAny
foreign import nativeScript_asScriptNOfK :: NativeScript -> Nullable ScriptNOfK
foreign import nativeScript_asTimelockStart :: NativeScript -> Nullable TimelockStart
foreign import nativeScript_asTimelockExpiry :: NativeScript -> Nullable TimelockExpiry
foreign import nativeScript_getRequiredSigners :: NativeScript -> Ed25519KeyHashes

-- | Native script class
type NativeScriptClass =
  { free :: NativeScript -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: NativeScript -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> NativeScript
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: NativeScript -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> NativeScript
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: NativeScript -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: NativeScript -> NativeScriptJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> NativeScript
    -- ^ From json
    -- > fromJson json
  , hash :: NativeScript -> ScriptHash
    -- ^ Hash
    -- > hash self
  , newScriptPubkey :: ScriptPubkey -> NativeScript
    -- ^ New script pubkey
    -- > newScriptPubkey scriptPubkey
  , newScriptAll :: ScriptAll -> NativeScript
    -- ^ New script all
    -- > newScriptAll scriptAll
  , newScriptAny :: ScriptAny -> NativeScript
    -- ^ New script any
    -- > newScriptAny scriptAny
  , newScriptNOfK :: ScriptNOfK -> NativeScript
    -- ^ New script n of k
    -- > newScriptNOfK scriptNOfK
  , newTimelockStart :: TimelockStart -> NativeScript
    -- ^ New timelock start
    -- > newTimelockStart timelockStart
  , newTimelockExpiry :: TimelockExpiry -> NativeScript
    -- ^ New timelock expiry
    -- > newTimelockExpiry timelockExpiry
  , kind :: NativeScript -> Number
    -- ^ Kind
    -- > kind self
  , asScriptPubkey :: NativeScript -> Maybe ScriptPubkey
    -- ^ As script pubkey
    -- > asScriptPubkey self
  , asScriptAll :: NativeScript -> Maybe ScriptAll
    -- ^ As script all
    -- > asScriptAll self
  , asScriptAny :: NativeScript -> Maybe ScriptAny
    -- ^ As script any
    -- > asScriptAny self
  , asScriptNOfK :: NativeScript -> Maybe ScriptNOfK
    -- ^ As script n of k
    -- > asScriptNOfK self
  , asTimelockStart :: NativeScript -> Maybe TimelockStart
    -- ^ As timelock start
    -- > asTimelockStart self
  , asTimelockExpiry :: NativeScript -> Maybe TimelockExpiry
    -- ^ As timelock expiry
    -- > asTimelockExpiry self
  , getRequiredSigners :: NativeScript -> Ed25519KeyHashes
    -- ^ Get required signers
    -- > getRequiredSigners self
  }

-- | Native script class API
nativeScript :: NativeScriptClass
nativeScript =
  { free: nativeScript_free
  , toBytes: nativeScript_toBytes
  , fromBytes: nativeScript_fromBytes
  , toHex: nativeScript_toHex
  , fromHex: nativeScript_fromHex
  , toJson: nativeScript_toJson
  , toJsValue: nativeScript_toJsValue
  , fromJson: nativeScript_fromJson
  , hash: nativeScript_hash
  , newScriptPubkey: nativeScript_newScriptPubkey
  , newScriptAll: nativeScript_newScriptAll
  , newScriptAny: nativeScript_newScriptAny
  , newScriptNOfK: nativeScript_newScriptNOfK
  , newTimelockStart: nativeScript_newTimelockStart
  , newTimelockExpiry: nativeScript_newTimelockExpiry
  , kind: nativeScript_kind
  , asScriptPubkey: \a1 -> Nullable.toMaybe $ nativeScript_asScriptPubkey a1
  , asScriptAll: \a1 -> Nullable.toMaybe $ nativeScript_asScriptAll a1
  , asScriptAny: \a1 -> Nullable.toMaybe $ nativeScript_asScriptAny a1
  , asScriptNOfK: \a1 -> Nullable.toMaybe $ nativeScript_asScriptNOfK a1
  , asTimelockStart: \a1 -> Nullable.toMaybe $ nativeScript_asTimelockStart a1
  , asTimelockExpiry: \a1 -> Nullable.toMaybe $ nativeScript_asTimelockExpiry a1
  , getRequiredSigners: nativeScript_getRequiredSigners
  }

instance HasFree NativeScript where
  free = nativeScript.free

instance Show NativeScript where
  show = nativeScript.toHex

instance ToJsValue NativeScript where
  toJsValue = nativeScript.toJsValue

instance IsHex NativeScript where
  toHex = nativeScript.toHex
  fromHex = nativeScript.fromHex

instance IsBytes NativeScript where
  toBytes = nativeScript.toBytes
  fromBytes = nativeScript.fromBytes

instance IsJson NativeScript where
  toJson = nativeScript.toJson
  fromJson = nativeScript.fromJson

-------------------------------------------------------------------------------------
-- Native scripts

foreign import nativeScripts_free :: NativeScripts -> Effect Unit
foreign import nativeScripts_new :: Effect NativeScripts
foreign import nativeScripts_len :: NativeScripts -> Effect Int
foreign import nativeScripts_get :: NativeScripts -> Int -> Effect NativeScript
foreign import nativeScripts_add :: NativeScripts -> NativeScript -> Effect Unit

-- | Native scripts class
type NativeScriptsClass =
  { free :: NativeScripts -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: Effect NativeScripts
    -- ^ New
    -- > new
  , len :: NativeScripts -> Effect Int
    -- ^ Len
    -- > len self
  , get :: NativeScripts -> Int -> Effect NativeScript
    -- ^ Get
    -- > get self index
  , add :: NativeScripts -> NativeScript -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Native scripts class API
nativeScripts :: NativeScriptsClass
nativeScripts =
  { free: nativeScripts_free
  , new: nativeScripts_new
  , len: nativeScripts_len
  , get: nativeScripts_get
  , add: nativeScripts_add
  }

instance HasFree NativeScripts where
  free = nativeScripts.free

instance MutableList NativeScripts NativeScript where
  addItem = nativeScripts.add
  getItem = nativeScripts.get
  emptyList = nativeScripts.new

instance MutableLen NativeScripts where
  getLen = nativeScripts.len

-------------------------------------------------------------------------------------
-- Network id

foreign import networkId_free :: NetworkId -> Effect Unit
foreign import networkId_toBytes :: NetworkId -> Bytes
foreign import networkId_fromBytes :: Bytes -> NetworkId
foreign import networkId_toHex :: NetworkId -> String
foreign import networkId_fromHex :: String -> NetworkId
foreign import networkId_toJson :: NetworkId -> String
foreign import networkId_toJsValue :: NetworkId -> NetworkIdJson
foreign import networkId_fromJson :: String -> NetworkId
foreign import networkId_testnet :: NetworkId
foreign import networkId_mainnet :: NetworkId
foreign import networkId_kind :: NetworkId -> Number

-- | Network id class
type NetworkIdClass =
  { free :: NetworkId -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: NetworkId -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> NetworkId
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: NetworkId -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> NetworkId
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: NetworkId -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: NetworkId -> NetworkIdJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> NetworkId
    -- ^ From json
    -- > fromJson json
  , testnet :: NetworkId
    -- ^ Testnet
    -- > testnet
  , mainnet :: NetworkId
    -- ^ Mainnet
    -- > mainnet
  , kind :: NetworkId -> Number
    -- ^ Kind
    -- > kind self
  }

-- | Network id class API
networkId :: NetworkIdClass
networkId =
  { free: networkId_free
  , toBytes: networkId_toBytes
  , fromBytes: networkId_fromBytes
  , toHex: networkId_toHex
  , fromHex: networkId_fromHex
  , toJson: networkId_toJson
  , toJsValue: networkId_toJsValue
  , fromJson: networkId_fromJson
  , testnet: networkId_testnet
  , mainnet: networkId_mainnet
  , kind: networkId_kind
  }

instance HasFree NetworkId where
  free = networkId.free

instance Show NetworkId where
  show = networkId.toHex

instance ToJsValue NetworkId where
  toJsValue = networkId.toJsValue

instance IsHex NetworkId where
  toHex = networkId.toHex
  fromHex = networkId.fromHex

instance IsBytes NetworkId where
  toBytes = networkId.toBytes
  fromBytes = networkId.fromBytes

instance IsJson NetworkId where
  toJson = networkId.toJson
  fromJson = networkId.fromJson

-------------------------------------------------------------------------------------
-- Network info

foreign import networkInfo_free :: NetworkInfo -> Effect Unit
foreign import networkInfo_new :: Number -> Number -> NetworkInfo
foreign import networkInfo_networkId :: NetworkInfo -> Number
foreign import networkInfo_protocolMagic :: NetworkInfo -> Number
foreign import networkInfo_testnet :: NetworkInfo
foreign import networkInfo_mainnet :: NetworkInfo

-- | Network info class
type NetworkInfoClass =
  { free :: NetworkInfo -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: Number -> Number -> NetworkInfo
    -- ^ New
    -- > new networkId protocolMagic
  , networkId :: NetworkInfo -> Number
    -- ^ Network id
    -- > networkId self
  , protocolMagic :: NetworkInfo -> Number
    -- ^ Protocol magic
    -- > protocolMagic self
  , testnet :: NetworkInfo
    -- ^ Testnet
    -- > testnet
  , mainnet :: NetworkInfo
    -- ^ Mainnet
    -- > mainnet
  }

-- | Network info class API
networkInfo :: NetworkInfoClass
networkInfo =
  { free: networkInfo_free
  , new: networkInfo_new
  , networkId: networkInfo_networkId
  , protocolMagic: networkInfo_protocolMagic
  , testnet: networkInfo_testnet
  , mainnet: networkInfo_mainnet
  }

instance HasFree NetworkInfo where
  free = networkInfo.free

-------------------------------------------------------------------------------------
-- Nonce

foreign import nonce_free :: Nonce -> Effect Unit
foreign import nonce_toBytes :: Nonce -> Bytes
foreign import nonce_fromBytes :: Bytes -> Nonce
foreign import nonce_toHex :: Nonce -> String
foreign import nonce_fromHex :: String -> Nonce
foreign import nonce_toJson :: Nonce -> String
foreign import nonce_toJsValue :: Nonce -> NonceJson
foreign import nonce_fromJson :: String -> Nonce
foreign import nonce_newIdentity :: Nonce
foreign import nonce_newFromHash :: Bytes -> Nonce
foreign import nonce_getHash :: Nonce -> Nullable Bytes

-- | Nonce class
type NonceClass =
  { free :: Nonce -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Nonce -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Nonce
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Nonce -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Nonce
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Nonce -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Nonce -> NonceJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Nonce
    -- ^ From json
    -- > fromJson json
  , newIdentity :: Nonce
    -- ^ New identity
    -- > newIdentity
  , newFromHash :: Bytes -> Nonce
    -- ^ New from hash
    -- > newFromHash hash
  , getHash :: Nonce -> Maybe Bytes
    -- ^ Get hash
    -- > getHash self
  }

-- | Nonce class API
nonce :: NonceClass
nonce =
  { free: nonce_free
  , toBytes: nonce_toBytes
  , fromBytes: nonce_fromBytes
  , toHex: nonce_toHex
  , fromHex: nonce_fromHex
  , toJson: nonce_toJson
  , toJsValue: nonce_toJsValue
  , fromJson: nonce_fromJson
  , newIdentity: nonce_newIdentity
  , newFromHash: nonce_newFromHash
  , getHash: \a1 -> Nullable.toMaybe $ nonce_getHash a1
  }

instance HasFree Nonce where
  free = nonce.free

instance Show Nonce where
  show = nonce.toHex

instance ToJsValue Nonce where
  toJsValue = nonce.toJsValue

instance IsHex Nonce where
  toHex = nonce.toHex
  fromHex = nonce.fromHex

instance IsBytes Nonce where
  toBytes = nonce.toBytes
  fromBytes = nonce.fromBytes

instance IsJson Nonce where
  toJson = nonce.toJson
  fromJson = nonce.fromJson

-------------------------------------------------------------------------------------
-- Operational cert

foreign import operationalCert_free :: OperationalCert -> Effect Unit
foreign import operationalCert_toBytes :: OperationalCert -> Bytes
foreign import operationalCert_fromBytes :: Bytes -> OperationalCert
foreign import operationalCert_toHex :: OperationalCert -> String
foreign import operationalCert_fromHex :: String -> OperationalCert
foreign import operationalCert_toJson :: OperationalCert -> String
foreign import operationalCert_toJsValue :: OperationalCert -> OperationalCertJson
foreign import operationalCert_fromJson :: String -> OperationalCert
foreign import operationalCert_hotVkey :: OperationalCert -> KESVKey
foreign import operationalCert_sequenceNumber :: OperationalCert -> Number
foreign import operationalCert_kesPeriod :: OperationalCert -> Number
foreign import operationalCert_sigma :: OperationalCert -> Ed25519Signature
foreign import operationalCert_new :: KESVKey -> Number -> Number -> Ed25519Signature -> OperationalCert

-- | Operational cert class
type OperationalCertClass =
  { free :: OperationalCert -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: OperationalCert -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> OperationalCert
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: OperationalCert -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> OperationalCert
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: OperationalCert -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: OperationalCert -> OperationalCertJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> OperationalCert
    -- ^ From json
    -- > fromJson json
  , hotVkey :: OperationalCert -> KESVKey
    -- ^ Hot vkey
    -- > hotVkey self
  , sequenceNumber :: OperationalCert -> Number
    -- ^ Sequence number
    -- > sequenceNumber self
  , kesPeriod :: OperationalCert -> Number
    -- ^ Kes period
    -- > kesPeriod self
  , sigma :: OperationalCert -> Ed25519Signature
    -- ^ Sigma
    -- > sigma self
  , new :: KESVKey -> Number -> Number -> Ed25519Signature -> OperationalCert
    -- ^ New
    -- > new hotVkey sequenceNumber kesPeriod sigma
  }

-- | Operational cert class API
operationalCert :: OperationalCertClass
operationalCert =
  { free: operationalCert_free
  , toBytes: operationalCert_toBytes
  , fromBytes: operationalCert_fromBytes
  , toHex: operationalCert_toHex
  , fromHex: operationalCert_fromHex
  , toJson: operationalCert_toJson
  , toJsValue: operationalCert_toJsValue
  , fromJson: operationalCert_fromJson
  , hotVkey: operationalCert_hotVkey
  , sequenceNumber: operationalCert_sequenceNumber
  , kesPeriod: operationalCert_kesPeriod
  , sigma: operationalCert_sigma
  , new: operationalCert_new
  }

instance HasFree OperationalCert where
  free = operationalCert.free

instance Show OperationalCert where
  show = operationalCert.toHex

instance ToJsValue OperationalCert where
  toJsValue = operationalCert.toJsValue

instance IsHex OperationalCert where
  toHex = operationalCert.toHex
  fromHex = operationalCert.fromHex

instance IsBytes OperationalCert where
  toBytes = operationalCert.toBytes
  fromBytes = operationalCert.fromBytes

instance IsJson OperationalCert where
  toJson = operationalCert.toJson
  fromJson = operationalCert.fromJson

-------------------------------------------------------------------------------------
-- Plutus data

foreign import plutusData_free :: PlutusData -> Effect Unit
foreign import plutusData_toBytes :: PlutusData -> Bytes
foreign import plutusData_fromBytes :: Bytes -> PlutusData
foreign import plutusData_toHex :: PlutusData -> String
foreign import plutusData_fromHex :: String -> PlutusData
foreign import plutusData_toJson :: PlutusData -> String
foreign import plutusData_toJsValue :: PlutusData -> PlutusDataJson
foreign import plutusData_fromJson :: String -> PlutusData
foreign import plutusData_newConstrPlutusData :: ConstrPlutusData -> PlutusData
foreign import plutusData_newEmptyConstrPlutusData :: BigNum -> PlutusData
foreign import plutusData_newMap :: PlutusMap -> PlutusData
foreign import plutusData_newList :: PlutusList -> PlutusData
foreign import plutusData_newInteger :: BigInt -> PlutusData
foreign import plutusData_newBytes :: Bytes -> PlutusData
foreign import plutusData_kind :: PlutusData -> Number
foreign import plutusData_asConstrPlutusData :: PlutusData -> Nullable ConstrPlutusData
foreign import plutusData_asMap :: PlutusData -> Nullable PlutusMap
foreign import plutusData_asList :: PlutusData -> Nullable PlutusList
foreign import plutusData_asInteger :: PlutusData -> Nullable BigInt
foreign import plutusData_asBytes :: PlutusData -> Nullable Bytes

-- | Plutus data class
type PlutusDataClass =
  { free :: PlutusData -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: PlutusData -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> PlutusData
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: PlutusData -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> PlutusData
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: PlutusData -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: PlutusData -> PlutusDataJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> PlutusData
    -- ^ From json
    -- > fromJson json
  , newConstrPlutusData :: ConstrPlutusData -> PlutusData
    -- ^ New constr plutus data
    -- > newConstrPlutusData constrPlutusData
  , newEmptyConstrPlutusData :: BigNum -> PlutusData
    -- ^ New empty constr plutus data
    -- > newEmptyConstrPlutusData alternative
  , newMap :: PlutusMap -> PlutusData
    -- ^ New map
    -- > newMap map
  , newList :: PlutusList -> PlutusData
    -- ^ New list
    -- > newList list
  , newInteger :: BigInt -> PlutusData
    -- ^ New integer
    -- > newInteger integer
  , newBytes :: Bytes -> PlutusData
    -- ^ New bytes
    -- > newBytes bytes
  , kind :: PlutusData -> Number
    -- ^ Kind
    -- > kind self
  , asConstrPlutusData :: PlutusData -> Maybe ConstrPlutusData
    -- ^ As constr plutus data
    -- > asConstrPlutusData self
  , asMap :: PlutusData -> Maybe PlutusMap
    -- ^ As map
    -- > asMap self
  , asList :: PlutusData -> Maybe PlutusList
    -- ^ As list
    -- > asList self
  , asInteger :: PlutusData -> Maybe BigInt
    -- ^ As integer
    -- > asInteger self
  , asBytes :: PlutusData -> Maybe Bytes
    -- ^ As bytes
    -- > asBytes self
  }

-- | Plutus data class API
plutusData :: PlutusDataClass
plutusData =
  { free: plutusData_free
  , toBytes: plutusData_toBytes
  , fromBytes: plutusData_fromBytes
  , toHex: plutusData_toHex
  , fromHex: plutusData_fromHex
  , toJson: plutusData_toJson
  , toJsValue: plutusData_toJsValue
  , fromJson: plutusData_fromJson
  , newConstrPlutusData: plutusData_newConstrPlutusData
  , newEmptyConstrPlutusData: plutusData_newEmptyConstrPlutusData
  , newMap: plutusData_newMap
  , newList: plutusData_newList
  , newInteger: plutusData_newInteger
  , newBytes: plutusData_newBytes
  , kind: plutusData_kind
  , asConstrPlutusData: \a1 -> Nullable.toMaybe $ plutusData_asConstrPlutusData a1
  , asMap: \a1 -> Nullable.toMaybe $ plutusData_asMap a1
  , asList: \a1 -> Nullable.toMaybe $ plutusData_asList a1
  , asInteger: \a1 -> Nullable.toMaybe $ plutusData_asInteger a1
  , asBytes: \a1 -> Nullable.toMaybe $ plutusData_asBytes a1
  }

instance HasFree PlutusData where
  free = plutusData.free

instance Show PlutusData where
  show = plutusData.toHex

instance ToJsValue PlutusData where
  toJsValue = plutusData.toJsValue

instance IsHex PlutusData where
  toHex = plutusData.toHex
  fromHex = plutusData.fromHex

instance IsBytes PlutusData where
  toBytes = plutusData.toBytes
  fromBytes = plutusData.fromBytes

instance IsJson PlutusData where
  toJson = plutusData.toJson
  fromJson = plutusData.fromJson

-------------------------------------------------------------------------------------
-- Plutus list

foreign import plutusList_free :: PlutusList -> Effect Unit
foreign import plutusList_toBytes :: PlutusList -> Bytes
foreign import plutusList_fromBytes :: Bytes -> PlutusList
foreign import plutusList_toHex :: PlutusList -> String
foreign import plutusList_fromHex :: String -> PlutusList
foreign import plutusList_toJson :: PlutusList -> String
foreign import plutusList_toJsValue :: PlutusList -> PlutusListJson
foreign import plutusList_fromJson :: String -> PlutusList
foreign import plutusList_new :: Effect PlutusList
foreign import plutusList_len :: PlutusList -> Effect Int
foreign import plutusList_get :: PlutusList -> Int -> Effect PlutusData
foreign import plutusList_add :: PlutusList -> PlutusData -> Effect Unit

-- | Plutus list class
type PlutusListClass =
  { free :: PlutusList -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: PlutusList -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> PlutusList
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: PlutusList -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> PlutusList
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: PlutusList -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: PlutusList -> PlutusListJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> PlutusList
    -- ^ From json
    -- > fromJson json
  , new :: Effect PlutusList
    -- ^ New
    -- > new
  , len :: PlutusList -> Effect Int
    -- ^ Len
    -- > len self
  , get :: PlutusList -> Int -> Effect PlutusData
    -- ^ Get
    -- > get self index
  , add :: PlutusList -> PlutusData -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Plutus list class API
plutusList :: PlutusListClass
plutusList =
  { free: plutusList_free
  , toBytes: plutusList_toBytes
  , fromBytes: plutusList_fromBytes
  , toHex: plutusList_toHex
  , fromHex: plutusList_fromHex
  , toJson: plutusList_toJson
  , toJsValue: plutusList_toJsValue
  , fromJson: plutusList_fromJson
  , new: plutusList_new
  , len: plutusList_len
  , get: plutusList_get
  , add: plutusList_add
  }

instance HasFree PlutusList where
  free = plutusList.free

instance Show PlutusList where
  show = plutusList.toHex

instance MutableList PlutusList PlutusData where
  addItem = plutusList.add
  getItem = plutusList.get
  emptyList = plutusList.new

instance MutableLen PlutusList where
  getLen = plutusList.len


instance ToJsValue PlutusList where
  toJsValue = plutusList.toJsValue

instance IsHex PlutusList where
  toHex = plutusList.toHex
  fromHex = plutusList.fromHex

instance IsBytes PlutusList where
  toBytes = plutusList.toBytes
  fromBytes = plutusList.fromBytes

instance IsJson PlutusList where
  toJson = plutusList.toJson
  fromJson = plutusList.fromJson

-------------------------------------------------------------------------------------
-- Plutus map

foreign import plutusMap_free :: PlutusMap -> Effect Unit
foreign import plutusMap_toBytes :: PlutusMap -> Bytes
foreign import plutusMap_fromBytes :: Bytes -> PlutusMap
foreign import plutusMap_toHex :: PlutusMap -> String
foreign import plutusMap_fromHex :: String -> PlutusMap
foreign import plutusMap_toJson :: PlutusMap -> String
foreign import plutusMap_toJsValue :: PlutusMap -> PlutusMapJson
foreign import plutusMap_fromJson :: String -> PlutusMap
foreign import plutusMap_new :: Effect PlutusMap
foreign import plutusMap_len :: PlutusMap -> Effect Int
foreign import plutusMap_insert :: PlutusMap -> PlutusData -> PlutusData -> Effect (Nullable PlutusData)
foreign import plutusMap_get :: PlutusMap -> PlutusData -> Effect (Nullable PlutusData)
foreign import plutusMap_keys :: PlutusMap -> Effect PlutusList

-- | Plutus map class
type PlutusMapClass =
  { free :: PlutusMap -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: PlutusMap -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> PlutusMap
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: PlutusMap -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> PlutusMap
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: PlutusMap -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: PlutusMap -> PlutusMapJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> PlutusMap
    -- ^ From json
    -- > fromJson json
  , new :: Effect PlutusMap
    -- ^ New
    -- > new
  , len :: PlutusMap -> Effect Int
    -- ^ Len
    -- > len self
  , insert :: PlutusMap -> PlutusData -> PlutusData -> Effect (Maybe PlutusData)
    -- ^ Insert
    -- > insert self key value
  , get :: PlutusMap -> PlutusData -> Effect (Maybe PlutusData)
    -- ^ Get
    -- > get self key
  , keys :: PlutusMap -> Effect PlutusList
    -- ^ Keys
    -- > keys self
  }

-- | Plutus map class API
plutusMap :: PlutusMapClass
plutusMap =
  { free: plutusMap_free
  , toBytes: plutusMap_toBytes
  , fromBytes: plutusMap_fromBytes
  , toHex: plutusMap_toHex
  , fromHex: plutusMap_fromHex
  , toJson: plutusMap_toJson
  , toJsValue: plutusMap_toJsValue
  , fromJson: plutusMap_fromJson
  , new: plutusMap_new
  , len: plutusMap_len
  , insert: \a1 a2 a3 -> Nullable.toMaybe <$> plutusMap_insert a1 a2 a3
  , get: \a1 a2 -> Nullable.toMaybe <$> plutusMap_get a1 a2
  , keys: plutusMap_keys
  }

instance HasFree PlutusMap where
  free = plutusMap.free

instance Show PlutusMap where
  show = plutusMap.toHex

instance ToJsValue PlutusMap where
  toJsValue = plutusMap.toJsValue

instance IsHex PlutusMap where
  toHex = plutusMap.toHex
  fromHex = plutusMap.fromHex

instance IsBytes PlutusMap where
  toBytes = plutusMap.toBytes
  fromBytes = plutusMap.fromBytes

instance IsJson PlutusMap where
  toJson = plutusMap.toJson
  fromJson = plutusMap.fromJson

-------------------------------------------------------------------------------------
-- Plutus script

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

-- | Plutus script class
type PlutusScriptClass =
  { free :: PlutusScript -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: PlutusScript -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> PlutusScript
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: PlutusScript -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> PlutusScript
    -- ^ From hex
    -- > fromHex hexStr
  , new :: Bytes -> PlutusScript
    -- ^ New
    -- > new bytes
  , newV2 :: Bytes -> PlutusScript
    -- ^ New v2
    -- > newV2 bytes
  , newWithVersion :: Bytes -> Language -> PlutusScript
    -- ^ New with version
    -- > newWithVersion bytes language
  , bytes :: PlutusScript -> Bytes
    -- ^ Bytes
    -- > bytes self
  , fromBytesV2 :: Bytes -> PlutusScript
    -- ^ From bytes v2
    -- > fromBytesV2 bytes
  , fromBytesWithVersion :: Bytes -> Language -> PlutusScript
    -- ^ From bytes with version
    -- > fromBytesWithVersion bytes language
  , hash :: PlutusScript -> ScriptHash
    -- ^ Hash
    -- > hash self
  , languageVersion :: PlutusScript -> Language
    -- ^ Language version
    -- > languageVersion self
  }

-- | Plutus script class API
plutusScript :: PlutusScriptClass
plutusScript =
  { free: plutusScript_free
  , toBytes: plutusScript_toBytes
  , fromBytes: plutusScript_fromBytes
  , toHex: plutusScript_toHex
  , fromHex: plutusScript_fromHex
  , new: plutusScript_new
  , newV2: plutusScript_newV2
  , newWithVersion: plutusScript_newWithVersion
  , bytes: plutusScript_bytes
  , fromBytesV2: plutusScript_fromBytesV2
  , fromBytesWithVersion: plutusScript_fromBytesWithVersion
  , hash: plutusScript_hash
  , languageVersion: plutusScript_languageVersion
  }

instance HasFree PlutusScript where
  free = plutusScript.free

instance Show PlutusScript where
  show = plutusScript.toHex

instance IsHex PlutusScript where
  toHex = plutusScript.toHex
  fromHex = plutusScript.fromHex

instance IsBytes PlutusScript where
  toBytes = plutusScript.toBytes
  fromBytes = plutusScript.fromBytes

-------------------------------------------------------------------------------------
-- Plutus script source

foreign import plutusScriptSource_free :: PlutusScriptSource -> Effect Unit
foreign import plutusScriptSource_new :: PlutusScript -> PlutusScriptSource
foreign import plutusScriptSource_newRefIn :: ScriptHash -> TxIn -> PlutusScriptSource

-- | Plutus script source class
type PlutusScriptSourceClass =
  { free :: PlutusScriptSource -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: PlutusScript -> PlutusScriptSource
    -- ^ New
    -- > new script
  , newRefIn :: ScriptHash -> TxIn -> PlutusScriptSource
    -- ^ New ref input
    -- > newRefIn scriptHash in
  }

-- | Plutus script source class API
plutusScriptSource :: PlutusScriptSourceClass
plutusScriptSource =
  { free: plutusScriptSource_free
  , new: plutusScriptSource_new
  , newRefIn: plutusScriptSource_newRefIn
  }

instance HasFree PlutusScriptSource where
  free = plutusScriptSource.free

-------------------------------------------------------------------------------------
-- Plutus scripts

foreign import plutusScripts_free :: PlutusScripts -> Effect Unit
foreign import plutusScripts_toBytes :: PlutusScripts -> Bytes
foreign import plutusScripts_fromBytes :: Bytes -> PlutusScripts
foreign import plutusScripts_toHex :: PlutusScripts -> String
foreign import plutusScripts_fromHex :: String -> PlutusScripts
foreign import plutusScripts_toJson :: PlutusScripts -> String
foreign import plutusScripts_toJsValue :: PlutusScripts -> PlutusScriptsJson
foreign import plutusScripts_fromJson :: String -> PlutusScripts
foreign import plutusScripts_new :: Effect PlutusScripts
foreign import plutusScripts_len :: PlutusScripts -> Effect Int
foreign import plutusScripts_get :: PlutusScripts -> Int -> Effect PlutusScript
foreign import plutusScripts_add :: PlutusScripts -> PlutusScript -> Effect Unit

-- | Plutus scripts class
type PlutusScriptsClass =
  { free :: PlutusScripts -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: PlutusScripts -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> PlutusScripts
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: PlutusScripts -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> PlutusScripts
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: PlutusScripts -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: PlutusScripts -> PlutusScriptsJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> PlutusScripts
    -- ^ From json
    -- > fromJson json
  , new :: Effect PlutusScripts
    -- ^ New
    -- > new
  , len :: PlutusScripts -> Effect Int
    -- ^ Len
    -- > len self
  , get :: PlutusScripts -> Int -> Effect PlutusScript
    -- ^ Get
    -- > get self index
  , add :: PlutusScripts -> PlutusScript -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Plutus scripts class API
plutusScripts :: PlutusScriptsClass
plutusScripts =
  { free: plutusScripts_free
  , toBytes: plutusScripts_toBytes
  , fromBytes: plutusScripts_fromBytes
  , toHex: plutusScripts_toHex
  , fromHex: plutusScripts_fromHex
  , toJson: plutusScripts_toJson
  , toJsValue: plutusScripts_toJsValue
  , fromJson: plutusScripts_fromJson
  , new: plutusScripts_new
  , len: plutusScripts_len
  , get: plutusScripts_get
  , add: plutusScripts_add
  }

instance HasFree PlutusScripts where
  free = plutusScripts.free

instance Show PlutusScripts where
  show = plutusScripts.toHex

instance MutableList PlutusScripts PlutusScript where
  addItem = plutusScripts.add
  getItem = plutusScripts.get
  emptyList = plutusScripts.new

instance MutableLen PlutusScripts where
  getLen = plutusScripts.len


instance ToJsValue PlutusScripts where
  toJsValue = plutusScripts.toJsValue

instance IsHex PlutusScripts where
  toHex = plutusScripts.toHex
  fromHex = plutusScripts.fromHex

instance IsBytes PlutusScripts where
  toBytes = plutusScripts.toBytes
  fromBytes = plutusScripts.fromBytes

instance IsJson PlutusScripts where
  toJson = plutusScripts.toJson
  fromJson = plutusScripts.fromJson

-------------------------------------------------------------------------------------
-- Plutus witness

foreign import plutusWitness_free :: PlutusWitness -> Effect Unit
foreign import plutusWitness_new :: PlutusScript -> PlutusData -> Redeemer -> PlutusWitness
foreign import plutusWitness_newWithRef :: PlutusScriptSource -> DatumSource -> Redeemer -> PlutusWitness
foreign import plutusWitness_script :: PlutusWitness -> Nullable PlutusScript
foreign import plutusWitness_datum :: PlutusWitness -> Nullable PlutusData
foreign import plutusWitness_redeemer :: PlutusWitness -> Redeemer

-- | Plutus witness class
type PlutusWitnessClass =
  { free :: PlutusWitness -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: PlutusScript -> PlutusData -> Redeemer -> PlutusWitness
    -- ^ New
    -- > new script datum redeemer
  , newWithRef :: PlutusScriptSource -> DatumSource -> Redeemer -> PlutusWitness
    -- ^ New with ref
    -- > newWithRef script datum redeemer
  , script :: PlutusWitness -> Maybe PlutusScript
    -- ^ Script
    -- > script self
  , datum :: PlutusWitness -> Maybe PlutusData
    -- ^ Datum
    -- > datum self
  , redeemer :: PlutusWitness -> Redeemer
    -- ^ Redeemer
    -- > redeemer self
  }

-- | Plutus witness class API
plutusWitness :: PlutusWitnessClass
plutusWitness =
  { free: plutusWitness_free
  , new: plutusWitness_new
  , newWithRef: plutusWitness_newWithRef
  , script: \a1 -> Nullable.toMaybe $ plutusWitness_script a1
  , datum: \a1 -> Nullable.toMaybe $ plutusWitness_datum a1
  , redeemer: plutusWitness_redeemer
  }

instance HasFree PlutusWitness where
  free = plutusWitness.free

-------------------------------------------------------------------------------------
-- Plutus witnesses

foreign import plutusWitnesses_free :: PlutusWitnesses -> Effect Unit
foreign import plutusWitnesses_new :: Effect PlutusWitnesses
foreign import plutusWitnesses_len :: PlutusWitnesses -> Effect Int
foreign import plutusWitnesses_get :: PlutusWitnesses -> Int -> Effect PlutusWitness
foreign import plutusWitnesses_add :: PlutusWitnesses -> PlutusWitness -> Effect Unit

-- | Plutus witnesses class
type PlutusWitnessesClass =
  { free :: PlutusWitnesses -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: Effect PlutusWitnesses
    -- ^ New
    -- > new
  , len :: PlutusWitnesses -> Effect Int
    -- ^ Len
    -- > len self
  , get :: PlutusWitnesses -> Int -> Effect PlutusWitness
    -- ^ Get
    -- > get self index
  , add :: PlutusWitnesses -> PlutusWitness -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Plutus witnesses class API
plutusWitnesses :: PlutusWitnessesClass
plutusWitnesses =
  { free: plutusWitnesses_free
  , new: plutusWitnesses_new
  , len: plutusWitnesses_len
  , get: plutusWitnesses_get
  , add: plutusWitnesses_add
  }

instance HasFree PlutusWitnesses where
  free = plutusWitnesses.free

instance MutableList PlutusWitnesses PlutusWitness where
  addItem = plutusWitnesses.add
  getItem = plutusWitnesses.get
  emptyList = plutusWitnesses.new

instance MutableLen PlutusWitnesses where
  getLen = plutusWitnesses.len

-------------------------------------------------------------------------------------
-- Pointer

foreign import pointer_free :: Pointer -> Effect Unit
foreign import pointer_new :: Number -> Number -> Number -> Pointer
foreign import pointer_newPointer :: BigNum -> BigNum -> BigNum -> Pointer
foreign import pointer_slot :: Pointer -> Number
foreign import pointer_txIndex :: Pointer -> Number
foreign import pointer_certIndex :: Pointer -> Number
foreign import pointer_slotBignum :: Pointer -> BigNum
foreign import pointer_txIndexBignum :: Pointer -> BigNum
foreign import pointer_certIndexBignum :: Pointer -> BigNum

-- | Pointer class
type PointerClass =
  { free :: Pointer -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: Number -> Number -> Number -> Pointer
    -- ^ New
    -- > new slot txIndex certIndex
  , newPointer :: BigNum -> BigNum -> BigNum -> Pointer
    -- ^ New pointer
    -- > newPointer slot txIndex certIndex
  , slot :: Pointer -> Number
    -- ^ Slot
    -- > slot self
  , txIndex :: Pointer -> Number
    -- ^ Tx index
    -- > txIndex self
  , certIndex :: Pointer -> Number
    -- ^ Cert index
    -- > certIndex self
  , slotBignum :: Pointer -> BigNum
    -- ^ Slot bignum
    -- > slotBignum self
  , txIndexBignum :: Pointer -> BigNum
    -- ^ Tx index bignum
    -- > txIndexBignum self
  , certIndexBignum :: Pointer -> BigNum
    -- ^ Cert index bignum
    -- > certIndexBignum self
  }

-- | Pointer class API
pointer :: PointerClass
pointer =
  { free: pointer_free
  , new: pointer_new
  , newPointer: pointer_newPointer
  , slot: pointer_slot
  , txIndex: pointer_txIndex
  , certIndex: pointer_certIndex
  , slotBignum: pointer_slotBignum
  , txIndexBignum: pointer_txIndexBignum
  , certIndexBignum: pointer_certIndexBignum
  }

instance HasFree Pointer where
  free = pointer.free

-------------------------------------------------------------------------------------
-- Pointer address

foreign import pointerAddress_free :: PointerAddress -> Effect Unit
foreign import pointerAddress_new :: Number -> StakeCredential -> Pointer -> PointerAddress
foreign import pointerAddress_paymentCred :: PointerAddress -> StakeCredential
foreign import pointerAddress_stakePointer :: PointerAddress -> Pointer
foreign import pointerAddress_toAddress :: PointerAddress -> Address
foreign import pointerAddress_fromAddress :: Address -> Nullable PointerAddress

-- | Pointer address class
type PointerAddressClass =
  { free :: PointerAddress -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: Number -> StakeCredential -> Pointer -> PointerAddress
    -- ^ New
    -- > new network payment stake
  , paymentCred :: PointerAddress -> StakeCredential
    -- ^ Payment cred
    -- > paymentCred self
  , stakePointer :: PointerAddress -> Pointer
    -- ^ Stake pointer
    -- > stakePointer self
  , toAddress :: PointerAddress -> Address
    -- ^ To address
    -- > toAddress self
  , fromAddress :: Address -> Maybe PointerAddress
    -- ^ From address
    -- > fromAddress addr
  }

-- | Pointer address class API
pointerAddress :: PointerAddressClass
pointerAddress =
  { free: pointerAddress_free
  , new: pointerAddress_new
  , paymentCred: pointerAddress_paymentCred
  , stakePointer: pointerAddress_stakePointer
  , toAddress: pointerAddress_toAddress
  , fromAddress: \a1 -> Nullable.toMaybe $ pointerAddress_fromAddress a1
  }

instance HasFree PointerAddress where
  free = pointerAddress.free

-------------------------------------------------------------------------------------
-- Pool metadata

foreign import poolMetadata_free :: PoolMetadata -> Effect Unit
foreign import poolMetadata_toBytes :: PoolMetadata -> Bytes
foreign import poolMetadata_fromBytes :: Bytes -> PoolMetadata
foreign import poolMetadata_toHex :: PoolMetadata -> String
foreign import poolMetadata_fromHex :: String -> PoolMetadata
foreign import poolMetadata_toJson :: PoolMetadata -> String
foreign import poolMetadata_toJsValue :: PoolMetadata -> PoolMetadataJson
foreign import poolMetadata_fromJson :: String -> PoolMetadata
foreign import poolMetadata_url :: PoolMetadata -> URL
foreign import poolMetadata_poolMetadataHash :: PoolMetadata -> PoolMetadataHash
foreign import poolMetadata_new :: URL -> PoolMetadataHash -> PoolMetadata

-- | Pool metadata class
type PoolMetadataClass =
  { free :: PoolMetadata -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: PoolMetadata -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> PoolMetadata
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: PoolMetadata -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> PoolMetadata
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: PoolMetadata -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: PoolMetadata -> PoolMetadataJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> PoolMetadata
    -- ^ From json
    -- > fromJson json
  , url :: PoolMetadata -> URL
    -- ^ Url
    -- > url self
  , poolMetadataHash :: PoolMetadata -> PoolMetadataHash
    -- ^ Pool metadata hash
    -- > poolMetadataHash self
  , new :: URL -> PoolMetadataHash -> PoolMetadata
    -- ^ New
    -- > new url poolMetadataHash
  }

-- | Pool metadata class API
poolMetadata :: PoolMetadataClass
poolMetadata =
  { free: poolMetadata_free
  , toBytes: poolMetadata_toBytes
  , fromBytes: poolMetadata_fromBytes
  , toHex: poolMetadata_toHex
  , fromHex: poolMetadata_fromHex
  , toJson: poolMetadata_toJson
  , toJsValue: poolMetadata_toJsValue
  , fromJson: poolMetadata_fromJson
  , url: poolMetadata_url
  , poolMetadataHash: poolMetadata_poolMetadataHash
  , new: poolMetadata_new
  }

instance HasFree PoolMetadata where
  free = poolMetadata.free

instance Show PoolMetadata where
  show = poolMetadata.toHex

instance ToJsValue PoolMetadata where
  toJsValue = poolMetadata.toJsValue

instance IsHex PoolMetadata where
  toHex = poolMetadata.toHex
  fromHex = poolMetadata.fromHex

instance IsBytes PoolMetadata where
  toBytes = poolMetadata.toBytes
  fromBytes = poolMetadata.fromBytes

instance IsJson PoolMetadata where
  toJson = poolMetadata.toJson
  fromJson = poolMetadata.fromJson

-------------------------------------------------------------------------------------
-- Pool metadata hash

foreign import poolMetadataHash_free :: PoolMetadataHash -> Effect Unit
foreign import poolMetadataHash_fromBytes :: Bytes -> PoolMetadataHash
foreign import poolMetadataHash_toBytes :: PoolMetadataHash -> Bytes
foreign import poolMetadataHash_toBech32 :: PoolMetadataHash -> String -> String
foreign import poolMetadataHash_fromBech32 :: String -> PoolMetadataHash
foreign import poolMetadataHash_toHex :: PoolMetadataHash -> String
foreign import poolMetadataHash_fromHex :: String -> PoolMetadataHash

-- | Pool metadata hash class
type PoolMetadataHashClass =
  { free :: PoolMetadataHash -> Effect Unit
    -- ^ Free
    -- > free self
  , fromBytes :: Bytes -> PoolMetadataHash
    -- ^ From bytes
    -- > fromBytes bytes
  , toBytes :: PoolMetadataHash -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , toBech32 :: PoolMetadataHash -> String -> String
    -- ^ To bech32
    -- > toBech32 self prefix
  , fromBech32 :: String -> PoolMetadataHash
    -- ^ From bech32
    -- > fromBech32 bechStr
  , toHex :: PoolMetadataHash -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> PoolMetadataHash
    -- ^ From hex
    -- > fromHex hex
  }

-- | Pool metadata hash class API
poolMetadataHash :: PoolMetadataHashClass
poolMetadataHash =
  { free: poolMetadataHash_free
  , fromBytes: poolMetadataHash_fromBytes
  , toBytes: poolMetadataHash_toBytes
  , toBech32: poolMetadataHash_toBech32
  , fromBech32: poolMetadataHash_fromBech32
  , toHex: poolMetadataHash_toHex
  , fromHex: poolMetadataHash_fromHex
  }

instance HasFree PoolMetadataHash where
  free = poolMetadataHash.free

instance Show PoolMetadataHash where
  show = poolMetadataHash.toHex

instance IsHex PoolMetadataHash where
  toHex = poolMetadataHash.toHex
  fromHex = poolMetadataHash.fromHex

instance IsBytes PoolMetadataHash where
  toBytes = poolMetadataHash.toBytes
  fromBytes = poolMetadataHash.fromBytes

-------------------------------------------------------------------------------------
-- Pool params

foreign import poolParams_free :: PoolParams -> Effect Unit
foreign import poolParams_toBytes :: PoolParams -> Bytes
foreign import poolParams_fromBytes :: Bytes -> PoolParams
foreign import poolParams_toHex :: PoolParams -> String
foreign import poolParams_fromHex :: String -> PoolParams
foreign import poolParams_toJson :: PoolParams -> String
foreign import poolParams_toJsValue :: PoolParams -> PoolParamsJson
foreign import poolParams_fromJson :: String -> PoolParams
foreign import poolParams_operator :: PoolParams -> Ed25519KeyHash
foreign import poolParams_vrfKeyhash :: PoolParams -> VRFKeyHash
foreign import poolParams_pledge :: PoolParams -> BigNum
foreign import poolParams_cost :: PoolParams -> BigNum
foreign import poolParams_margin :: PoolParams -> UnitInterval
foreign import poolParams_rewardAccount :: PoolParams -> RewardAddress
foreign import poolParams_poolOwners :: PoolParams -> Ed25519KeyHashes
foreign import poolParams_relays :: PoolParams -> Relays
foreign import poolParams_poolMetadata :: PoolParams -> Nullable PoolMetadata
foreign import poolParams_new :: Ed25519KeyHash -> VRFKeyHash -> BigNum -> BigNum -> UnitInterval -> RewardAddress -> Ed25519KeyHashes -> Relays -> PoolMetadata -> PoolParams

-- | Pool params class
type PoolParamsClass =
  { free :: PoolParams -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: PoolParams -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> PoolParams
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: PoolParams -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> PoolParams
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: PoolParams -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: PoolParams -> PoolParamsJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> PoolParams
    -- ^ From json
    -- > fromJson json
  , operator :: PoolParams -> Ed25519KeyHash
    -- ^ Operator
    -- > operator self
  , vrfKeyhash :: PoolParams -> VRFKeyHash
    -- ^ Vrf keyhash
    -- > vrfKeyhash self
  , pledge :: PoolParams -> BigNum
    -- ^ Pledge
    -- > pledge self
  , cost :: PoolParams -> BigNum
    -- ^ Cost
    -- > cost self
  , margin :: PoolParams -> UnitInterval
    -- ^ Margin
    -- > margin self
  , rewardAccount :: PoolParams -> RewardAddress
    -- ^ Reward account
    -- > rewardAccount self
  , poolOwners :: PoolParams -> Ed25519KeyHashes
    -- ^ Pool owners
    -- > poolOwners self
  , relays :: PoolParams -> Relays
    -- ^ Relays
    -- > relays self
  , poolMetadata :: PoolParams -> Maybe PoolMetadata
    -- ^ Pool metadata
    -- > poolMetadata self
  , new :: Ed25519KeyHash -> VRFKeyHash -> BigNum -> BigNum -> UnitInterval -> RewardAddress -> Ed25519KeyHashes -> Relays -> PoolMetadata -> PoolParams
    -- ^ New
    -- > new operator vrfKeyhash pledge cost margin rewardAccount poolOwners relays poolMetadata
  }

-- | Pool params class API
poolParams :: PoolParamsClass
poolParams =
  { free: poolParams_free
  , toBytes: poolParams_toBytes
  , fromBytes: poolParams_fromBytes
  , toHex: poolParams_toHex
  , fromHex: poolParams_fromHex
  , toJson: poolParams_toJson
  , toJsValue: poolParams_toJsValue
  , fromJson: poolParams_fromJson
  , operator: poolParams_operator
  , vrfKeyhash: poolParams_vrfKeyhash
  , pledge: poolParams_pledge
  , cost: poolParams_cost
  , margin: poolParams_margin
  , rewardAccount: poolParams_rewardAccount
  , poolOwners: poolParams_poolOwners
  , relays: poolParams_relays
  , poolMetadata: \a1 -> Nullable.toMaybe $ poolParams_poolMetadata a1
  , new: poolParams_new
  }

instance HasFree PoolParams where
  free = poolParams.free

instance Show PoolParams where
  show = poolParams.toHex

instance ToJsValue PoolParams where
  toJsValue = poolParams.toJsValue

instance IsHex PoolParams where
  toHex = poolParams.toHex
  fromHex = poolParams.fromHex

instance IsBytes PoolParams where
  toBytes = poolParams.toBytes
  fromBytes = poolParams.fromBytes

instance IsJson PoolParams where
  toJson = poolParams.toJson
  fromJson = poolParams.fromJson

-------------------------------------------------------------------------------------
-- Pool registration

foreign import poolRegistration_free :: PoolRegistration -> Effect Unit
foreign import poolRegistration_toBytes :: PoolRegistration -> Bytes
foreign import poolRegistration_fromBytes :: Bytes -> PoolRegistration
foreign import poolRegistration_toHex :: PoolRegistration -> String
foreign import poolRegistration_fromHex :: String -> PoolRegistration
foreign import poolRegistration_toJson :: PoolRegistration -> String
foreign import poolRegistration_toJsValue :: PoolRegistration -> PoolRegistrationJson
foreign import poolRegistration_fromJson :: String -> PoolRegistration
foreign import poolRegistration_poolParams :: PoolRegistration -> PoolParams
foreign import poolRegistration_new :: PoolParams -> PoolRegistration

-- | Pool registration class
type PoolRegistrationClass =
  { free :: PoolRegistration -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: PoolRegistration -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> PoolRegistration
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: PoolRegistration -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> PoolRegistration
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: PoolRegistration -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: PoolRegistration -> PoolRegistrationJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> PoolRegistration
    -- ^ From json
    -- > fromJson json
  , poolParams :: PoolRegistration -> PoolParams
    -- ^ Pool params
    -- > poolParams self
  , new :: PoolParams -> PoolRegistration
    -- ^ New
    -- > new poolParams
  }

-- | Pool registration class API
poolRegistration :: PoolRegistrationClass
poolRegistration =
  { free: poolRegistration_free
  , toBytes: poolRegistration_toBytes
  , fromBytes: poolRegistration_fromBytes
  , toHex: poolRegistration_toHex
  , fromHex: poolRegistration_fromHex
  , toJson: poolRegistration_toJson
  , toJsValue: poolRegistration_toJsValue
  , fromJson: poolRegistration_fromJson
  , poolParams: poolRegistration_poolParams
  , new: poolRegistration_new
  }

instance HasFree PoolRegistration where
  free = poolRegistration.free

instance Show PoolRegistration where
  show = poolRegistration.toHex

instance ToJsValue PoolRegistration where
  toJsValue = poolRegistration.toJsValue

instance IsHex PoolRegistration where
  toHex = poolRegistration.toHex
  fromHex = poolRegistration.fromHex

instance IsBytes PoolRegistration where
  toBytes = poolRegistration.toBytes
  fromBytes = poolRegistration.fromBytes

instance IsJson PoolRegistration where
  toJson = poolRegistration.toJson
  fromJson = poolRegistration.fromJson

-------------------------------------------------------------------------------------
-- Pool retirement

foreign import poolRetirement_free :: PoolRetirement -> Effect Unit
foreign import poolRetirement_toBytes :: PoolRetirement -> Bytes
foreign import poolRetirement_fromBytes :: Bytes -> PoolRetirement
foreign import poolRetirement_toHex :: PoolRetirement -> String
foreign import poolRetirement_fromHex :: String -> PoolRetirement
foreign import poolRetirement_toJson :: PoolRetirement -> String
foreign import poolRetirement_toJsValue :: PoolRetirement -> PoolRetirementJson
foreign import poolRetirement_fromJson :: String -> PoolRetirement
foreign import poolRetirement_poolKeyhash :: PoolRetirement -> Ed25519KeyHash
foreign import poolRetirement_epoch :: PoolRetirement -> Number
foreign import poolRetirement_new :: Ed25519KeyHash -> Number -> PoolRetirement

-- | Pool retirement class
type PoolRetirementClass =
  { free :: PoolRetirement -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: PoolRetirement -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> PoolRetirement
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: PoolRetirement -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> PoolRetirement
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: PoolRetirement -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: PoolRetirement -> PoolRetirementJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> PoolRetirement
    -- ^ From json
    -- > fromJson json
  , poolKeyhash :: PoolRetirement -> Ed25519KeyHash
    -- ^ Pool keyhash
    -- > poolKeyhash self
  , epoch :: PoolRetirement -> Number
    -- ^ Epoch
    -- > epoch self
  , new :: Ed25519KeyHash -> Number -> PoolRetirement
    -- ^ New
    -- > new poolKeyhash epoch
  }

-- | Pool retirement class API
poolRetirement :: PoolRetirementClass
poolRetirement =
  { free: poolRetirement_free
  , toBytes: poolRetirement_toBytes
  , fromBytes: poolRetirement_fromBytes
  , toHex: poolRetirement_toHex
  , fromHex: poolRetirement_fromHex
  , toJson: poolRetirement_toJson
  , toJsValue: poolRetirement_toJsValue
  , fromJson: poolRetirement_fromJson
  , poolKeyhash: poolRetirement_poolKeyhash
  , epoch: poolRetirement_epoch
  , new: poolRetirement_new
  }

instance HasFree PoolRetirement where
  free = poolRetirement.free

instance Show PoolRetirement where
  show = poolRetirement.toHex

instance ToJsValue PoolRetirement where
  toJsValue = poolRetirement.toJsValue

instance IsHex PoolRetirement where
  toHex = poolRetirement.toHex
  fromHex = poolRetirement.fromHex

instance IsBytes PoolRetirement where
  toBytes = poolRetirement.toBytes
  fromBytes = poolRetirement.fromBytes

instance IsJson PoolRetirement where
  toJson = poolRetirement.toJson
  fromJson = poolRetirement.fromJson

-------------------------------------------------------------------------------------
-- Private key

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

-- | Private key class
type PrivateKeyClass =
  { free :: PrivateKey -> Effect Unit
    -- ^ Free
    -- > free self
  , toPublic :: PrivateKey -> PublicKey
    -- ^ To public
    -- > toPublic self
  , generateEd25519 :: PrivateKey
    -- ^ Generate ed25519
    -- > generateEd25519
  , generateEd25519extended :: PrivateKey
    -- ^ Generate ed25519extended
    -- > generateEd25519extended
  , fromBech32 :: String -> PrivateKey
    -- ^ From bech32
    -- > fromBech32 bech32Str
  , toBech32 :: PrivateKey -> String
    -- ^ To bech32
    -- > toBech32 self
  , asBytes :: PrivateKey -> Bytes
    -- ^ As bytes
    -- > asBytes self
  , fromExtendedBytes :: Bytes -> PrivateKey
    -- ^ From extended bytes
    -- > fromExtendedBytes bytes
  , fromNormalBytes :: Bytes -> PrivateKey
    -- ^ From normal bytes
    -- > fromNormalBytes bytes
  , sign :: PrivateKey -> Bytes -> Ed25519Signature
    -- ^ Sign
    -- > sign self message
  , toHex :: PrivateKey -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> PrivateKey
    -- ^ From hex
    -- > fromHex hexStr
  }

-- | Private key class API
privateKey :: PrivateKeyClass
privateKey =
  { free: privateKey_free
  , toPublic: privateKey_toPublic
  , generateEd25519: privateKey_generateEd25519
  , generateEd25519extended: privateKey_generateEd25519extended
  , fromBech32: privateKey_fromBech32
  , toBech32: privateKey_toBech32
  , asBytes: privateKey_asBytes
  , fromExtendedBytes: privateKey_fromExtendedBytes
  , fromNormalBytes: privateKey_fromNormalBytes
  , sign: privateKey_sign
  , toHex: privateKey_toHex
  , fromHex: privateKey_fromHex
  }

instance HasFree PrivateKey where
  free = privateKey.free

instance Show PrivateKey where
  show = privateKey.toHex

instance IsHex PrivateKey where
  toHex = privateKey.toHex
  fromHex = privateKey.fromHex

instance IsBech32 PrivateKey where
  toBech32 = privateKey.toBech32
  fromBech32 = privateKey.fromBech32

-------------------------------------------------------------------------------------
-- Proposed protocol parameter updates

foreign import proposedProtocolParameterUpdates_free :: ProposedProtocolParameterUpdates -> Effect Unit
foreign import proposedProtocolParameterUpdates_toBytes :: ProposedProtocolParameterUpdates -> Bytes
foreign import proposedProtocolParameterUpdates_fromBytes :: Bytes -> ProposedProtocolParameterUpdates
foreign import proposedProtocolParameterUpdates_toHex :: ProposedProtocolParameterUpdates -> String
foreign import proposedProtocolParameterUpdates_fromHex :: String -> ProposedProtocolParameterUpdates
foreign import proposedProtocolParameterUpdates_toJson :: ProposedProtocolParameterUpdates -> String
foreign import proposedProtocolParameterUpdates_toJsValue :: ProposedProtocolParameterUpdates -> ProposedProtocolParameterUpdatesJson
foreign import proposedProtocolParameterUpdates_fromJson :: String -> ProposedProtocolParameterUpdates
foreign import proposedProtocolParameterUpdates_new :: Effect ProposedProtocolParameterUpdates
foreign import proposedProtocolParameterUpdates_len :: ProposedProtocolParameterUpdates -> Effect Int
foreign import proposedProtocolParameterUpdates_insert :: ProposedProtocolParameterUpdates -> GenesisHash -> ProtocolParamUpdate -> Effect (Nullable ProtocolParamUpdate)
foreign import proposedProtocolParameterUpdates_get :: ProposedProtocolParameterUpdates -> GenesisHash -> Effect (Nullable ProtocolParamUpdate)
foreign import proposedProtocolParameterUpdates_keys :: ProposedProtocolParameterUpdates -> Effect GenesisHashes

-- | Proposed protocol parameter updates class
type ProposedProtocolParameterUpdatesClass =
  { free :: ProposedProtocolParameterUpdates -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: ProposedProtocolParameterUpdates -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> ProposedProtocolParameterUpdates
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: ProposedProtocolParameterUpdates -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> ProposedProtocolParameterUpdates
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: ProposedProtocolParameterUpdates -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: ProposedProtocolParameterUpdates -> ProposedProtocolParameterUpdatesJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> ProposedProtocolParameterUpdates
    -- ^ From json
    -- > fromJson json
  , new :: Effect ProposedProtocolParameterUpdates
    -- ^ New
    -- > new
  , len :: ProposedProtocolParameterUpdates -> Effect Int
    -- ^ Len
    -- > len self
  , insert :: ProposedProtocolParameterUpdates -> GenesisHash -> ProtocolParamUpdate -> Effect (Maybe ProtocolParamUpdate)
    -- ^ Insert
    -- > insert self key value
  , get :: ProposedProtocolParameterUpdates -> GenesisHash -> Effect (Maybe ProtocolParamUpdate)
    -- ^ Get
    -- > get self key
  , keys :: ProposedProtocolParameterUpdates -> Effect GenesisHashes
    -- ^ Keys
    -- > keys self
  }

-- | Proposed protocol parameter updates class API
proposedProtocolParameterUpdates :: ProposedProtocolParameterUpdatesClass
proposedProtocolParameterUpdates =
  { free: proposedProtocolParameterUpdates_free
  , toBytes: proposedProtocolParameterUpdates_toBytes
  , fromBytes: proposedProtocolParameterUpdates_fromBytes
  , toHex: proposedProtocolParameterUpdates_toHex
  , fromHex: proposedProtocolParameterUpdates_fromHex
  , toJson: proposedProtocolParameterUpdates_toJson
  , toJsValue: proposedProtocolParameterUpdates_toJsValue
  , fromJson: proposedProtocolParameterUpdates_fromJson
  , new: proposedProtocolParameterUpdates_new
  , len: proposedProtocolParameterUpdates_len
  , insert: \a1 a2 a3 -> Nullable.toMaybe <$> proposedProtocolParameterUpdates_insert a1 a2 a3
  , get: \a1 a2 -> Nullable.toMaybe <$> proposedProtocolParameterUpdates_get a1 a2
  , keys: proposedProtocolParameterUpdates_keys
  }

instance HasFree ProposedProtocolParameterUpdates where
  free = proposedProtocolParameterUpdates.free

instance Show ProposedProtocolParameterUpdates where
  show = proposedProtocolParameterUpdates.toHex

instance ToJsValue ProposedProtocolParameterUpdates where
  toJsValue = proposedProtocolParameterUpdates.toJsValue

instance IsHex ProposedProtocolParameterUpdates where
  toHex = proposedProtocolParameterUpdates.toHex
  fromHex = proposedProtocolParameterUpdates.fromHex

instance IsBytes ProposedProtocolParameterUpdates where
  toBytes = proposedProtocolParameterUpdates.toBytes
  fromBytes = proposedProtocolParameterUpdates.fromBytes

instance IsJson ProposedProtocolParameterUpdates where
  toJson = proposedProtocolParameterUpdates.toJson
  fromJson = proposedProtocolParameterUpdates.fromJson

-------------------------------------------------------------------------------------
-- Protocol param update

foreign import protocolParamUpdate_free :: ProtocolParamUpdate -> Effect Unit
foreign import protocolParamUpdate_toBytes :: ProtocolParamUpdate -> Bytes
foreign import protocolParamUpdate_fromBytes :: Bytes -> ProtocolParamUpdate
foreign import protocolParamUpdate_toHex :: ProtocolParamUpdate -> String
foreign import protocolParamUpdate_fromHex :: String -> ProtocolParamUpdate
foreign import protocolParamUpdate_toJson :: ProtocolParamUpdate -> String
foreign import protocolParamUpdate_toJsValue :: ProtocolParamUpdate -> ProtocolParamUpdateJson
foreign import protocolParamUpdate_fromJson :: String -> ProtocolParamUpdate
foreign import protocolParamUpdate_setMinfeeA :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_minfeeA :: ProtocolParamUpdate -> Nullable BigNum
foreign import protocolParamUpdate_setMinfeeB :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_minfeeB :: ProtocolParamUpdate -> Nullable BigNum
foreign import protocolParamUpdate_setMaxBlockBodySize :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_maxBlockBodySize :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_setMaxTxSize :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_maxTxSize :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_setMaxBlockHeaderSize :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_maxBlockHeaderSize :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_setKeyDeposit :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_keyDeposit :: ProtocolParamUpdate -> Nullable BigNum
foreign import protocolParamUpdate_setPoolDeposit :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_poolDeposit :: ProtocolParamUpdate -> Nullable BigNum
foreign import protocolParamUpdate_setMaxEpoch :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_maxEpoch :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_setNOpt :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_nOpt :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_setPoolPledgeInfluence :: ProtocolParamUpdate -> UnitInterval -> Effect Unit
foreign import protocolParamUpdate_poolPledgeInfluence :: ProtocolParamUpdate -> Nullable UnitInterval
foreign import protocolParamUpdate_setExpansionRate :: ProtocolParamUpdate -> UnitInterval -> Effect Unit
foreign import protocolParamUpdate_expansionRate :: ProtocolParamUpdate -> Nullable UnitInterval
foreign import protocolParamUpdate_setTreasuryGrowthRate :: ProtocolParamUpdate -> UnitInterval -> Effect Unit
foreign import protocolParamUpdate_treasuryGrowthRate :: ProtocolParamUpdate -> Nullable UnitInterval
foreign import protocolParamUpdate_d :: ProtocolParamUpdate -> Nullable UnitInterval
foreign import protocolParamUpdate_extraEntropy :: ProtocolParamUpdate -> Nullable Nonce
foreign import protocolParamUpdate_setProtocolVersion :: ProtocolParamUpdate -> ProtocolVersion -> Effect Unit
foreign import protocolParamUpdate_protocolVersion :: ProtocolParamUpdate -> Nullable ProtocolVersion
foreign import protocolParamUpdate_setMinPoolCost :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_minPoolCost :: ProtocolParamUpdate -> Nullable BigNum
foreign import protocolParamUpdate_setAdaPerUtxoByte :: ProtocolParamUpdate -> BigNum -> Effect Unit
foreign import protocolParamUpdate_adaPerUtxoByte :: ProtocolParamUpdate -> Nullable BigNum
foreign import protocolParamUpdate_setCostModels :: ProtocolParamUpdate -> Costmdls -> Effect Unit
foreign import protocolParamUpdate_costModels :: ProtocolParamUpdate -> Nullable Costmdls
foreign import protocolParamUpdate_setExecutionCosts :: ProtocolParamUpdate -> ExUnitPrices -> Effect Unit
foreign import protocolParamUpdate_executionCosts :: ProtocolParamUpdate -> Nullable ExUnitPrices
foreign import protocolParamUpdate_setMaxTxExUnits :: ProtocolParamUpdate -> ExUnits -> Effect Unit
foreign import protocolParamUpdate_maxTxExUnits :: ProtocolParamUpdate -> Nullable ExUnits
foreign import protocolParamUpdate_setMaxBlockExUnits :: ProtocolParamUpdate -> ExUnits -> Effect Unit
foreign import protocolParamUpdate_maxBlockExUnits :: ProtocolParamUpdate -> Nullable ExUnits
foreign import protocolParamUpdate_setMaxValueSize :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_maxValueSize :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_setCollateralPercentage :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_collateralPercentage :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_setMaxCollateralIns :: ProtocolParamUpdate -> Number -> Effect Unit
foreign import protocolParamUpdate_maxCollateralIns :: ProtocolParamUpdate -> Nullable Number
foreign import protocolParamUpdate_new :: ProtocolParamUpdate

-- | Protocol param update class
type ProtocolParamUpdateClass =
  { free :: ProtocolParamUpdate -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: ProtocolParamUpdate -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> ProtocolParamUpdate
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: ProtocolParamUpdate -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> ProtocolParamUpdate
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: ProtocolParamUpdate -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: ProtocolParamUpdate -> ProtocolParamUpdateJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> ProtocolParamUpdate
    -- ^ From json
    -- > fromJson json
  , setMinfeeA :: ProtocolParamUpdate -> BigNum -> Effect Unit
    -- ^ Set minfee a
    -- > setMinfeeA self minfeeA
  , minfeeA :: ProtocolParamUpdate -> Maybe BigNum
    -- ^ Minfee a
    -- > minfeeA self
  , setMinfeeB :: ProtocolParamUpdate -> BigNum -> Effect Unit
    -- ^ Set minfee b
    -- > setMinfeeB self minfeeB
  , minfeeB :: ProtocolParamUpdate -> Maybe BigNum
    -- ^ Minfee b
    -- > minfeeB self
  , setMaxBlockBodySize :: ProtocolParamUpdate -> Number -> Effect Unit
    -- ^ Set max block body size
    -- > setMaxBlockBodySize self maxBlockBodySize
  , maxBlockBodySize :: ProtocolParamUpdate -> Maybe Number
    -- ^ Max block body size
    -- > maxBlockBodySize self
  , setMaxTxSize :: ProtocolParamUpdate -> Number -> Effect Unit
    -- ^ Set max tx size
    -- > setMaxTxSize self maxTxSize
  , maxTxSize :: ProtocolParamUpdate -> Maybe Number
    -- ^ Max tx size
    -- > maxTxSize self
  , setMaxBlockHeaderSize :: ProtocolParamUpdate -> Number -> Effect Unit
    -- ^ Set max block header size
    -- > setMaxBlockHeaderSize self maxBlockHeaderSize
  , maxBlockHeaderSize :: ProtocolParamUpdate -> Maybe Number
    -- ^ Max block header size
    -- > maxBlockHeaderSize self
  , setKeyDeposit :: ProtocolParamUpdate -> BigNum -> Effect Unit
    -- ^ Set key deposit
    -- > setKeyDeposit self keyDeposit
  , keyDeposit :: ProtocolParamUpdate -> Maybe BigNum
    -- ^ Key deposit
    -- > keyDeposit self
  , setPoolDeposit :: ProtocolParamUpdate -> BigNum -> Effect Unit
    -- ^ Set pool deposit
    -- > setPoolDeposit self poolDeposit
  , poolDeposit :: ProtocolParamUpdate -> Maybe BigNum
    -- ^ Pool deposit
    -- > poolDeposit self
  , setMaxEpoch :: ProtocolParamUpdate -> Number -> Effect Unit
    -- ^ Set max epoch
    -- > setMaxEpoch self maxEpoch
  , maxEpoch :: ProtocolParamUpdate -> Maybe Number
    -- ^ Max epoch
    -- > maxEpoch self
  , setNOpt :: ProtocolParamUpdate -> Number -> Effect Unit
    -- ^ Set n opt
    -- > setNOpt self nOpt
  , nOpt :: ProtocolParamUpdate -> Maybe Number
    -- ^ N opt
    -- > nOpt self
  , setPoolPledgeInfluence :: ProtocolParamUpdate -> UnitInterval -> Effect Unit
    -- ^ Set pool pledge influence
    -- > setPoolPledgeInfluence self poolPledgeInfluence
  , poolPledgeInfluence :: ProtocolParamUpdate -> Maybe UnitInterval
    -- ^ Pool pledge influence
    -- > poolPledgeInfluence self
  , setExpansionRate :: ProtocolParamUpdate -> UnitInterval -> Effect Unit
    -- ^ Set expansion rate
    -- > setExpansionRate self expansionRate
  , expansionRate :: ProtocolParamUpdate -> Maybe UnitInterval
    -- ^ Expansion rate
    -- > expansionRate self
  , setTreasuryGrowthRate :: ProtocolParamUpdate -> UnitInterval -> Effect Unit
    -- ^ Set treasury growth rate
    -- > setTreasuryGrowthRate self treasuryGrowthRate
  , treasuryGrowthRate :: ProtocolParamUpdate -> Maybe UnitInterval
    -- ^ Treasury growth rate
    -- > treasuryGrowthRate self
  , d :: ProtocolParamUpdate -> Maybe UnitInterval
    -- ^ D
    -- > d self
  , extraEntropy :: ProtocolParamUpdate -> Maybe Nonce
    -- ^ Extra entropy
    -- > extraEntropy self
  , setProtocolVersion :: ProtocolParamUpdate -> ProtocolVersion -> Effect Unit
    -- ^ Set protocol version
    -- > setProtocolVersion self protocolVersion
  , protocolVersion :: ProtocolParamUpdate -> Maybe ProtocolVersion
    -- ^ Protocol version
    -- > protocolVersion self
  , setMinPoolCost :: ProtocolParamUpdate -> BigNum -> Effect Unit
    -- ^ Set min pool cost
    -- > setMinPoolCost self minPoolCost
  , minPoolCost :: ProtocolParamUpdate -> Maybe BigNum
    -- ^ Min pool cost
    -- > minPoolCost self
  , setAdaPerUtxoByte :: ProtocolParamUpdate -> BigNum -> Effect Unit
    -- ^ Set ada per utxo byte
    -- > setAdaPerUtxoByte self adaPerUtxoByte
  , adaPerUtxoByte :: ProtocolParamUpdate -> Maybe BigNum
    -- ^ Ada per utxo byte
    -- > adaPerUtxoByte self
  , setCostModels :: ProtocolParamUpdate -> Costmdls -> Effect Unit
    -- ^ Set cost models
    -- > setCostModels self costModels
  , costModels :: ProtocolParamUpdate -> Maybe Costmdls
    -- ^ Cost models
    -- > costModels self
  , setExecutionCosts :: ProtocolParamUpdate -> ExUnitPrices -> Effect Unit
    -- ^ Set execution costs
    -- > setExecutionCosts self executionCosts
  , executionCosts :: ProtocolParamUpdate -> Maybe ExUnitPrices
    -- ^ Execution costs
    -- > executionCosts self
  , setMaxTxExUnits :: ProtocolParamUpdate -> ExUnits -> Effect Unit
    -- ^ Set max tx ex units
    -- > setMaxTxExUnits self maxTxExUnits
  , maxTxExUnits :: ProtocolParamUpdate -> Maybe ExUnits
    -- ^ Max tx ex units
    -- > maxTxExUnits self
  , setMaxBlockExUnits :: ProtocolParamUpdate -> ExUnits -> Effect Unit
    -- ^ Set max block ex units
    -- > setMaxBlockExUnits self maxBlockExUnits
  , maxBlockExUnits :: ProtocolParamUpdate -> Maybe ExUnits
    -- ^ Max block ex units
    -- > maxBlockExUnits self
  , setMaxValueSize :: ProtocolParamUpdate -> Number -> Effect Unit
    -- ^ Set max value size
    -- > setMaxValueSize self maxValueSize
  , maxValueSize :: ProtocolParamUpdate -> Maybe Number
    -- ^ Max value size
    -- > maxValueSize self
  , setCollateralPercentage :: ProtocolParamUpdate -> Number -> Effect Unit
    -- ^ Set collateral percentage
    -- > setCollateralPercentage self collateralPercentage
  , collateralPercentage :: ProtocolParamUpdate -> Maybe Number
    -- ^ Collateral percentage
    -- > collateralPercentage self
  , setMaxCollateralIns :: ProtocolParamUpdate -> Number -> Effect Unit
    -- ^ Set max collateral inputs
    -- > setMaxCollateralIns self maxCollateralIns
  , maxCollateralIns :: ProtocolParamUpdate -> Maybe Number
    -- ^ Max collateral inputs
    -- > maxCollateralIns self
  , new :: ProtocolParamUpdate
    -- ^ New
    -- > new
  }

-- | Protocol param update class API
protocolParamUpdate :: ProtocolParamUpdateClass
protocolParamUpdate =
  { free: protocolParamUpdate_free
  , toBytes: protocolParamUpdate_toBytes
  , fromBytes: protocolParamUpdate_fromBytes
  , toHex: protocolParamUpdate_toHex
  , fromHex: protocolParamUpdate_fromHex
  , toJson: protocolParamUpdate_toJson
  , toJsValue: protocolParamUpdate_toJsValue
  , fromJson: protocolParamUpdate_fromJson
  , setMinfeeA: protocolParamUpdate_setMinfeeA
  , minfeeA: \a1 -> Nullable.toMaybe $ protocolParamUpdate_minfeeA a1
  , setMinfeeB: protocolParamUpdate_setMinfeeB
  , minfeeB: \a1 -> Nullable.toMaybe $ protocolParamUpdate_minfeeB a1
  , setMaxBlockBodySize: protocolParamUpdate_setMaxBlockBodySize
  , maxBlockBodySize: \a1 -> Nullable.toMaybe $ protocolParamUpdate_maxBlockBodySize a1
  , setMaxTxSize: protocolParamUpdate_setMaxTxSize
  , maxTxSize: \a1 -> Nullable.toMaybe $ protocolParamUpdate_maxTxSize a1
  , setMaxBlockHeaderSize: protocolParamUpdate_setMaxBlockHeaderSize
  , maxBlockHeaderSize: \a1 -> Nullable.toMaybe $ protocolParamUpdate_maxBlockHeaderSize a1
  , setKeyDeposit: protocolParamUpdate_setKeyDeposit
  , keyDeposit: \a1 -> Nullable.toMaybe $ protocolParamUpdate_keyDeposit a1
  , setPoolDeposit: protocolParamUpdate_setPoolDeposit
  , poolDeposit: \a1 -> Nullable.toMaybe $ protocolParamUpdate_poolDeposit a1
  , setMaxEpoch: protocolParamUpdate_setMaxEpoch
  , maxEpoch: \a1 -> Nullable.toMaybe $ protocolParamUpdate_maxEpoch a1
  , setNOpt: protocolParamUpdate_setNOpt
  , nOpt: \a1 -> Nullable.toMaybe $ protocolParamUpdate_nOpt a1
  , setPoolPledgeInfluence: protocolParamUpdate_setPoolPledgeInfluence
  , poolPledgeInfluence: \a1 -> Nullable.toMaybe $ protocolParamUpdate_poolPledgeInfluence a1
  , setExpansionRate: protocolParamUpdate_setExpansionRate
  , expansionRate: \a1 -> Nullable.toMaybe $ protocolParamUpdate_expansionRate a1
  , setTreasuryGrowthRate: protocolParamUpdate_setTreasuryGrowthRate
  , treasuryGrowthRate: \a1 -> Nullable.toMaybe $ protocolParamUpdate_treasuryGrowthRate a1
  , d: \a1 -> Nullable.toMaybe $ protocolParamUpdate_d a1
  , extraEntropy: \a1 -> Nullable.toMaybe $ protocolParamUpdate_extraEntropy a1
  , setProtocolVersion: protocolParamUpdate_setProtocolVersion
  , protocolVersion: \a1 -> Nullable.toMaybe $ protocolParamUpdate_protocolVersion a1
  , setMinPoolCost: protocolParamUpdate_setMinPoolCost
  , minPoolCost: \a1 -> Nullable.toMaybe $ protocolParamUpdate_minPoolCost a1
  , setAdaPerUtxoByte: protocolParamUpdate_setAdaPerUtxoByte
  , adaPerUtxoByte: \a1 -> Nullable.toMaybe $ protocolParamUpdate_adaPerUtxoByte a1
  , setCostModels: protocolParamUpdate_setCostModels
  , costModels: \a1 -> Nullable.toMaybe $ protocolParamUpdate_costModels a1
  , setExecutionCosts: protocolParamUpdate_setExecutionCosts
  , executionCosts: \a1 -> Nullable.toMaybe $ protocolParamUpdate_executionCosts a1
  , setMaxTxExUnits: protocolParamUpdate_setMaxTxExUnits
  , maxTxExUnits: \a1 -> Nullable.toMaybe $ protocolParamUpdate_maxTxExUnits a1
  , setMaxBlockExUnits: protocolParamUpdate_setMaxBlockExUnits
  , maxBlockExUnits: \a1 -> Nullable.toMaybe $ protocolParamUpdate_maxBlockExUnits a1
  , setMaxValueSize: protocolParamUpdate_setMaxValueSize
  , maxValueSize: \a1 -> Nullable.toMaybe $ protocolParamUpdate_maxValueSize a1
  , setCollateralPercentage: protocolParamUpdate_setCollateralPercentage
  , collateralPercentage: \a1 -> Nullable.toMaybe $ protocolParamUpdate_collateralPercentage a1
  , setMaxCollateralIns: protocolParamUpdate_setMaxCollateralIns
  , maxCollateralIns: \a1 -> Nullable.toMaybe $ protocolParamUpdate_maxCollateralIns a1
  , new: protocolParamUpdate_new
  }

instance HasFree ProtocolParamUpdate where
  free = protocolParamUpdate.free

instance Show ProtocolParamUpdate where
  show = protocolParamUpdate.toHex

instance ToJsValue ProtocolParamUpdate where
  toJsValue = protocolParamUpdate.toJsValue

instance IsHex ProtocolParamUpdate where
  toHex = protocolParamUpdate.toHex
  fromHex = protocolParamUpdate.fromHex

instance IsBytes ProtocolParamUpdate where
  toBytes = protocolParamUpdate.toBytes
  fromBytes = protocolParamUpdate.fromBytes

instance IsJson ProtocolParamUpdate where
  toJson = protocolParamUpdate.toJson
  fromJson = protocolParamUpdate.fromJson

-------------------------------------------------------------------------------------
-- Protocol version

foreign import protocolVersion_free :: ProtocolVersion -> Effect Unit
foreign import protocolVersion_toBytes :: ProtocolVersion -> Bytes
foreign import protocolVersion_fromBytes :: Bytes -> ProtocolVersion
foreign import protocolVersion_toHex :: ProtocolVersion -> String
foreign import protocolVersion_fromHex :: String -> ProtocolVersion
foreign import protocolVersion_toJson :: ProtocolVersion -> String
foreign import protocolVersion_toJsValue :: ProtocolVersion -> ProtocolVersionJson
foreign import protocolVersion_fromJson :: String -> ProtocolVersion
foreign import protocolVersion_major :: ProtocolVersion -> Number
foreign import protocolVersion_minor :: ProtocolVersion -> Number
foreign import protocolVersion_new :: Number -> Number -> ProtocolVersion

-- | Protocol version class
type ProtocolVersionClass =
  { free :: ProtocolVersion -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: ProtocolVersion -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> ProtocolVersion
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: ProtocolVersion -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> ProtocolVersion
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: ProtocolVersion -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: ProtocolVersion -> ProtocolVersionJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> ProtocolVersion
    -- ^ From json
    -- > fromJson json
  , major :: ProtocolVersion -> Number
    -- ^ Major
    -- > major self
  , minor :: ProtocolVersion -> Number
    -- ^ Minor
    -- > minor self
  , new :: Number -> Number -> ProtocolVersion
    -- ^ New
    -- > new major minor
  }

-- | Protocol version class API
protocolVersion :: ProtocolVersionClass
protocolVersion =
  { free: protocolVersion_free
  , toBytes: protocolVersion_toBytes
  , fromBytes: protocolVersion_fromBytes
  , toHex: protocolVersion_toHex
  , fromHex: protocolVersion_fromHex
  , toJson: protocolVersion_toJson
  , toJsValue: protocolVersion_toJsValue
  , fromJson: protocolVersion_fromJson
  , major: protocolVersion_major
  , minor: protocolVersion_minor
  , new: protocolVersion_new
  }

instance HasFree ProtocolVersion where
  free = protocolVersion.free

instance Show ProtocolVersion where
  show = protocolVersion.toHex

instance ToJsValue ProtocolVersion where
  toJsValue = protocolVersion.toJsValue

instance IsHex ProtocolVersion where
  toHex = protocolVersion.toHex
  fromHex = protocolVersion.fromHex

instance IsBytes ProtocolVersion where
  toBytes = protocolVersion.toBytes
  fromBytes = protocolVersion.fromBytes

instance IsJson ProtocolVersion where
  toJson = protocolVersion.toJson
  fromJson = protocolVersion.fromJson

-------------------------------------------------------------------------------------
-- Public key

foreign import publicKey_free :: PublicKey -> Effect Unit
foreign import publicKey_fromBech32 :: String -> PublicKey
foreign import publicKey_toBech32 :: PublicKey -> String
foreign import publicKey_asBytes :: PublicKey -> Bytes
foreign import publicKey_fromBytes :: Bytes -> PublicKey
foreign import publicKey_verify :: PublicKey -> Bytes -> Ed25519Signature -> Boolean
foreign import publicKey_hash :: PublicKey -> Ed25519KeyHash
foreign import publicKey_toHex :: PublicKey -> String
foreign import publicKey_fromHex :: String -> PublicKey

-- | Public key class
type PublicKeyClass =
  { free :: PublicKey -> Effect Unit
    -- ^ Free
    -- > free self
  , fromBech32 :: String -> PublicKey
    -- ^ From bech32
    -- > fromBech32 bech32Str
  , toBech32 :: PublicKey -> String
    -- ^ To bech32
    -- > toBech32 self
  , asBytes :: PublicKey -> Bytes
    -- ^ As bytes
    -- > asBytes self
  , fromBytes :: Bytes -> PublicKey
    -- ^ From bytes
    -- > fromBytes bytes
  , verify :: PublicKey -> Bytes -> Ed25519Signature -> Boolean
    -- ^ Verify
    -- > verify self data signature
  , hash :: PublicKey -> Ed25519KeyHash
    -- ^ Hash
    -- > hash self
  , toHex :: PublicKey -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> PublicKey
    -- ^ From hex
    -- > fromHex hexStr
  }

-- | Public key class API
publicKey :: PublicKeyClass
publicKey =
  { free: publicKey_free
  , fromBech32: publicKey_fromBech32
  , toBech32: publicKey_toBech32
  , asBytes: publicKey_asBytes
  , fromBytes: publicKey_fromBytes
  , verify: publicKey_verify
  , hash: publicKey_hash
  , toHex: publicKey_toHex
  , fromHex: publicKey_fromHex
  }

instance HasFree PublicKey where
  free = publicKey.free

instance Show PublicKey where
  show = publicKey.toHex

instance IsHex PublicKey where
  toHex = publicKey.toHex
  fromHex = publicKey.fromHex

instance IsBech32 PublicKey where
  toBech32 = publicKey.toBech32
  fromBech32 = publicKey.fromBech32

-------------------------------------------------------------------------------------
-- Public keys

foreign import publicKeys_free :: PublicKeys -> Effect Unit
foreign import publicKeys_constructor :: PublicKeys -> This
foreign import publicKeys_size :: PublicKeys -> Number
foreign import publicKeys_get :: PublicKeys -> Number -> PublicKey
foreign import publicKeys_add :: PublicKeys -> PublicKey -> Effect Unit

-- | Public keys class
type PublicKeysClass =
  { free :: PublicKeys -> Effect Unit
    -- ^ Free
    -- > free self
  , constructor :: PublicKeys -> This
    -- ^ Constructor
    -- > constructor self
  , size :: PublicKeys -> Number
    -- ^ Size
    -- > size self
  , get :: PublicKeys -> Number -> PublicKey
    -- ^ Get
    -- > get self index
  , add :: PublicKeys -> PublicKey -> Effect Unit
    -- ^ Add
    -- > add self key
  }

-- | Public keys class API
publicKeys :: PublicKeysClass
publicKeys =
  { free: publicKeys_free
  , constructor: publicKeys_constructor
  , size: publicKeys_size
  , get: publicKeys_get
  , add: publicKeys_add
  }

instance HasFree PublicKeys where
  free = publicKeys.free

-------------------------------------------------------------------------------------
-- Redeemer

foreign import redeemer_free :: Redeemer -> Effect Unit
foreign import redeemer_toBytes :: Redeemer -> Bytes
foreign import redeemer_fromBytes :: Bytes -> Redeemer
foreign import redeemer_toHex :: Redeemer -> String
foreign import redeemer_fromHex :: String -> Redeemer
foreign import redeemer_toJson :: Redeemer -> String
foreign import redeemer_toJsValue :: Redeemer -> RedeemerJson
foreign import redeemer_fromJson :: String -> Redeemer
foreign import redeemer_tag :: Redeemer -> RedeemerTag
foreign import redeemer_index :: Redeemer -> BigNum
foreign import redeemer_data :: Redeemer -> PlutusData
foreign import redeemer_exUnits :: Redeemer -> ExUnits
foreign import redeemer_new :: RedeemerTag -> BigNum -> PlutusData -> ExUnits -> Redeemer

-- | Redeemer class
type RedeemerClass =
  { free :: Redeemer -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Redeemer -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Redeemer
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Redeemer -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Redeemer
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Redeemer -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Redeemer -> RedeemerJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Redeemer
    -- ^ From json
    -- > fromJson json
  , tag :: Redeemer -> RedeemerTag
    -- ^ Tag
    -- > tag self
  , index :: Redeemer -> BigNum
    -- ^ Index
    -- > index self
  , data :: Redeemer -> PlutusData
    -- ^ Data
    -- > data self
  , exUnits :: Redeemer -> ExUnits
    -- ^ Ex units
    -- > exUnits self
  , new :: RedeemerTag -> BigNum -> PlutusData -> ExUnits -> Redeemer
    -- ^ New
    -- > new tag index data exUnits
  }

-- | Redeemer class API
redeemer :: RedeemerClass
redeemer =
  { free: redeemer_free
  , toBytes: redeemer_toBytes
  , fromBytes: redeemer_fromBytes
  , toHex: redeemer_toHex
  , fromHex: redeemer_fromHex
  , toJson: redeemer_toJson
  , toJsValue: redeemer_toJsValue
  , fromJson: redeemer_fromJson
  , tag: redeemer_tag
  , index: redeemer_index
  , data: redeemer_data
  , exUnits: redeemer_exUnits
  , new: redeemer_new
  }

instance HasFree Redeemer where
  free = redeemer.free

instance Show Redeemer where
  show = redeemer.toHex

instance ToJsValue Redeemer where
  toJsValue = redeemer.toJsValue

instance IsHex Redeemer where
  toHex = redeemer.toHex
  fromHex = redeemer.fromHex

instance IsBytes Redeemer where
  toBytes = redeemer.toBytes
  fromBytes = redeemer.fromBytes

instance IsJson Redeemer where
  toJson = redeemer.toJson
  fromJson = redeemer.fromJson

-------------------------------------------------------------------------------------
-- Redeemer tag

foreign import redeemerTag_free :: RedeemerTag -> Effect Unit
foreign import redeemerTag_toBytes :: RedeemerTag -> Bytes
foreign import redeemerTag_fromBytes :: Bytes -> RedeemerTag
foreign import redeemerTag_toHex :: RedeemerTag -> String
foreign import redeemerTag_fromHex :: String -> RedeemerTag
foreign import redeemerTag_toJson :: RedeemerTag -> String
foreign import redeemerTag_toJsValue :: RedeemerTag -> RedeemerTagJson
foreign import redeemerTag_fromJson :: String -> RedeemerTag
foreign import redeemerTag_newSpend :: RedeemerTag
foreign import redeemerTag_newMint :: RedeemerTag
foreign import redeemerTag_newCert :: RedeemerTag
foreign import redeemerTag_newReward :: RedeemerTag
foreign import redeemerTag_kind :: RedeemerTag -> Number

-- | Redeemer tag class
type RedeemerTagClass =
  { free :: RedeemerTag -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: RedeemerTag -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> RedeemerTag
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: RedeemerTag -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> RedeemerTag
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: RedeemerTag -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: RedeemerTag -> RedeemerTagJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> RedeemerTag
    -- ^ From json
    -- > fromJson json
  , newSpend :: RedeemerTag
    -- ^ New spend
    -- > newSpend
  , newMint :: RedeemerTag
    -- ^ New mint
    -- > newMint
  , newCert :: RedeemerTag
    -- ^ New cert
    -- > newCert
  , newReward :: RedeemerTag
    -- ^ New reward
    -- > newReward
  , kind :: RedeemerTag -> Number
    -- ^ Kind
    -- > kind self
  }

-- | Redeemer tag class API
redeemerTag :: RedeemerTagClass
redeemerTag =
  { free: redeemerTag_free
  , toBytes: redeemerTag_toBytes
  , fromBytes: redeemerTag_fromBytes
  , toHex: redeemerTag_toHex
  , fromHex: redeemerTag_fromHex
  , toJson: redeemerTag_toJson
  , toJsValue: redeemerTag_toJsValue
  , fromJson: redeemerTag_fromJson
  , newSpend: redeemerTag_newSpend
  , newMint: redeemerTag_newMint
  , newCert: redeemerTag_newCert
  , newReward: redeemerTag_newReward
  , kind: redeemerTag_kind
  }

instance HasFree RedeemerTag where
  free = redeemerTag.free

instance Show RedeemerTag where
  show = redeemerTag.toHex

instance ToJsValue RedeemerTag where
  toJsValue = redeemerTag.toJsValue

instance IsHex RedeemerTag where
  toHex = redeemerTag.toHex
  fromHex = redeemerTag.fromHex

instance IsBytes RedeemerTag where
  toBytes = redeemerTag.toBytes
  fromBytes = redeemerTag.fromBytes

instance IsJson RedeemerTag where
  toJson = redeemerTag.toJson
  fromJson = redeemerTag.fromJson

-------------------------------------------------------------------------------------
-- Redeemers

foreign import redeemers_free :: Redeemers -> Effect Unit
foreign import redeemers_toBytes :: Redeemers -> Bytes
foreign import redeemers_fromBytes :: Bytes -> Redeemers
foreign import redeemers_toHex :: Redeemers -> String
foreign import redeemers_fromHex :: String -> Redeemers
foreign import redeemers_toJson :: Redeemers -> String
foreign import redeemers_toJsValue :: Redeemers -> RedeemersJson
foreign import redeemers_fromJson :: String -> Redeemers
foreign import redeemers_new :: Effect Redeemers
foreign import redeemers_len :: Redeemers -> Effect Int
foreign import redeemers_get :: Redeemers -> Int -> Effect Redeemer
foreign import redeemers_add :: Redeemers -> Redeemer -> Effect Unit
foreign import redeemers_totalExUnits :: Redeemers -> ExUnits

-- | Redeemers class
type RedeemersClass =
  { free :: Redeemers -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Redeemers -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Redeemers
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Redeemers -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Redeemers
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Redeemers -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Redeemers -> RedeemersJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Redeemers
    -- ^ From json
    -- > fromJson json
  , new :: Effect Redeemers
    -- ^ New
    -- > new
  , len :: Redeemers -> Effect Int
    -- ^ Len
    -- > len self
  , get :: Redeemers -> Int -> Effect Redeemer
    -- ^ Get
    -- > get self index
  , add :: Redeemers -> Redeemer -> Effect Unit
    -- ^ Add
    -- > add self elem
  , totalExUnits :: Redeemers -> ExUnits
    -- ^ Total ex units
    -- > totalExUnits self
  }

-- | Redeemers class API
redeemers :: RedeemersClass
redeemers =
  { free: redeemers_free
  , toBytes: redeemers_toBytes
  , fromBytes: redeemers_fromBytes
  , toHex: redeemers_toHex
  , fromHex: redeemers_fromHex
  , toJson: redeemers_toJson
  , toJsValue: redeemers_toJsValue
  , fromJson: redeemers_fromJson
  , new: redeemers_new
  , len: redeemers_len
  , get: redeemers_get
  , add: redeemers_add
  , totalExUnits: redeemers_totalExUnits
  }

instance HasFree Redeemers where
  free = redeemers.free

instance Show Redeemers where
  show = redeemers.toHex

instance MutableList Redeemers Redeemer where
  addItem = redeemers.add
  getItem = redeemers.get
  emptyList = redeemers.new

instance MutableLen Redeemers where
  getLen = redeemers.len


instance ToJsValue Redeemers where
  toJsValue = redeemers.toJsValue

instance IsHex Redeemers where
  toHex = redeemers.toHex
  fromHex = redeemers.fromHex

instance IsBytes Redeemers where
  toBytes = redeemers.toBytes
  fromBytes = redeemers.fromBytes

instance IsJson Redeemers where
  toJson = redeemers.toJson
  fromJson = redeemers.fromJson

-------------------------------------------------------------------------------------
-- Relay

foreign import relay_free :: Relay -> Effect Unit
foreign import relay_toBytes :: Relay -> Bytes
foreign import relay_fromBytes :: Bytes -> Relay
foreign import relay_toHex :: Relay -> String
foreign import relay_fromHex :: String -> Relay
foreign import relay_toJson :: Relay -> String
foreign import relay_toJsValue :: Relay -> RelayJson
foreign import relay_fromJson :: String -> Relay
foreign import relay_newSingleHostAddr :: SingleHostAddr -> Relay
foreign import relay_newSingleHostName :: SingleHostName -> Relay
foreign import relay_newMultiHostName :: MultiHostName -> Relay
foreign import relay_kind :: Relay -> Number
foreign import relay_asSingleHostAddr :: Relay -> Nullable SingleHostAddr
foreign import relay_asSingleHostName :: Relay -> Nullable SingleHostName
foreign import relay_asMultiHostName :: Relay -> Nullable MultiHostName

-- | Relay class
type RelayClass =
  { free :: Relay -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Relay -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Relay
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Relay -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Relay
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Relay -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Relay -> RelayJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Relay
    -- ^ From json
    -- > fromJson json
  , newSingleHostAddr :: SingleHostAddr -> Relay
    -- ^ New single host addr
    -- > newSingleHostAddr singleHostAddr
  , newSingleHostName :: SingleHostName -> Relay
    -- ^ New single host name
    -- > newSingleHostName singleHostName
  , newMultiHostName :: MultiHostName -> Relay
    -- ^ New multi host name
    -- > newMultiHostName multiHostName
  , kind :: Relay -> Number
    -- ^ Kind
    -- > kind self
  , asSingleHostAddr :: Relay -> Maybe SingleHostAddr
    -- ^ As single host addr
    -- > asSingleHostAddr self
  , asSingleHostName :: Relay -> Maybe SingleHostName
    -- ^ As single host name
    -- > asSingleHostName self
  , asMultiHostName :: Relay -> Maybe MultiHostName
    -- ^ As multi host name
    -- > asMultiHostName self
  }

-- | Relay class API
relay :: RelayClass
relay =
  { free: relay_free
  , toBytes: relay_toBytes
  , fromBytes: relay_fromBytes
  , toHex: relay_toHex
  , fromHex: relay_fromHex
  , toJson: relay_toJson
  , toJsValue: relay_toJsValue
  , fromJson: relay_fromJson
  , newSingleHostAddr: relay_newSingleHostAddr
  , newSingleHostName: relay_newSingleHostName
  , newMultiHostName: relay_newMultiHostName
  , kind: relay_kind
  , asSingleHostAddr: \a1 -> Nullable.toMaybe $ relay_asSingleHostAddr a1
  , asSingleHostName: \a1 -> Nullable.toMaybe $ relay_asSingleHostName a1
  , asMultiHostName: \a1 -> Nullable.toMaybe $ relay_asMultiHostName a1
  }

instance HasFree Relay where
  free = relay.free

instance Show Relay where
  show = relay.toHex

instance ToJsValue Relay where
  toJsValue = relay.toJsValue

instance IsHex Relay where
  toHex = relay.toHex
  fromHex = relay.fromHex

instance IsBytes Relay where
  toBytes = relay.toBytes
  fromBytes = relay.fromBytes

instance IsJson Relay where
  toJson = relay.toJson
  fromJson = relay.fromJson

-------------------------------------------------------------------------------------
-- Relays

foreign import relays_free :: Relays -> Effect Unit
foreign import relays_toBytes :: Relays -> Bytes
foreign import relays_fromBytes :: Bytes -> Relays
foreign import relays_toHex :: Relays -> String
foreign import relays_fromHex :: String -> Relays
foreign import relays_toJson :: Relays -> String
foreign import relays_toJsValue :: Relays -> RelaysJson
foreign import relays_fromJson :: String -> Relays
foreign import relays_new :: Effect Relays
foreign import relays_len :: Relays -> Effect Int
foreign import relays_get :: Relays -> Int -> Effect Relay
foreign import relays_add :: Relays -> Relay -> Effect Unit

-- | Relays class
type RelaysClass =
  { free :: Relays -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Relays -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Relays
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Relays -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Relays
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Relays -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Relays -> RelaysJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Relays
    -- ^ From json
    -- > fromJson json
  , new :: Effect Relays
    -- ^ New
    -- > new
  , len :: Relays -> Effect Int
    -- ^ Len
    -- > len self
  , get :: Relays -> Int -> Effect Relay
    -- ^ Get
    -- > get self index
  , add :: Relays -> Relay -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Relays class API
relays :: RelaysClass
relays =
  { free: relays_free
  , toBytes: relays_toBytes
  , fromBytes: relays_fromBytes
  , toHex: relays_toHex
  , fromHex: relays_fromHex
  , toJson: relays_toJson
  , toJsValue: relays_toJsValue
  , fromJson: relays_fromJson
  , new: relays_new
  , len: relays_len
  , get: relays_get
  , add: relays_add
  }

instance HasFree Relays where
  free = relays.free

instance Show Relays where
  show = relays.toHex

instance MutableList Relays Relay where
  addItem = relays.add
  getItem = relays.get
  emptyList = relays.new

instance MutableLen Relays where
  getLen = relays.len


instance ToJsValue Relays where
  toJsValue = relays.toJsValue

instance IsHex Relays where
  toHex = relays.toHex
  fromHex = relays.fromHex

instance IsBytes Relays where
  toBytes = relays.toBytes
  fromBytes = relays.fromBytes

instance IsJson Relays where
  toJson = relays.toJson
  fromJson = relays.fromJson

-------------------------------------------------------------------------------------
-- Reward address

foreign import rewardAddress_free :: RewardAddress -> Effect Unit
foreign import rewardAddress_new :: Number -> StakeCredential -> RewardAddress
foreign import rewardAddress_paymentCred :: RewardAddress -> StakeCredential
foreign import rewardAddress_toAddress :: RewardAddress -> Address
foreign import rewardAddress_fromAddress :: Address -> Nullable RewardAddress

-- | Reward address class
type RewardAddressClass =
  { free :: RewardAddress -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: Number -> StakeCredential -> RewardAddress
    -- ^ New
    -- > new network payment
  , paymentCred :: RewardAddress -> StakeCredential
    -- ^ Payment cred
    -- > paymentCred self
  , toAddress :: RewardAddress -> Address
    -- ^ To address
    -- > toAddress self
  , fromAddress :: Address -> Maybe RewardAddress
    -- ^ From address
    -- > fromAddress addr
  }

-- | Reward address class API
rewardAddress :: RewardAddressClass
rewardAddress =
  { free: rewardAddress_free
  , new: rewardAddress_new
  , paymentCred: rewardAddress_paymentCred
  , toAddress: rewardAddress_toAddress
  , fromAddress: \a1 -> Nullable.toMaybe $ rewardAddress_fromAddress a1
  }

instance HasFree RewardAddress where
  free = rewardAddress.free

-------------------------------------------------------------------------------------
-- Reward addresses

foreign import rewardAddresses_free :: RewardAddresses -> Effect Unit
foreign import rewardAddresses_toBytes :: RewardAddresses -> Bytes
foreign import rewardAddresses_fromBytes :: Bytes -> RewardAddresses
foreign import rewardAddresses_toHex :: RewardAddresses -> String
foreign import rewardAddresses_fromHex :: String -> RewardAddresses
foreign import rewardAddresses_toJson :: RewardAddresses -> String
foreign import rewardAddresses_toJsValue :: RewardAddresses -> RewardAddressesJson
foreign import rewardAddresses_fromJson :: String -> RewardAddresses
foreign import rewardAddresses_new :: Effect RewardAddresses
foreign import rewardAddresses_len :: RewardAddresses -> Effect Int
foreign import rewardAddresses_get :: RewardAddresses -> Int -> Effect RewardAddress
foreign import rewardAddresses_add :: RewardAddresses -> RewardAddress -> Effect Unit

-- | Reward addresses class
type RewardAddressesClass =
  { free :: RewardAddresses -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: RewardAddresses -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> RewardAddresses
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: RewardAddresses -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> RewardAddresses
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: RewardAddresses -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: RewardAddresses -> RewardAddressesJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> RewardAddresses
    -- ^ From json
    -- > fromJson json
  , new :: Effect RewardAddresses
    -- ^ New
    -- > new
  , len :: RewardAddresses -> Effect Int
    -- ^ Len
    -- > len self
  , get :: RewardAddresses -> Int -> Effect RewardAddress
    -- ^ Get
    -- > get self index
  , add :: RewardAddresses -> RewardAddress -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Reward addresses class API
rewardAddresses :: RewardAddressesClass
rewardAddresses =
  { free: rewardAddresses_free
  , toBytes: rewardAddresses_toBytes
  , fromBytes: rewardAddresses_fromBytes
  , toHex: rewardAddresses_toHex
  , fromHex: rewardAddresses_fromHex
  , toJson: rewardAddresses_toJson
  , toJsValue: rewardAddresses_toJsValue
  , fromJson: rewardAddresses_fromJson
  , new: rewardAddresses_new
  , len: rewardAddresses_len
  , get: rewardAddresses_get
  , add: rewardAddresses_add
  }

instance HasFree RewardAddresses where
  free = rewardAddresses.free

instance Show RewardAddresses where
  show = rewardAddresses.toHex

instance MutableList RewardAddresses RewardAddress where
  addItem = rewardAddresses.add
  getItem = rewardAddresses.get
  emptyList = rewardAddresses.new

instance MutableLen RewardAddresses where
  getLen = rewardAddresses.len


instance ToJsValue RewardAddresses where
  toJsValue = rewardAddresses.toJsValue

instance IsHex RewardAddresses where
  toHex = rewardAddresses.toHex
  fromHex = rewardAddresses.fromHex

instance IsBytes RewardAddresses where
  toBytes = rewardAddresses.toBytes
  fromBytes = rewardAddresses.fromBytes

instance IsJson RewardAddresses where
  toJson = rewardAddresses.toJson
  fromJson = rewardAddresses.fromJson

-------------------------------------------------------------------------------------
-- Script all

foreign import scriptAll_free :: ScriptAll -> Effect Unit
foreign import scriptAll_toBytes :: ScriptAll -> Bytes
foreign import scriptAll_fromBytes :: Bytes -> ScriptAll
foreign import scriptAll_toHex :: ScriptAll -> String
foreign import scriptAll_fromHex :: String -> ScriptAll
foreign import scriptAll_toJson :: ScriptAll -> String
foreign import scriptAll_toJsValue :: ScriptAll -> ScriptAllJson
foreign import scriptAll_fromJson :: String -> ScriptAll
foreign import scriptAll_nativeScripts :: ScriptAll -> NativeScripts
foreign import scriptAll_new :: NativeScripts -> ScriptAll

-- | Script all class
type ScriptAllClass =
  { free :: ScriptAll -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: ScriptAll -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> ScriptAll
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: ScriptAll -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> ScriptAll
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: ScriptAll -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: ScriptAll -> ScriptAllJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> ScriptAll
    -- ^ From json
    -- > fromJson json
  , nativeScripts :: ScriptAll -> NativeScripts
    -- ^ Native scripts
    -- > nativeScripts self
  , new :: NativeScripts -> ScriptAll
    -- ^ New
    -- > new nativeScripts
  }

-- | Script all class API
scriptAll :: ScriptAllClass
scriptAll =
  { free: scriptAll_free
  , toBytes: scriptAll_toBytes
  , fromBytes: scriptAll_fromBytes
  , toHex: scriptAll_toHex
  , fromHex: scriptAll_fromHex
  , toJson: scriptAll_toJson
  , toJsValue: scriptAll_toJsValue
  , fromJson: scriptAll_fromJson
  , nativeScripts: scriptAll_nativeScripts
  , new: scriptAll_new
  }

instance HasFree ScriptAll where
  free = scriptAll.free

instance Show ScriptAll where
  show = scriptAll.toHex

instance ToJsValue ScriptAll where
  toJsValue = scriptAll.toJsValue

instance IsHex ScriptAll where
  toHex = scriptAll.toHex
  fromHex = scriptAll.fromHex

instance IsBytes ScriptAll where
  toBytes = scriptAll.toBytes
  fromBytes = scriptAll.fromBytes

instance IsJson ScriptAll where
  toJson = scriptAll.toJson
  fromJson = scriptAll.fromJson

-------------------------------------------------------------------------------------
-- Script any

foreign import scriptAny_free :: ScriptAny -> Effect Unit
foreign import scriptAny_toBytes :: ScriptAny -> Bytes
foreign import scriptAny_fromBytes :: Bytes -> ScriptAny
foreign import scriptAny_toHex :: ScriptAny -> String
foreign import scriptAny_fromHex :: String -> ScriptAny
foreign import scriptAny_toJson :: ScriptAny -> String
foreign import scriptAny_toJsValue :: ScriptAny -> ScriptAnyJson
foreign import scriptAny_fromJson :: String -> ScriptAny
foreign import scriptAny_nativeScripts :: ScriptAny -> NativeScripts
foreign import scriptAny_new :: NativeScripts -> ScriptAny

-- | Script any class
type ScriptAnyClass =
  { free :: ScriptAny -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: ScriptAny -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> ScriptAny
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: ScriptAny -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> ScriptAny
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: ScriptAny -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: ScriptAny -> ScriptAnyJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> ScriptAny
    -- ^ From json
    -- > fromJson json
  , nativeScripts :: ScriptAny -> NativeScripts
    -- ^ Native scripts
    -- > nativeScripts self
  , new :: NativeScripts -> ScriptAny
    -- ^ New
    -- > new nativeScripts
  }

-- | Script any class API
scriptAny :: ScriptAnyClass
scriptAny =
  { free: scriptAny_free
  , toBytes: scriptAny_toBytes
  , fromBytes: scriptAny_fromBytes
  , toHex: scriptAny_toHex
  , fromHex: scriptAny_fromHex
  , toJson: scriptAny_toJson
  , toJsValue: scriptAny_toJsValue
  , fromJson: scriptAny_fromJson
  , nativeScripts: scriptAny_nativeScripts
  , new: scriptAny_new
  }

instance HasFree ScriptAny where
  free = scriptAny.free

instance Show ScriptAny where
  show = scriptAny.toHex

instance ToJsValue ScriptAny where
  toJsValue = scriptAny.toJsValue

instance IsHex ScriptAny where
  toHex = scriptAny.toHex
  fromHex = scriptAny.fromHex

instance IsBytes ScriptAny where
  toBytes = scriptAny.toBytes
  fromBytes = scriptAny.fromBytes

instance IsJson ScriptAny where
  toJson = scriptAny.toJson
  fromJson = scriptAny.fromJson

-------------------------------------------------------------------------------------
-- Script data hash

foreign import scriptDataHash_free :: ScriptDataHash -> Effect Unit
foreign import scriptDataHash_fromBytes :: Bytes -> ScriptDataHash
foreign import scriptDataHash_toBytes :: ScriptDataHash -> Bytes
foreign import scriptDataHash_toBech32 :: ScriptDataHash -> String -> String
foreign import scriptDataHash_fromBech32 :: String -> ScriptDataHash
foreign import scriptDataHash_toHex :: ScriptDataHash -> String
foreign import scriptDataHash_fromHex :: String -> ScriptDataHash

-- | Script data hash class
type ScriptDataHashClass =
  { free :: ScriptDataHash -> Effect Unit
    -- ^ Free
    -- > free self
  , fromBytes :: Bytes -> ScriptDataHash
    -- ^ From bytes
    -- > fromBytes bytes
  , toBytes :: ScriptDataHash -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , toBech32 :: ScriptDataHash -> String -> String
    -- ^ To bech32
    -- > toBech32 self prefix
  , fromBech32 :: String -> ScriptDataHash
    -- ^ From bech32
    -- > fromBech32 bechStr
  , toHex :: ScriptDataHash -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> ScriptDataHash
    -- ^ From hex
    -- > fromHex hex
  }

-- | Script data hash class API
scriptDataHash :: ScriptDataHashClass
scriptDataHash =
  { free: scriptDataHash_free
  , fromBytes: scriptDataHash_fromBytes
  , toBytes: scriptDataHash_toBytes
  , toBech32: scriptDataHash_toBech32
  , fromBech32: scriptDataHash_fromBech32
  , toHex: scriptDataHash_toHex
  , fromHex: scriptDataHash_fromHex
  }

instance HasFree ScriptDataHash where
  free = scriptDataHash.free

instance Show ScriptDataHash where
  show = scriptDataHash.toHex

instance IsHex ScriptDataHash where
  toHex = scriptDataHash.toHex
  fromHex = scriptDataHash.fromHex

instance IsBytes ScriptDataHash where
  toBytes = scriptDataHash.toBytes
  fromBytes = scriptDataHash.fromBytes

-------------------------------------------------------------------------------------
-- Script hash

foreign import scriptHash_free :: ScriptHash -> Effect Unit
foreign import scriptHash_fromBytes :: Bytes -> ScriptHash
foreign import scriptHash_toBytes :: ScriptHash -> Bytes
foreign import scriptHash_toBech32 :: ScriptHash -> String -> String
foreign import scriptHash_fromBech32 :: String -> ScriptHash
foreign import scriptHash_toHex :: ScriptHash -> String
foreign import scriptHash_fromHex :: String -> ScriptHash

-- | Script hash class
type ScriptHashClass =
  { free :: ScriptHash -> Effect Unit
    -- ^ Free
    -- > free self
  , fromBytes :: Bytes -> ScriptHash
    -- ^ From bytes
    -- > fromBytes bytes
  , toBytes :: ScriptHash -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , toBech32 :: ScriptHash -> String -> String
    -- ^ To bech32
    -- > toBech32 self prefix
  , fromBech32 :: String -> ScriptHash
    -- ^ From bech32
    -- > fromBech32 bechStr
  , toHex :: ScriptHash -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> ScriptHash
    -- ^ From hex
    -- > fromHex hex
  }

-- | Script hash class API
scriptHash :: ScriptHashClass
scriptHash =
  { free: scriptHash_free
  , fromBytes: scriptHash_fromBytes
  , toBytes: scriptHash_toBytes
  , toBech32: scriptHash_toBech32
  , fromBech32: scriptHash_fromBech32
  , toHex: scriptHash_toHex
  , fromHex: scriptHash_fromHex
  }

instance HasFree ScriptHash where
  free = scriptHash.free

instance Show ScriptHash where
  show = scriptHash.toHex

instance IsHex ScriptHash where
  toHex = scriptHash.toHex
  fromHex = scriptHash.fromHex

instance IsBytes ScriptHash where
  toBytes = scriptHash.toBytes
  fromBytes = scriptHash.fromBytes

-------------------------------------------------------------------------------------
-- Script hashes

foreign import scriptHashes_free :: ScriptHashes -> Effect Unit
foreign import scriptHashes_toBytes :: ScriptHashes -> Bytes
foreign import scriptHashes_fromBytes :: Bytes -> ScriptHashes
foreign import scriptHashes_toHex :: ScriptHashes -> String
foreign import scriptHashes_fromHex :: String -> ScriptHashes
foreign import scriptHashes_toJson :: ScriptHashes -> String
foreign import scriptHashes_toJsValue :: ScriptHashes -> ScriptHashesJson
foreign import scriptHashes_fromJson :: String -> ScriptHashes
foreign import scriptHashes_new :: Effect ScriptHashes
foreign import scriptHashes_len :: ScriptHashes -> Effect Int
foreign import scriptHashes_get :: ScriptHashes -> Int -> Effect ScriptHash
foreign import scriptHashes_add :: ScriptHashes -> ScriptHash -> Effect Unit

-- | Script hashes class
type ScriptHashesClass =
  { free :: ScriptHashes -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: ScriptHashes -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> ScriptHashes
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: ScriptHashes -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> ScriptHashes
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: ScriptHashes -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: ScriptHashes -> ScriptHashesJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> ScriptHashes
    -- ^ From json
    -- > fromJson json
  , new :: Effect ScriptHashes
    -- ^ New
    -- > new
  , len :: ScriptHashes -> Effect Int
    -- ^ Len
    -- > len self
  , get :: ScriptHashes -> Int -> Effect ScriptHash
    -- ^ Get
    -- > get self index
  , add :: ScriptHashes -> ScriptHash -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Script hashes class API
scriptHashes :: ScriptHashesClass
scriptHashes =
  { free: scriptHashes_free
  , toBytes: scriptHashes_toBytes
  , fromBytes: scriptHashes_fromBytes
  , toHex: scriptHashes_toHex
  , fromHex: scriptHashes_fromHex
  , toJson: scriptHashes_toJson
  , toJsValue: scriptHashes_toJsValue
  , fromJson: scriptHashes_fromJson
  , new: scriptHashes_new
  , len: scriptHashes_len
  , get: scriptHashes_get
  , add: scriptHashes_add
  }

instance HasFree ScriptHashes where
  free = scriptHashes.free

instance Show ScriptHashes where
  show = scriptHashes.toHex

instance MutableList ScriptHashes ScriptHash where
  addItem = scriptHashes.add
  getItem = scriptHashes.get
  emptyList = scriptHashes.new

instance MutableLen ScriptHashes where
  getLen = scriptHashes.len


instance ToJsValue ScriptHashes where
  toJsValue = scriptHashes.toJsValue

instance IsHex ScriptHashes where
  toHex = scriptHashes.toHex
  fromHex = scriptHashes.fromHex

instance IsBytes ScriptHashes where
  toBytes = scriptHashes.toBytes
  fromBytes = scriptHashes.fromBytes

instance IsJson ScriptHashes where
  toJson = scriptHashes.toJson
  fromJson = scriptHashes.fromJson

-------------------------------------------------------------------------------------
-- Script nOf k

foreign import scriptNOfK_free :: ScriptNOfK -> Effect Unit
foreign import scriptNOfK_toBytes :: ScriptNOfK -> Bytes
foreign import scriptNOfK_fromBytes :: Bytes -> ScriptNOfK
foreign import scriptNOfK_toHex :: ScriptNOfK -> String
foreign import scriptNOfK_fromHex :: String -> ScriptNOfK
foreign import scriptNOfK_toJson :: ScriptNOfK -> String
foreign import scriptNOfK_toJsValue :: ScriptNOfK -> ScriptNOfKJson
foreign import scriptNOfK_fromJson :: String -> ScriptNOfK
foreign import scriptNOfK_n :: ScriptNOfK -> Number
foreign import scriptNOfK_nativeScripts :: ScriptNOfK -> NativeScripts
foreign import scriptNOfK_new :: Number -> NativeScripts -> ScriptNOfK

-- | Script nOf k class
type ScriptNOfKClass =
  { free :: ScriptNOfK -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: ScriptNOfK -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> ScriptNOfK
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: ScriptNOfK -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> ScriptNOfK
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: ScriptNOfK -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: ScriptNOfK -> ScriptNOfKJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> ScriptNOfK
    -- ^ From json
    -- > fromJson json
  , n :: ScriptNOfK -> Number
    -- ^ N
    -- > n self
  , nativeScripts :: ScriptNOfK -> NativeScripts
    -- ^ Native scripts
    -- > nativeScripts self
  , new :: Number -> NativeScripts -> ScriptNOfK
    -- ^ New
    -- > new n nativeScripts
  }

-- | Script nOf k class API
scriptNOfK :: ScriptNOfKClass
scriptNOfK =
  { free: scriptNOfK_free
  , toBytes: scriptNOfK_toBytes
  , fromBytes: scriptNOfK_fromBytes
  , toHex: scriptNOfK_toHex
  , fromHex: scriptNOfK_fromHex
  , toJson: scriptNOfK_toJson
  , toJsValue: scriptNOfK_toJsValue
  , fromJson: scriptNOfK_fromJson
  , n: scriptNOfK_n
  , nativeScripts: scriptNOfK_nativeScripts
  , new: scriptNOfK_new
  }

instance HasFree ScriptNOfK where
  free = scriptNOfK.free

instance Show ScriptNOfK where
  show = scriptNOfK.toHex

instance ToJsValue ScriptNOfK where
  toJsValue = scriptNOfK.toJsValue

instance IsHex ScriptNOfK where
  toHex = scriptNOfK.toHex
  fromHex = scriptNOfK.fromHex

instance IsBytes ScriptNOfK where
  toBytes = scriptNOfK.toBytes
  fromBytes = scriptNOfK.fromBytes

instance IsJson ScriptNOfK where
  toJson = scriptNOfK.toJson
  fromJson = scriptNOfK.fromJson

-------------------------------------------------------------------------------------
-- Script pubkey

foreign import scriptPubkey_free :: ScriptPubkey -> Effect Unit
foreign import scriptPubkey_toBytes :: ScriptPubkey -> Bytes
foreign import scriptPubkey_fromBytes :: Bytes -> ScriptPubkey
foreign import scriptPubkey_toHex :: ScriptPubkey -> String
foreign import scriptPubkey_fromHex :: String -> ScriptPubkey
foreign import scriptPubkey_toJson :: ScriptPubkey -> String
foreign import scriptPubkey_toJsValue :: ScriptPubkey -> ScriptPubkeyJson
foreign import scriptPubkey_fromJson :: String -> ScriptPubkey
foreign import scriptPubkey_addrKeyhash :: ScriptPubkey -> Ed25519KeyHash
foreign import scriptPubkey_new :: Ed25519KeyHash -> ScriptPubkey

-- | Script pubkey class
type ScriptPubkeyClass =
  { free :: ScriptPubkey -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: ScriptPubkey -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> ScriptPubkey
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: ScriptPubkey -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> ScriptPubkey
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: ScriptPubkey -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: ScriptPubkey -> ScriptPubkeyJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> ScriptPubkey
    -- ^ From json
    -- > fromJson json
  , addrKeyhash :: ScriptPubkey -> Ed25519KeyHash
    -- ^ Addr keyhash
    -- > addrKeyhash self
  , new :: Ed25519KeyHash -> ScriptPubkey
    -- ^ New
    -- > new addrKeyhash
  }

-- | Script pubkey class API
scriptPubkey :: ScriptPubkeyClass
scriptPubkey =
  { free: scriptPubkey_free
  , toBytes: scriptPubkey_toBytes
  , fromBytes: scriptPubkey_fromBytes
  , toHex: scriptPubkey_toHex
  , fromHex: scriptPubkey_fromHex
  , toJson: scriptPubkey_toJson
  , toJsValue: scriptPubkey_toJsValue
  , fromJson: scriptPubkey_fromJson
  , addrKeyhash: scriptPubkey_addrKeyhash
  , new: scriptPubkey_new
  }

instance HasFree ScriptPubkey where
  free = scriptPubkey.free

instance Show ScriptPubkey where
  show = scriptPubkey.toHex

instance ToJsValue ScriptPubkey where
  toJsValue = scriptPubkey.toJsValue

instance IsHex ScriptPubkey where
  toHex = scriptPubkey.toHex
  fromHex = scriptPubkey.fromHex

instance IsBytes ScriptPubkey where
  toBytes = scriptPubkey.toBytes
  fromBytes = scriptPubkey.fromBytes

instance IsJson ScriptPubkey where
  toJson = scriptPubkey.toJson
  fromJson = scriptPubkey.fromJson

-------------------------------------------------------------------------------------
-- Script ref

foreign import scriptRef_free :: ScriptRef -> Effect Unit
foreign import scriptRef_toBytes :: ScriptRef -> Bytes
foreign import scriptRef_fromBytes :: Bytes -> ScriptRef
foreign import scriptRef_toHex :: ScriptRef -> String
foreign import scriptRef_fromHex :: String -> ScriptRef
foreign import scriptRef_toJson :: ScriptRef -> String
foreign import scriptRef_toJsValue :: ScriptRef -> ScriptRefJson
foreign import scriptRef_fromJson :: String -> ScriptRef
foreign import scriptRef_newNativeScript :: NativeScript -> ScriptRef
foreign import scriptRef_newPlutusScript :: PlutusScript -> ScriptRef
foreign import scriptRef_isNativeScript :: ScriptRef -> Boolean
foreign import scriptRef_isPlutusScript :: ScriptRef -> Boolean
foreign import scriptRef_nativeScript :: ScriptRef -> Nullable NativeScript
foreign import scriptRef_plutusScript :: ScriptRef -> Nullable PlutusScript

-- | Script ref class
type ScriptRefClass =
  { free :: ScriptRef -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: ScriptRef -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> ScriptRef
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: ScriptRef -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> ScriptRef
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: ScriptRef -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: ScriptRef -> ScriptRefJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> ScriptRef
    -- ^ From json
    -- > fromJson json
  , newNativeScript :: NativeScript -> ScriptRef
    -- ^ New native script
    -- > newNativeScript nativeScript
  , newPlutusScript :: PlutusScript -> ScriptRef
    -- ^ New plutus script
    -- > newPlutusScript plutusScript
  , isNativeScript :: ScriptRef -> Boolean
    -- ^ Is native script
    -- > isNativeScript self
  , isPlutusScript :: ScriptRef -> Boolean
    -- ^ Is plutus script
    -- > isPlutusScript self
  , nativeScript :: ScriptRef -> Maybe NativeScript
    -- ^ Native script
    -- > nativeScript self
  , plutusScript :: ScriptRef -> Maybe PlutusScript
    -- ^ Plutus script
    -- > plutusScript self
  }

-- | Script ref class API
scriptRef :: ScriptRefClass
scriptRef =
  { free: scriptRef_free
  , toBytes: scriptRef_toBytes
  , fromBytes: scriptRef_fromBytes
  , toHex: scriptRef_toHex
  , fromHex: scriptRef_fromHex
  , toJson: scriptRef_toJson
  , toJsValue: scriptRef_toJsValue
  , fromJson: scriptRef_fromJson
  , newNativeScript: scriptRef_newNativeScript
  , newPlutusScript: scriptRef_newPlutusScript
  , isNativeScript: scriptRef_isNativeScript
  , isPlutusScript: scriptRef_isPlutusScript
  , nativeScript: \a1 -> Nullable.toMaybe $ scriptRef_nativeScript a1
  , plutusScript: \a1 -> Nullable.toMaybe $ scriptRef_plutusScript a1
  }

instance HasFree ScriptRef where
  free = scriptRef.free

instance Show ScriptRef where
  show = scriptRef.toHex

instance ToJsValue ScriptRef where
  toJsValue = scriptRef.toJsValue

instance IsHex ScriptRef where
  toHex = scriptRef.toHex
  fromHex = scriptRef.fromHex

instance IsBytes ScriptRef where
  toBytes = scriptRef.toBytes
  fromBytes = scriptRef.fromBytes

instance IsJson ScriptRef where
  toJson = scriptRef.toJson
  fromJson = scriptRef.fromJson

-------------------------------------------------------------------------------------
-- Single host addr

foreign import singleHostAddr_free :: SingleHostAddr -> Effect Unit
foreign import singleHostAddr_toBytes :: SingleHostAddr -> Bytes
foreign import singleHostAddr_fromBytes :: Bytes -> SingleHostAddr
foreign import singleHostAddr_toHex :: SingleHostAddr -> String
foreign import singleHostAddr_fromHex :: String -> SingleHostAddr
foreign import singleHostAddr_toJson :: SingleHostAddr -> String
foreign import singleHostAddr_toJsValue :: SingleHostAddr -> SingleHostAddrJson
foreign import singleHostAddr_fromJson :: String -> SingleHostAddr
foreign import singleHostAddr_port :: SingleHostAddr -> Nullable Number
foreign import singleHostAddr_ipv4 :: SingleHostAddr -> Nullable Ipv4
foreign import singleHostAddr_ipv6 :: SingleHostAddr -> Nullable Ipv6
foreign import singleHostAddr_new :: Number -> Ipv4 -> Ipv6 -> SingleHostAddr

-- | Single host addr class
type SingleHostAddrClass =
  { free :: SingleHostAddr -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: SingleHostAddr -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> SingleHostAddr
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: SingleHostAddr -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> SingleHostAddr
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: SingleHostAddr -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: SingleHostAddr -> SingleHostAddrJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> SingleHostAddr
    -- ^ From json
    -- > fromJson json
  , port :: SingleHostAddr -> Maybe Number
    -- ^ Port
    -- > port self
  , ipv4 :: SingleHostAddr -> Maybe Ipv4
    -- ^ Ipv4
    -- > ipv4 self
  , ipv6 :: SingleHostAddr -> Maybe Ipv6
    -- ^ Ipv6
    -- > ipv6 self
  , new :: Number -> Ipv4 -> Ipv6 -> SingleHostAddr
    -- ^ New
    -- > new port ipv4 ipv6
  }

-- | Single host addr class API
singleHostAddr :: SingleHostAddrClass
singleHostAddr =
  { free: singleHostAddr_free
  , toBytes: singleHostAddr_toBytes
  , fromBytes: singleHostAddr_fromBytes
  , toHex: singleHostAddr_toHex
  , fromHex: singleHostAddr_fromHex
  , toJson: singleHostAddr_toJson
  , toJsValue: singleHostAddr_toJsValue
  , fromJson: singleHostAddr_fromJson
  , port: \a1 -> Nullable.toMaybe $ singleHostAddr_port a1
  , ipv4: \a1 -> Nullable.toMaybe $ singleHostAddr_ipv4 a1
  , ipv6: \a1 -> Nullable.toMaybe $ singleHostAddr_ipv6 a1
  , new: singleHostAddr_new
  }

instance HasFree SingleHostAddr where
  free = singleHostAddr.free

instance Show SingleHostAddr where
  show = singleHostAddr.toHex

instance ToJsValue SingleHostAddr where
  toJsValue = singleHostAddr.toJsValue

instance IsHex SingleHostAddr where
  toHex = singleHostAddr.toHex
  fromHex = singleHostAddr.fromHex

instance IsBytes SingleHostAddr where
  toBytes = singleHostAddr.toBytes
  fromBytes = singleHostAddr.fromBytes

instance IsJson SingleHostAddr where
  toJson = singleHostAddr.toJson
  fromJson = singleHostAddr.fromJson

-------------------------------------------------------------------------------------
-- Single host name

foreign import singleHostName_free :: SingleHostName -> Effect Unit
foreign import singleHostName_toBytes :: SingleHostName -> Bytes
foreign import singleHostName_fromBytes :: Bytes -> SingleHostName
foreign import singleHostName_toHex :: SingleHostName -> String
foreign import singleHostName_fromHex :: String -> SingleHostName
foreign import singleHostName_toJson :: SingleHostName -> String
foreign import singleHostName_toJsValue :: SingleHostName -> SingleHostNameJson
foreign import singleHostName_fromJson :: String -> SingleHostName
foreign import singleHostName_port :: SingleHostName -> Nullable Number
foreign import singleHostName_dnsName :: SingleHostName -> DNSRecordAorAAAA
foreign import singleHostName_new :: Nullable Number -> DNSRecordAorAAAA -> SingleHostName

-- | Single host name class
type SingleHostNameClass =
  { free :: SingleHostName -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: SingleHostName -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> SingleHostName
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: SingleHostName -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> SingleHostName
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: SingleHostName -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: SingleHostName -> SingleHostNameJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> SingleHostName
    -- ^ From json
    -- > fromJson json
  , port :: SingleHostName -> Maybe Number
    -- ^ Port
    -- > port self
  , dnsName :: SingleHostName -> DNSRecordAorAAAA
    -- ^ Dns name
    -- > dnsName self
  , new :: Maybe Number -> DNSRecordAorAAAA -> SingleHostName
    -- ^ New
    -- > new port dnsName
  }

-- | Single host name class API
singleHostName :: SingleHostNameClass
singleHostName =
  { free: singleHostName_free
  , toBytes: singleHostName_toBytes
  , fromBytes: singleHostName_fromBytes
  , toHex: singleHostName_toHex
  , fromHex: singleHostName_fromHex
  , toJson: singleHostName_toJson
  , toJsValue: singleHostName_toJsValue
  , fromJson: singleHostName_fromJson
  , port: \a1 -> Nullable.toMaybe $ singleHostName_port a1
  , dnsName: singleHostName_dnsName
  , new: \a1 a2 -> singleHostName_new (Nullable.toNullable a1) a2
  }

instance HasFree SingleHostName where
  free = singleHostName.free

instance Show SingleHostName where
  show = singleHostName.toHex

instance ToJsValue SingleHostName where
  toJsValue = singleHostName.toJsValue

instance IsHex SingleHostName where
  toHex = singleHostName.toHex
  fromHex = singleHostName.fromHex

instance IsBytes SingleHostName where
  toBytes = singleHostName.toBytes
  fromBytes = singleHostName.fromBytes

instance IsJson SingleHostName where
  toJson = singleHostName.toJson
  fromJson = singleHostName.fromJson

-------------------------------------------------------------------------------------
-- Stake credential

foreign import stakeCredential_free :: StakeCredential -> Effect Unit
foreign import stakeCredential_fromKeyhash :: Ed25519KeyHash -> StakeCredential
foreign import stakeCredential_fromScripthash :: ScriptHash -> StakeCredential
foreign import stakeCredential_toKeyhash :: StakeCredential -> Nullable Ed25519KeyHash
foreign import stakeCredential_toScripthash :: StakeCredential -> Nullable ScriptHash
foreign import stakeCredential_kind :: StakeCredential -> Number
foreign import stakeCredential_toBytes :: StakeCredential -> Bytes
foreign import stakeCredential_fromBytes :: Bytes -> StakeCredential
foreign import stakeCredential_toHex :: StakeCredential -> String
foreign import stakeCredential_fromHex :: String -> StakeCredential
foreign import stakeCredential_toJson :: StakeCredential -> String
foreign import stakeCredential_toJsValue :: StakeCredential -> StakeCredentialJson
foreign import stakeCredential_fromJson :: String -> StakeCredential

-- | Stake credential class
type StakeCredentialClass =
  { free :: StakeCredential -> Effect Unit
    -- ^ Free
    -- > free self
  , fromKeyhash :: Ed25519KeyHash -> StakeCredential
    -- ^ From keyhash
    -- > fromKeyhash hash
  , fromScripthash :: ScriptHash -> StakeCredential
    -- ^ From scripthash
    -- > fromScripthash hash
  , toKeyhash :: StakeCredential -> Maybe Ed25519KeyHash
    -- ^ To keyhash
    -- > toKeyhash self
  , toScripthash :: StakeCredential -> Maybe ScriptHash
    -- ^ To scripthash
    -- > toScripthash self
  , kind :: StakeCredential -> Number
    -- ^ Kind
    -- > kind self
  , toBytes :: StakeCredential -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> StakeCredential
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: StakeCredential -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> StakeCredential
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: StakeCredential -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: StakeCredential -> StakeCredentialJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> StakeCredential
    -- ^ From json
    -- > fromJson json
  }

-- | Stake credential class API
stakeCredential :: StakeCredentialClass
stakeCredential =
  { free: stakeCredential_free
  , fromKeyhash: stakeCredential_fromKeyhash
  , fromScripthash: stakeCredential_fromScripthash
  , toKeyhash: \a1 -> Nullable.toMaybe $ stakeCredential_toKeyhash a1
  , toScripthash: \a1 -> Nullable.toMaybe $ stakeCredential_toScripthash a1
  , kind: stakeCredential_kind
  , toBytes: stakeCredential_toBytes
  , fromBytes: stakeCredential_fromBytes
  , toHex: stakeCredential_toHex
  , fromHex: stakeCredential_fromHex
  , toJson: stakeCredential_toJson
  , toJsValue: stakeCredential_toJsValue
  , fromJson: stakeCredential_fromJson
  }

instance HasFree StakeCredential where
  free = stakeCredential.free

instance Show StakeCredential where
  show = stakeCredential.toHex

instance ToJsValue StakeCredential where
  toJsValue = stakeCredential.toJsValue

instance IsHex StakeCredential where
  toHex = stakeCredential.toHex
  fromHex = stakeCredential.fromHex

instance IsBytes StakeCredential where
  toBytes = stakeCredential.toBytes
  fromBytes = stakeCredential.fromBytes

instance IsJson StakeCredential where
  toJson = stakeCredential.toJson
  fromJson = stakeCredential.fromJson

-------------------------------------------------------------------------------------
-- Stake credentials

foreign import stakeCredentials_free :: StakeCredentials -> Effect Unit
foreign import stakeCredentials_toBytes :: StakeCredentials -> Bytes
foreign import stakeCredentials_fromBytes :: Bytes -> StakeCredentials
foreign import stakeCredentials_toHex :: StakeCredentials -> String
foreign import stakeCredentials_fromHex :: String -> StakeCredentials
foreign import stakeCredentials_toJson :: StakeCredentials -> String
foreign import stakeCredentials_toJsValue :: StakeCredentials -> StakeCredentialsJson
foreign import stakeCredentials_fromJson :: String -> StakeCredentials
foreign import stakeCredentials_new :: Effect StakeCredentials
foreign import stakeCredentials_len :: StakeCredentials -> Effect Int
foreign import stakeCredentials_get :: StakeCredentials -> Int -> Effect StakeCredential
foreign import stakeCredentials_add :: StakeCredentials -> StakeCredential -> Effect Unit

-- | Stake credentials class
type StakeCredentialsClass =
  { free :: StakeCredentials -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: StakeCredentials -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> StakeCredentials
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: StakeCredentials -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> StakeCredentials
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: StakeCredentials -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: StakeCredentials -> StakeCredentialsJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> StakeCredentials
    -- ^ From json
    -- > fromJson json
  , new :: Effect StakeCredentials
    -- ^ New
    -- > new
  , len :: StakeCredentials -> Effect Int
    -- ^ Len
    -- > len self
  , get :: StakeCredentials -> Int -> Effect StakeCredential
    -- ^ Get
    -- > get self index
  , add :: StakeCredentials -> StakeCredential -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Stake credentials class API
stakeCredentials :: StakeCredentialsClass
stakeCredentials =
  { free: stakeCredentials_free
  , toBytes: stakeCredentials_toBytes
  , fromBytes: stakeCredentials_fromBytes
  , toHex: stakeCredentials_toHex
  , fromHex: stakeCredentials_fromHex
  , toJson: stakeCredentials_toJson
  , toJsValue: stakeCredentials_toJsValue
  , fromJson: stakeCredentials_fromJson
  , new: stakeCredentials_new
  , len: stakeCredentials_len
  , get: stakeCredentials_get
  , add: stakeCredentials_add
  }

instance HasFree StakeCredentials where
  free = stakeCredentials.free

instance Show StakeCredentials where
  show = stakeCredentials.toHex

instance MutableList StakeCredentials StakeCredential where
  addItem = stakeCredentials.add
  getItem = stakeCredentials.get
  emptyList = stakeCredentials.new

instance MutableLen StakeCredentials where
  getLen = stakeCredentials.len


instance ToJsValue StakeCredentials where
  toJsValue = stakeCredentials.toJsValue

instance IsHex StakeCredentials where
  toHex = stakeCredentials.toHex
  fromHex = stakeCredentials.fromHex

instance IsBytes StakeCredentials where
  toBytes = stakeCredentials.toBytes
  fromBytes = stakeCredentials.fromBytes

instance IsJson StakeCredentials where
  toJson = stakeCredentials.toJson
  fromJson = stakeCredentials.fromJson

-------------------------------------------------------------------------------------
-- Stake delegation

foreign import stakeDelegation_free :: StakeDelegation -> Effect Unit
foreign import stakeDelegation_toBytes :: StakeDelegation -> Bytes
foreign import stakeDelegation_fromBytes :: Bytes -> StakeDelegation
foreign import stakeDelegation_toHex :: StakeDelegation -> String
foreign import stakeDelegation_fromHex :: String -> StakeDelegation
foreign import stakeDelegation_toJson :: StakeDelegation -> String
foreign import stakeDelegation_toJsValue :: StakeDelegation -> StakeDelegationJson
foreign import stakeDelegation_fromJson :: String -> StakeDelegation
foreign import stakeDelegation_stakeCredential :: StakeDelegation -> StakeCredential
foreign import stakeDelegation_poolKeyhash :: StakeDelegation -> Ed25519KeyHash
foreign import stakeDelegation_new :: StakeCredential -> Ed25519KeyHash -> StakeDelegation

-- | Stake delegation class
type StakeDelegationClass =
  { free :: StakeDelegation -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: StakeDelegation -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> StakeDelegation
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: StakeDelegation -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> StakeDelegation
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: StakeDelegation -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: StakeDelegation -> StakeDelegationJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> StakeDelegation
    -- ^ From json
    -- > fromJson json
  , stakeCredential :: StakeDelegation -> StakeCredential
    -- ^ Stake credential
    -- > stakeCredential self
  , poolKeyhash :: StakeDelegation -> Ed25519KeyHash
    -- ^ Pool keyhash
    -- > poolKeyhash self
  , new :: StakeCredential -> Ed25519KeyHash -> StakeDelegation
    -- ^ New
    -- > new stakeCredential poolKeyhash
  }

-- | Stake delegation class API
stakeDelegation :: StakeDelegationClass
stakeDelegation =
  { free: stakeDelegation_free
  , toBytes: stakeDelegation_toBytes
  , fromBytes: stakeDelegation_fromBytes
  , toHex: stakeDelegation_toHex
  , fromHex: stakeDelegation_fromHex
  , toJson: stakeDelegation_toJson
  , toJsValue: stakeDelegation_toJsValue
  , fromJson: stakeDelegation_fromJson
  , stakeCredential: stakeDelegation_stakeCredential
  , poolKeyhash: stakeDelegation_poolKeyhash
  , new: stakeDelegation_new
  }

instance HasFree StakeDelegation where
  free = stakeDelegation.free

instance Show StakeDelegation where
  show = stakeDelegation.toHex

instance ToJsValue StakeDelegation where
  toJsValue = stakeDelegation.toJsValue

instance IsHex StakeDelegation where
  toHex = stakeDelegation.toHex
  fromHex = stakeDelegation.fromHex

instance IsBytes StakeDelegation where
  toBytes = stakeDelegation.toBytes
  fromBytes = stakeDelegation.fromBytes

instance IsJson StakeDelegation where
  toJson = stakeDelegation.toJson
  fromJson = stakeDelegation.fromJson

-------------------------------------------------------------------------------------
-- Stake deregistration

foreign import stakeDeregistration_free :: StakeDeregistration -> Effect Unit
foreign import stakeDeregistration_toBytes :: StakeDeregistration -> Bytes
foreign import stakeDeregistration_fromBytes :: Bytes -> StakeDeregistration
foreign import stakeDeregistration_toHex :: StakeDeregistration -> String
foreign import stakeDeregistration_fromHex :: String -> StakeDeregistration
foreign import stakeDeregistration_toJson :: StakeDeregistration -> String
foreign import stakeDeregistration_toJsValue :: StakeDeregistration -> StakeDeregistrationJson
foreign import stakeDeregistration_fromJson :: String -> StakeDeregistration
foreign import stakeDeregistration_stakeCredential :: StakeDeregistration -> StakeCredential
foreign import stakeDeregistration_new :: StakeCredential -> StakeDeregistration

-- | Stake deregistration class
type StakeDeregistrationClass =
  { free :: StakeDeregistration -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: StakeDeregistration -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> StakeDeregistration
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: StakeDeregistration -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> StakeDeregistration
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: StakeDeregistration -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: StakeDeregistration -> StakeDeregistrationJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> StakeDeregistration
    -- ^ From json
    -- > fromJson json
  , stakeCredential :: StakeDeregistration -> StakeCredential
    -- ^ Stake credential
    -- > stakeCredential self
  , new :: StakeCredential -> StakeDeregistration
    -- ^ New
    -- > new stakeCredential
  }

-- | Stake deregistration class API
stakeDeregistration :: StakeDeregistrationClass
stakeDeregistration =
  { free: stakeDeregistration_free
  , toBytes: stakeDeregistration_toBytes
  , fromBytes: stakeDeregistration_fromBytes
  , toHex: stakeDeregistration_toHex
  , fromHex: stakeDeregistration_fromHex
  , toJson: stakeDeregistration_toJson
  , toJsValue: stakeDeregistration_toJsValue
  , fromJson: stakeDeregistration_fromJson
  , stakeCredential: stakeDeregistration_stakeCredential
  , new: stakeDeregistration_new
  }

instance HasFree StakeDeregistration where
  free = stakeDeregistration.free

instance Show StakeDeregistration where
  show = stakeDeregistration.toHex

instance ToJsValue StakeDeregistration where
  toJsValue = stakeDeregistration.toJsValue

instance IsHex StakeDeregistration where
  toHex = stakeDeregistration.toHex
  fromHex = stakeDeregistration.fromHex

instance IsBytes StakeDeregistration where
  toBytes = stakeDeregistration.toBytes
  fromBytes = stakeDeregistration.fromBytes

instance IsJson StakeDeregistration where
  toJson = stakeDeregistration.toJson
  fromJson = stakeDeregistration.fromJson

-------------------------------------------------------------------------------------
-- Stake registration

foreign import stakeRegistration_free :: StakeRegistration -> Effect Unit
foreign import stakeRegistration_toBytes :: StakeRegistration -> Bytes
foreign import stakeRegistration_fromBytes :: Bytes -> StakeRegistration
foreign import stakeRegistration_toHex :: StakeRegistration -> String
foreign import stakeRegistration_fromHex :: String -> StakeRegistration
foreign import stakeRegistration_toJson :: StakeRegistration -> String
foreign import stakeRegistration_toJsValue :: StakeRegistration -> StakeRegistrationJson
foreign import stakeRegistration_fromJson :: String -> StakeRegistration
foreign import stakeRegistration_stakeCredential :: StakeRegistration -> StakeCredential
foreign import stakeRegistration_new :: StakeCredential -> StakeRegistration

-- | Stake registration class
type StakeRegistrationClass =
  { free :: StakeRegistration -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: StakeRegistration -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> StakeRegistration
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: StakeRegistration -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> StakeRegistration
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: StakeRegistration -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: StakeRegistration -> StakeRegistrationJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> StakeRegistration
    -- ^ From json
    -- > fromJson json
  , stakeCredential :: StakeRegistration -> StakeCredential
    -- ^ Stake credential
    -- > stakeCredential self
  , new :: StakeCredential -> StakeRegistration
    -- ^ New
    -- > new stakeCredential
  }

-- | Stake registration class API
stakeRegistration :: StakeRegistrationClass
stakeRegistration =
  { free: stakeRegistration_free
  , toBytes: stakeRegistration_toBytes
  , fromBytes: stakeRegistration_fromBytes
  , toHex: stakeRegistration_toHex
  , fromHex: stakeRegistration_fromHex
  , toJson: stakeRegistration_toJson
  , toJsValue: stakeRegistration_toJsValue
  , fromJson: stakeRegistration_fromJson
  , stakeCredential: stakeRegistration_stakeCredential
  , new: stakeRegistration_new
  }

instance HasFree StakeRegistration where
  free = stakeRegistration.free

instance Show StakeRegistration where
  show = stakeRegistration.toHex

instance ToJsValue StakeRegistration where
  toJsValue = stakeRegistration.toJsValue

instance IsHex StakeRegistration where
  toHex = stakeRegistration.toHex
  fromHex = stakeRegistration.fromHex

instance IsBytes StakeRegistration where
  toBytes = stakeRegistration.toBytes
  fromBytes = stakeRegistration.fromBytes

instance IsJson StakeRegistration where
  toJson = stakeRegistration.toJson
  fromJson = stakeRegistration.fromJson

-------------------------------------------------------------------------------------
-- Strings

foreign import strings_free :: Strings -> Effect Unit
foreign import strings_new :: Effect Strings
foreign import strings_len :: Strings -> Effect Int
foreign import strings_get :: Strings -> Int -> Effect String
foreign import strings_add :: Strings -> String -> Effect Unit

-- | Strings class
type StringsClass =
  { free :: Strings -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: Effect Strings
    -- ^ New
    -- > new
  , len :: Strings -> Effect Int
    -- ^ Len
    -- > len self
  , get :: Strings -> Int -> Effect String
    -- ^ Get
    -- > get self index
  , add :: Strings -> String -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Strings class API
strings :: StringsClass
strings =
  { free: strings_free
  , new: strings_new
  , len: strings_len
  , get: strings_get
  , add: strings_add
  }

instance HasFree Strings where
  free = strings.free

instance MutableList Strings String where
  addItem = strings.add
  getItem = strings.get
  emptyList = strings.new

instance MutableLen Strings where
  getLen = strings.len

-------------------------------------------------------------------------------------
-- Timelock expiry

foreign import timelockExpiry_free :: TimelockExpiry -> Effect Unit
foreign import timelockExpiry_toBytes :: TimelockExpiry -> Bytes
foreign import timelockExpiry_fromBytes :: Bytes -> TimelockExpiry
foreign import timelockExpiry_toHex :: TimelockExpiry -> String
foreign import timelockExpiry_fromHex :: String -> TimelockExpiry
foreign import timelockExpiry_toJson :: TimelockExpiry -> String
foreign import timelockExpiry_toJsValue :: TimelockExpiry -> TimelockExpiryJson
foreign import timelockExpiry_fromJson :: String -> TimelockExpiry
foreign import timelockExpiry_slot :: TimelockExpiry -> Number
foreign import timelockExpiry_slotBignum :: TimelockExpiry -> BigNum
foreign import timelockExpiry_new :: Number -> TimelockExpiry
foreign import timelockExpiry_newTimelockexpiry :: BigNum -> TimelockExpiry

-- | Timelock expiry class
type TimelockExpiryClass =
  { free :: TimelockExpiry -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: TimelockExpiry -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> TimelockExpiry
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: TimelockExpiry -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> TimelockExpiry
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: TimelockExpiry -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: TimelockExpiry -> TimelockExpiryJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> TimelockExpiry
    -- ^ From json
    -- > fromJson json
  , slot :: TimelockExpiry -> Number
    -- ^ Slot
    -- > slot self
  , slotBignum :: TimelockExpiry -> BigNum
    -- ^ Slot bignum
    -- > slotBignum self
  , new :: Number -> TimelockExpiry
    -- ^ New
    -- > new slot
  , newTimelockexpiry :: BigNum -> TimelockExpiry
    -- ^ New timelockexpiry
    -- > newTimelockexpiry slot
  }

-- | Timelock expiry class API
timelockExpiry :: TimelockExpiryClass
timelockExpiry =
  { free: timelockExpiry_free
  , toBytes: timelockExpiry_toBytes
  , fromBytes: timelockExpiry_fromBytes
  , toHex: timelockExpiry_toHex
  , fromHex: timelockExpiry_fromHex
  , toJson: timelockExpiry_toJson
  , toJsValue: timelockExpiry_toJsValue
  , fromJson: timelockExpiry_fromJson
  , slot: timelockExpiry_slot
  , slotBignum: timelockExpiry_slotBignum
  , new: timelockExpiry_new
  , newTimelockexpiry: timelockExpiry_newTimelockexpiry
  }

instance HasFree TimelockExpiry where
  free = timelockExpiry.free

instance Show TimelockExpiry where
  show = timelockExpiry.toHex

instance ToJsValue TimelockExpiry where
  toJsValue = timelockExpiry.toJsValue

instance IsHex TimelockExpiry where
  toHex = timelockExpiry.toHex
  fromHex = timelockExpiry.fromHex

instance IsBytes TimelockExpiry where
  toBytes = timelockExpiry.toBytes
  fromBytes = timelockExpiry.fromBytes

instance IsJson TimelockExpiry where
  toJson = timelockExpiry.toJson
  fromJson = timelockExpiry.fromJson

-------------------------------------------------------------------------------------
-- Timelock start

foreign import timelockStart_free :: TimelockStart -> Effect Unit
foreign import timelockStart_toBytes :: TimelockStart -> Bytes
foreign import timelockStart_fromBytes :: Bytes -> TimelockStart
foreign import timelockStart_toHex :: TimelockStart -> String
foreign import timelockStart_fromHex :: String -> TimelockStart
foreign import timelockStart_toJson :: TimelockStart -> String
foreign import timelockStart_toJsValue :: TimelockStart -> TimelockStartJson
foreign import timelockStart_fromJson :: String -> TimelockStart
foreign import timelockStart_slot :: TimelockStart -> Number
foreign import timelockStart_slotBignum :: TimelockStart -> BigNum
foreign import timelockStart_new :: Number -> TimelockStart
foreign import timelockStart_newTimelockstart :: BigNum -> TimelockStart

-- | Timelock start class
type TimelockStartClass =
  { free :: TimelockStart -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: TimelockStart -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> TimelockStart
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: TimelockStart -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> TimelockStart
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: TimelockStart -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: TimelockStart -> TimelockStartJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> TimelockStart
    -- ^ From json
    -- > fromJson json
  , slot :: TimelockStart -> Number
    -- ^ Slot
    -- > slot self
  , slotBignum :: TimelockStart -> BigNum
    -- ^ Slot bignum
    -- > slotBignum self
  , new :: Number -> TimelockStart
    -- ^ New
    -- > new slot
  , newTimelockstart :: BigNum -> TimelockStart
    -- ^ New timelockstart
    -- > newTimelockstart slot
  }

-- | Timelock start class API
timelockStart :: TimelockStartClass
timelockStart =
  { free: timelockStart_free
  , toBytes: timelockStart_toBytes
  , fromBytes: timelockStart_fromBytes
  , toHex: timelockStart_toHex
  , fromHex: timelockStart_fromHex
  , toJson: timelockStart_toJson
  , toJsValue: timelockStart_toJsValue
  , fromJson: timelockStart_fromJson
  , slot: timelockStart_slot
  , slotBignum: timelockStart_slotBignum
  , new: timelockStart_new
  , newTimelockstart: timelockStart_newTimelockstart
  }

instance HasFree TimelockStart where
  free = timelockStart.free

instance Show TimelockStart where
  show = timelockStart.toHex

instance ToJsValue TimelockStart where
  toJsValue = timelockStart.toJsValue

instance IsHex TimelockStart where
  toHex = timelockStart.toHex
  fromHex = timelockStart.fromHex

instance IsBytes TimelockStart where
  toBytes = timelockStart.toBytes
  fromBytes = timelockStart.fromBytes

instance IsJson TimelockStart where
  toJson = timelockStart.toJson
  fromJson = timelockStart.fromJson

-------------------------------------------------------------------------------------
-- Transaction

foreign import tx_free :: Tx -> Effect Unit
foreign import tx_toBytes :: Tx -> Bytes
foreign import tx_fromBytes :: Bytes -> Tx
foreign import tx_toHex :: Tx -> String
foreign import tx_fromHex :: String -> Tx
foreign import tx_toJson :: Tx -> String
foreign import tx_toJsValue :: Tx -> TxJson
foreign import tx_fromJson :: String -> Tx
foreign import tx_body :: Tx -> TxBody
foreign import tx_witnessSet :: Tx -> TxWitnessSet
foreign import tx_isValid :: Tx -> Boolean
foreign import tx_auxiliaryData :: Tx -> Nullable AuxiliaryData
foreign import tx_setIsValid :: Tx -> Boolean -> Effect Unit
foreign import tx_new :: TxBody -> TxWitnessSet -> AuxiliaryData -> Tx

-- | Transaction class
type TxClass =
  { free :: Tx -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Tx -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Tx
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Tx -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Tx
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Tx -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Tx -> TxJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Tx
    -- ^ From json
    -- > fromJson json
  , body :: Tx -> TxBody
    -- ^ Body
    -- > body self
  , witnessSet :: Tx -> TxWitnessSet
    -- ^ Witness set
    -- > witnessSet self
  , isValid :: Tx -> Boolean
    -- ^ Is valid
    -- > isValid self
  , auxiliaryData :: Tx -> Maybe AuxiliaryData
    -- ^ Auxiliary data
    -- > auxiliaryData self
  , setIsValid :: Tx -> Boolean -> Effect Unit
    -- ^ Set is valid
    -- > setIsValid self valid
  , new :: TxBody -> TxWitnessSet -> AuxiliaryData -> Tx
    -- ^ New
    -- > new body witnessSet auxiliaryData
  }

-- | Transaction class API
tx :: TxClass
tx =
  { free: tx_free
  , toBytes: tx_toBytes
  , fromBytes: tx_fromBytes
  , toHex: tx_toHex
  , fromHex: tx_fromHex
  , toJson: tx_toJson
  , toJsValue: tx_toJsValue
  , fromJson: tx_fromJson
  , body: tx_body
  , witnessSet: tx_witnessSet
  , isValid: tx_isValid
  , auxiliaryData: \a1 -> Nullable.toMaybe $ tx_auxiliaryData a1
  , setIsValid: tx_setIsValid
  , new: tx_new
  }

instance HasFree Tx where
  free = tx.free

instance Show Tx where
  show = tx.toHex

instance ToJsValue Tx where
  toJsValue = tx.toJsValue

instance IsHex Tx where
  toHex = tx.toHex
  fromHex = tx.fromHex

instance IsBytes Tx where
  toBytes = tx.toBytes
  fromBytes = tx.fromBytes

instance IsJson Tx where
  toJson = tx.toJson
  fromJson = tx.fromJson

-------------------------------------------------------------------------------------
-- Transaction bodies

foreign import txBodies_free :: TxBodies -> Effect Unit
foreign import txBodies_toBytes :: TxBodies -> Bytes
foreign import txBodies_fromBytes :: Bytes -> TxBodies
foreign import txBodies_toHex :: TxBodies -> String
foreign import txBodies_fromHex :: String -> TxBodies
foreign import txBodies_toJson :: TxBodies -> String
foreign import txBodies_toJsValue :: TxBodies -> TxBodiesJson
foreign import txBodies_fromJson :: String -> TxBodies
foreign import txBodies_new :: Effect TxBodies
foreign import txBodies_len :: TxBodies -> Effect Int
foreign import txBodies_get :: TxBodies -> Int -> Effect TxBody
foreign import txBodies_add :: TxBodies -> TxBody -> Effect Unit

-- | Transaction bodies class
type TxBodiesClass =
  { free :: TxBodies -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: TxBodies -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> TxBodies
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: TxBodies -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> TxBodies
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: TxBodies -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: TxBodies -> TxBodiesJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> TxBodies
    -- ^ From json
    -- > fromJson json
  , new :: Effect TxBodies
    -- ^ New
    -- > new
  , len :: TxBodies -> Effect Int
    -- ^ Len
    -- > len self
  , get :: TxBodies -> Int -> Effect TxBody
    -- ^ Get
    -- > get self index
  , add :: TxBodies -> TxBody -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Transaction bodies class API
txBodies :: TxBodiesClass
txBodies =
  { free: txBodies_free
  , toBytes: txBodies_toBytes
  , fromBytes: txBodies_fromBytes
  , toHex: txBodies_toHex
  , fromHex: txBodies_fromHex
  , toJson: txBodies_toJson
  , toJsValue: txBodies_toJsValue
  , fromJson: txBodies_fromJson
  , new: txBodies_new
  , len: txBodies_len
  , get: txBodies_get
  , add: txBodies_add
  }

instance HasFree TxBodies where
  free = txBodies.free

instance Show TxBodies where
  show = txBodies.toHex

instance MutableList TxBodies TxBody where
  addItem = txBodies.add
  getItem = txBodies.get
  emptyList = txBodies.new

instance MutableLen TxBodies where
  getLen = txBodies.len


instance ToJsValue TxBodies where
  toJsValue = txBodies.toJsValue

instance IsHex TxBodies where
  toHex = txBodies.toHex
  fromHex = txBodies.fromHex

instance IsBytes TxBodies where
  toBytes = txBodies.toBytes
  fromBytes = txBodies.fromBytes

instance IsJson TxBodies where
  toJson = txBodies.toJson
  fromJson = txBodies.fromJson

-------------------------------------------------------------------------------------
-- Transaction body

foreign import txBody_free :: TxBody -> Effect Unit
foreign import txBody_toBytes :: TxBody -> Bytes
foreign import txBody_fromBytes :: Bytes -> TxBody
foreign import txBody_toHex :: TxBody -> String
foreign import txBody_fromHex :: String -> TxBody
foreign import txBody_toJson :: TxBody -> String
foreign import txBody_toJsValue :: TxBody -> TxBodyJson
foreign import txBody_fromJson :: String -> TxBody
foreign import txBody_ins :: TxBody -> TxIns
foreign import txBody_outs :: TxBody -> TxOuts
foreign import txBody_fee :: TxBody -> BigNum
foreign import txBody_ttl :: TxBody -> Nullable Number
foreign import txBody_ttlBignum :: TxBody -> Nullable BigNum
foreign import txBody_setTtl :: TxBody -> BigNum -> Effect Unit
foreign import txBody_removeTtl :: TxBody -> Effect Unit
foreign import txBody_setCerts :: TxBody -> Certificates -> Effect Unit
foreign import txBody_certs :: TxBody -> Nullable Certificates
foreign import txBody_setWithdrawals :: TxBody -> Withdrawals -> Effect Unit
foreign import txBody_withdrawals :: TxBody -> Nullable Withdrawals
foreign import txBody_setUpdate :: TxBody -> Update -> Effect Unit
foreign import txBody_update :: TxBody -> Nullable Update
foreign import txBody_setAuxiliaryDataHash :: TxBody -> AuxiliaryDataHash -> Effect Unit
foreign import txBody_auxiliaryDataHash :: TxBody -> Nullable AuxiliaryDataHash
foreign import txBody_setValidityStartInterval :: TxBody -> Number -> Effect Unit
foreign import txBody_setValidityStartIntervalBignum :: TxBody -> BigNum -> Effect Unit
foreign import txBody_validityStartIntervalBignum :: TxBody -> Nullable BigNum
foreign import txBody_validityStartInterval :: TxBody -> Nullable Number
foreign import txBody_setMint :: TxBody -> Mint -> Effect Unit
foreign import txBody_mint :: TxBody -> Nullable Mint
foreign import txBody_multiassets :: TxBody -> Nullable Mint
foreign import txBody_setReferenceIns :: TxBody -> TxIns -> Effect Unit
foreign import txBody_referenceIns :: TxBody -> Nullable TxIns
foreign import txBody_setScriptDataHash :: TxBody -> ScriptDataHash -> Effect Unit
foreign import txBody_scriptDataHash :: TxBody -> Nullable ScriptDataHash
foreign import txBody_setCollateral :: TxBody -> TxIns -> Effect Unit
foreign import txBody_collateral :: TxBody -> Nullable TxIns
foreign import txBody_setRequiredSigners :: TxBody -> Ed25519KeyHashes -> Effect Unit
foreign import txBody_requiredSigners :: TxBody -> Nullable Ed25519KeyHashes
foreign import txBody_setNetworkId :: TxBody -> NetworkId -> Effect Unit
foreign import txBody_networkId :: TxBody -> Nullable NetworkId
foreign import txBody_setCollateralReturn :: TxBody -> TxOut -> Effect Unit
foreign import txBody_collateralReturn :: TxBody -> Nullable TxOut
foreign import txBody_setTotalCollateral :: TxBody -> BigNum -> Effect Unit
foreign import txBody_totalCollateral :: TxBody -> Nullable BigNum
foreign import txBody_new :: TxIns -> TxOuts -> BigNum -> Number -> TxBody
foreign import txBody_newTxBody :: TxIns -> TxOuts -> BigNum -> TxBody

-- | Transaction body class
type TxBodyClass =
  { free :: TxBody -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: TxBody -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> TxBody
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: TxBody -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> TxBody
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: TxBody -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: TxBody -> TxBodyJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> TxBody
    -- ^ From json
    -- > fromJson json
  , ins :: TxBody -> TxIns
    -- ^ Inputs
    -- > ins self
  , outs :: TxBody -> TxOuts
    -- ^ Outputs
    -- > outs self
  , fee :: TxBody -> BigNum
    -- ^ Fee
    -- > fee self
  , ttl :: TxBody -> Maybe Number
    -- ^ Ttl
    -- > ttl self
  , ttlBignum :: TxBody -> Maybe BigNum
    -- ^ Ttl bignum
    -- > ttlBignum self
  , setTtl :: TxBody -> BigNum -> Effect Unit
    -- ^ Set ttl
    -- > setTtl self ttl
  , removeTtl :: TxBody -> Effect Unit
    -- ^ Remove ttl
    -- > removeTtl self
  , setCerts :: TxBody -> Certificates -> Effect Unit
    -- ^ Set certs
    -- > setCerts self certs
  , certs :: TxBody -> Maybe Certificates
    -- ^ Certs
    -- > certs self
  , setWithdrawals :: TxBody -> Withdrawals -> Effect Unit
    -- ^ Set withdrawals
    -- > setWithdrawals self withdrawals
  , withdrawals :: TxBody -> Maybe Withdrawals
    -- ^ Withdrawals
    -- > withdrawals self
  , setUpdate :: TxBody -> Update -> Effect Unit
    -- ^ Set update
    -- > setUpdate self update
  , update :: TxBody -> Maybe Update
    -- ^ Update
    -- > update self
  , setAuxiliaryDataHash :: TxBody -> AuxiliaryDataHash -> Effect Unit
    -- ^ Set auxiliary data hash
    -- > setAuxiliaryDataHash self auxiliaryDataHash
  , auxiliaryDataHash :: TxBody -> Maybe AuxiliaryDataHash
    -- ^ Auxiliary data hash
    -- > auxiliaryDataHash self
  , setValidityStartInterval :: TxBody -> Number -> Effect Unit
    -- ^ Set validity start interval
    -- > setValidityStartInterval self validityStartInterval
  , setValidityStartIntervalBignum :: TxBody -> BigNum -> Effect Unit
    -- ^ Set validity start interval bignum
    -- > setValidityStartIntervalBignum self validityStartInterval
  , validityStartIntervalBignum :: TxBody -> Maybe BigNum
    -- ^ Validity start interval bignum
    -- > validityStartIntervalBignum self
  , validityStartInterval :: TxBody -> Maybe Number
    -- ^ Validity start interval
    -- > validityStartInterval self
  , setMint :: TxBody -> Mint -> Effect Unit
    -- ^ Set mint
    -- > setMint self mint
  , mint :: TxBody -> Maybe Mint
    -- ^ Mint
    -- > mint self
  , multiassets :: TxBody -> Maybe Mint
    -- ^ Multiassets
    -- > multiassets self
  , setReferenceIns :: TxBody -> TxIns -> Effect Unit
    -- ^ Set reference inputs
    -- > setReferenceIns self referenceIns
  , referenceIns :: TxBody -> Maybe TxIns
    -- ^ Reference inputs
    -- > referenceIns self
  , setScriptDataHash :: TxBody -> ScriptDataHash -> Effect Unit
    -- ^ Set script data hash
    -- > setScriptDataHash self scriptDataHash
  , scriptDataHash :: TxBody -> Maybe ScriptDataHash
    -- ^ Script data hash
    -- > scriptDataHash self
  , setCollateral :: TxBody -> TxIns -> Effect Unit
    -- ^ Set collateral
    -- > setCollateral self collateral
  , collateral :: TxBody -> Maybe TxIns
    -- ^ Collateral
    -- > collateral self
  , setRequiredSigners :: TxBody -> Ed25519KeyHashes -> Effect Unit
    -- ^ Set required signers
    -- > setRequiredSigners self requiredSigners
  , requiredSigners :: TxBody -> Maybe Ed25519KeyHashes
    -- ^ Required signers
    -- > requiredSigners self
  , setNetworkId :: TxBody -> NetworkId -> Effect Unit
    -- ^ Set network id
    -- > setNetworkId self networkId
  , networkId :: TxBody -> Maybe NetworkId
    -- ^ Network id
    -- > networkId self
  , setCollateralReturn :: TxBody -> TxOut -> Effect Unit
    -- ^ Set collateral return
    -- > setCollateralReturn self collateralReturn
  , collateralReturn :: TxBody -> Maybe TxOut
    -- ^ Collateral return
    -- > collateralReturn self
  , setTotalCollateral :: TxBody -> BigNum -> Effect Unit
    -- ^ Set total collateral
    -- > setTotalCollateral self totalCollateral
  , totalCollateral :: TxBody -> Maybe BigNum
    -- ^ Total collateral
    -- > totalCollateral self
  , new :: TxIns -> TxOuts -> BigNum -> Number -> TxBody
    -- ^ New
    -- > new ins outs fee ttl
  , newTxBody :: TxIns -> TxOuts -> BigNum -> TxBody
    -- ^ New tx body
    -- > newTxBody ins outs fee
  }

-- | Transaction body class API
txBody :: TxBodyClass
txBody =
  { free: txBody_free
  , toBytes: txBody_toBytes
  , fromBytes: txBody_fromBytes
  , toHex: txBody_toHex
  , fromHex: txBody_fromHex
  , toJson: txBody_toJson
  , toJsValue: txBody_toJsValue
  , fromJson: txBody_fromJson
  , ins: txBody_ins
  , outs: txBody_outs
  , fee: txBody_fee
  , ttl: \a1 -> Nullable.toMaybe $ txBody_ttl a1
  , ttlBignum: \a1 -> Nullable.toMaybe $ txBody_ttlBignum a1
  , setTtl: txBody_setTtl
  , removeTtl: txBody_removeTtl
  , setCerts: txBody_setCerts
  , certs: \a1 -> Nullable.toMaybe $ txBody_certs a1
  , setWithdrawals: txBody_setWithdrawals
  , withdrawals: \a1 -> Nullable.toMaybe $ txBody_withdrawals a1
  , setUpdate: txBody_setUpdate
  , update: \a1 -> Nullable.toMaybe $ txBody_update a1
  , setAuxiliaryDataHash: txBody_setAuxiliaryDataHash
  , auxiliaryDataHash: \a1 -> Nullable.toMaybe $ txBody_auxiliaryDataHash a1
  , setValidityStartInterval: txBody_setValidityStartInterval
  , setValidityStartIntervalBignum: txBody_setValidityStartIntervalBignum
  , validityStartIntervalBignum: \a1 -> Nullable.toMaybe $ txBody_validityStartIntervalBignum a1
  , validityStartInterval: \a1 -> Nullable.toMaybe $ txBody_validityStartInterval a1
  , setMint: txBody_setMint
  , mint: \a1 -> Nullable.toMaybe $ txBody_mint a1
  , multiassets: \a1 -> Nullable.toMaybe $ txBody_multiassets a1
  , setReferenceIns: txBody_setReferenceIns
  , referenceIns: \a1 -> Nullable.toMaybe $ txBody_referenceIns a1
  , setScriptDataHash: txBody_setScriptDataHash
  , scriptDataHash: \a1 -> Nullable.toMaybe $ txBody_scriptDataHash a1
  , setCollateral: txBody_setCollateral
  , collateral: \a1 -> Nullable.toMaybe $ txBody_collateral a1
  , setRequiredSigners: txBody_setRequiredSigners
  , requiredSigners: \a1 -> Nullable.toMaybe $ txBody_requiredSigners a1
  , setNetworkId: txBody_setNetworkId
  , networkId: \a1 -> Nullable.toMaybe $ txBody_networkId a1
  , setCollateralReturn: txBody_setCollateralReturn
  , collateralReturn: \a1 -> Nullable.toMaybe $ txBody_collateralReturn a1
  , setTotalCollateral: txBody_setTotalCollateral
  , totalCollateral: \a1 -> Nullable.toMaybe $ txBody_totalCollateral a1
  , new: txBody_new
  , newTxBody: txBody_newTxBody
  }

instance HasFree TxBody where
  free = txBody.free

instance Show TxBody where
  show = txBody.toHex

instance ToJsValue TxBody where
  toJsValue = txBody.toJsValue

instance IsHex TxBody where
  toHex = txBody.toHex
  fromHex = txBody.fromHex

instance IsBytes TxBody where
  toBytes = txBody.toBytes
  fromBytes = txBody.fromBytes

instance IsJson TxBody where
  toJson = txBody.toJson
  fromJson = txBody.fromJson

-------------------------------------------------------------------------------------
-- Transaction builder

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
foreign import txBuilder_countMissingInScripts :: TxBuilder -> Effect Number
foreign import txBuilder_addRequiredNativeInScripts :: TxBuilder -> NativeScripts -> Effect Number
foreign import txBuilder_addRequiredPlutusInScripts :: TxBuilder -> PlutusWitnesses -> Effect Number
foreign import txBuilder_getNativeInScripts :: TxBuilder -> Effect (Nullable NativeScripts)
foreign import txBuilder_getPlutusInScripts :: TxBuilder -> Effect (Nullable PlutusWitnesses)
foreign import txBuilder_feeForIn :: TxBuilder -> Address -> TxIn -> Value -> Effect BigNum
foreign import txBuilder_addOut :: TxBuilder -> TxOut -> Effect Unit
foreign import txBuilder_feeForOut :: TxBuilder -> TxOut -> Effect BigNum
foreign import txBuilder_setFee :: TxBuilder -> BigNum -> Effect Unit
foreign import txBuilder_setTtl :: TxBuilder -> Number -> Effect Unit
foreign import txBuilder_setTtlBignum :: TxBuilder -> BigNum -> Effect Unit
foreign import txBuilder_setValidityStartInterval :: TxBuilder -> Number -> Effect Unit
foreign import txBuilder_setValidityStartIntervalBignum :: TxBuilder -> BigNum -> Effect Unit
foreign import txBuilder_setCerts :: TxBuilder -> Certificates -> Effect Unit
foreign import txBuilder_setWithdrawals :: TxBuilder -> Withdrawals -> Effect Unit
foreign import txBuilder_getAuxiliaryData :: TxBuilder -> Effect (Nullable AuxiliaryData)
foreign import txBuilder_setAuxiliaryData :: TxBuilder -> AuxiliaryData -> Effect Unit
foreign import txBuilder_setMetadata :: TxBuilder -> GeneralTxMetadata -> Effect Unit
foreign import txBuilder_addMetadatum :: TxBuilder -> BigNum -> TxMetadatum -> Effect Unit
foreign import txBuilder_addJsonMetadatum :: TxBuilder -> BigNum -> String -> Effect Unit
foreign import txBuilder_addJsonMetadatumWithSchema :: TxBuilder -> BigNum -> String -> Number -> Effect Unit
foreign import txBuilder_setMint :: TxBuilder -> Mint -> NativeScripts -> Effect Unit
foreign import txBuilder_getMint :: TxBuilder -> Effect (Nullable Mint)
foreign import txBuilder_getMintScripts :: TxBuilder -> Effect (Nullable NativeScripts)
foreign import txBuilder_setMintAsset :: TxBuilder -> NativeScript -> MintAssets -> Effect Unit
foreign import txBuilder_addMintAsset :: TxBuilder -> NativeScript -> AssetName -> Int -> Effect Unit
foreign import txBuilder_addMintAssetAndOut :: TxBuilder -> NativeScript -> AssetName -> Int -> TxOutAmountBuilder -> BigNum -> Effect Unit
foreign import txBuilder_addMintAssetAndOutMinRequiredCoin :: TxBuilder -> NativeScript -> AssetName -> Int -> TxOutAmountBuilder -> Effect Unit
foreign import txBuilder_new :: TxBuilderConfig -> Effect TxBuilder
foreign import txBuilder_getReferenceIns :: TxBuilder -> Effect TxIns
foreign import txBuilder_getExplicitIn :: TxBuilder -> Effect Value
foreign import txBuilder_getImplicitIn :: TxBuilder -> Effect Value
foreign import txBuilder_getTotalIn :: TxBuilder -> Effect Value
foreign import txBuilder_getTotalOut :: TxBuilder -> Effect Value
foreign import txBuilder_getExplicitOut :: TxBuilder -> Effect Value
foreign import txBuilder_getDeposit :: TxBuilder -> Effect BigNum
foreign import txBuilder_getFeeIfSet :: TxBuilder -> Effect (Nullable BigNum)
foreign import txBuilder_addChangeIfNeeded :: TxBuilder -> Address -> Effect Boolean
foreign import txBuilder_calcScriptDataHash :: TxBuilder -> Costmdls -> Effect Unit
foreign import txBuilder_setScriptDataHash :: TxBuilder -> ScriptDataHash -> Effect Unit
foreign import txBuilder_removeScriptDataHash :: TxBuilder -> Effect Unit
foreign import txBuilder_addRequiredSigner :: TxBuilder -> Ed25519KeyHash -> Effect Unit
foreign import txBuilder_fullSize :: TxBuilder -> Effect Number
foreign import txBuilder_outSizes :: TxBuilder -> Effect Uint32Array
foreign import txBuilder_build :: TxBuilder -> Effect TxBody
foreign import txBuilder_buildTx :: TxBuilder -> Effect Tx
foreign import txBuilder_buildTxUnsafe :: TxBuilder -> Effect Tx
foreign import txBuilder_minFee :: TxBuilder -> Effect BigNum

-- | Transaction builder class
type TxBuilderClass =
  { free :: TxBuilder -> Effect Unit
    -- ^ Free
    -- > free self
  , addInsFrom :: TxBuilder -> TxUnspentOuts -> Number -> Effect Unit
    -- ^ Add inputs from
    -- > addInsFrom self ins strategy
  , setIns :: TxBuilder -> TxInsBuilder -> Effect Unit
    -- ^ Set inputs
    -- > setIns self ins
  , setCollateral :: TxBuilder -> TxInsBuilder -> Effect Unit
    -- ^ Set collateral
    -- > setCollateral self collateral
  , setCollateralReturn :: TxBuilder -> TxOut -> Effect Unit
    -- ^ Set collateral return
    -- > setCollateralReturn self collateralReturn
  , setCollateralReturnAndTotal :: TxBuilder -> TxOut -> Effect Unit
    -- ^ Set collateral return and total
    -- > setCollateralReturnAndTotal self collateralReturn
  , setTotalCollateral :: TxBuilder -> BigNum -> Effect Unit
    -- ^ Set total collateral
    -- > setTotalCollateral self totalCollateral
  , setTotalCollateralAndReturn :: TxBuilder -> BigNum -> Address -> Effect Unit
    -- ^ Set total collateral and return
    -- > setTotalCollateralAndReturn self totalCollateral returnAddress
  , addReferenceIn :: TxBuilder -> TxIn -> Effect Unit
    -- ^ Add reference input
    -- > addReferenceIn self referenceIn
  , addKeyIn :: TxBuilder -> Ed25519KeyHash -> TxIn -> Value -> Effect Unit
    -- ^ Add key input
    -- > addKeyIn self hash in amount
  , addScriptIn :: TxBuilder -> ScriptHash -> TxIn -> Value -> Effect Unit
    -- ^ Add script input
    -- > addScriptIn self hash in amount
  , addNativeScriptIn :: TxBuilder -> NativeScript -> TxIn -> Value -> Effect Unit
    -- ^ Add native script input
    -- > addNativeScriptIn self script in amount
  , addPlutusScriptIn :: TxBuilder -> PlutusWitness -> TxIn -> Value -> Effect Unit
    -- ^ Add plutus script input
    -- > addPlutusScriptIn self witness in amount
  , addBootstrapIn :: TxBuilder -> ByronAddress -> TxIn -> Value -> Effect Unit
    -- ^ Add bootstrap input
    -- > addBootstrapIn self hash in amount
  , addIn :: TxBuilder -> Address -> TxIn -> Value -> Effect Unit
    -- ^ Add input
    -- > addIn self address in amount
  , countMissingInScripts :: TxBuilder -> Effect Number
    -- ^ Count missing input scripts
    -- > countMissingInScripts self
  , addRequiredNativeInScripts :: TxBuilder -> NativeScripts -> Effect Number
    -- ^ Add required native input scripts
    -- > addRequiredNativeInScripts self scripts
  , addRequiredPlutusInScripts :: TxBuilder -> PlutusWitnesses -> Effect Number
    -- ^ Add required plutus input scripts
    -- > addRequiredPlutusInScripts self scripts
  , getNativeInScripts :: TxBuilder -> Effect (Maybe NativeScripts)
    -- ^ Get native input scripts
    -- > getNativeInScripts self
  , getPlutusInScripts :: TxBuilder -> Effect (Maybe PlutusWitnesses)
    -- ^ Get plutus input scripts
    -- > getPlutusInScripts self
  , feeForIn :: TxBuilder -> Address -> TxIn -> Value -> Effect BigNum
    -- ^ Fee for input
    -- > feeForIn self address in amount
  , addOut :: TxBuilder -> TxOut -> Effect Unit
    -- ^ Add output
    -- > addOut self out
  , feeForOut :: TxBuilder -> TxOut -> Effect BigNum
    -- ^ Fee for output
    -- > feeForOut self out
  , setFee :: TxBuilder -> BigNum -> Effect Unit
    -- ^ Set fee
    -- > setFee self fee
  , setTtl :: TxBuilder -> Number -> Effect Unit
    -- ^ Set ttl
    -- > setTtl self ttl
  , setTtlBignum :: TxBuilder -> BigNum -> Effect Unit
    -- ^ Set ttl bignum
    -- > setTtlBignum self ttl
  , setValidityStartInterval :: TxBuilder -> Number -> Effect Unit
    -- ^ Set validity start interval
    -- > setValidityStartInterval self validityStartInterval
  , setValidityStartIntervalBignum :: TxBuilder -> BigNum -> Effect Unit
    -- ^ Set validity start interval bignum
    -- > setValidityStartIntervalBignum self validityStartInterval
  , setCerts :: TxBuilder -> Certificates -> Effect Unit
    -- ^ Set certs
    -- > setCerts self certs
  , setWithdrawals :: TxBuilder -> Withdrawals -> Effect Unit
    -- ^ Set withdrawals
    -- > setWithdrawals self withdrawals
  , getAuxiliaryData :: TxBuilder -> Effect (Maybe AuxiliaryData)
    -- ^ Get auxiliary data
    -- > getAuxiliaryData self
  , setAuxiliaryData :: TxBuilder -> AuxiliaryData -> Effect Unit
    -- ^ Set auxiliary data
    -- > setAuxiliaryData self auxiliaryData
  , setMetadata :: TxBuilder -> GeneralTxMetadata -> Effect Unit
    -- ^ Set metadata
    -- > setMetadata self metadata
  , addMetadatum :: TxBuilder -> BigNum -> TxMetadatum -> Effect Unit
    -- ^ Add metadatum
    -- > addMetadatum self key val
  , addJsonMetadatum :: TxBuilder -> BigNum -> String -> Effect Unit
    -- ^ Add json metadatum
    -- > addJsonMetadatum self key val
  , addJsonMetadatumWithSchema :: TxBuilder -> BigNum -> String -> Number -> Effect Unit
    -- ^ Add json metadatum with schema
    -- > addJsonMetadatumWithSchema self key val schema
  , setMint :: TxBuilder -> Mint -> NativeScripts -> Effect Unit
    -- ^ Set mint
    -- > setMint self mint mintScripts
  , getMint :: TxBuilder -> Effect (Maybe Mint)
    -- ^ Get mint
    -- > getMint self
  , getMintScripts :: TxBuilder -> Effect (Maybe NativeScripts)
    -- ^ Get mint scripts
    -- > getMintScripts self
  , setMintAsset :: TxBuilder -> NativeScript -> MintAssets -> Effect Unit
    -- ^ Set mint asset
    -- > setMintAsset self policyScript mintAssets
  , addMintAsset :: TxBuilder -> NativeScript -> AssetName -> Int -> Effect Unit
    -- ^ Add mint asset
    -- > addMintAsset self policyScript assetName amount
  , addMintAssetAndOut :: TxBuilder -> NativeScript -> AssetName -> Int -> TxOutAmountBuilder -> BigNum -> Effect Unit
    -- ^ Add mint asset and output
    -- > addMintAssetAndOut self policyScript assetName amount outBuilder outCoin
  , addMintAssetAndOutMinRequiredCoin :: TxBuilder -> NativeScript -> AssetName -> Int -> TxOutAmountBuilder -> Effect Unit
    -- ^ Add mint asset and output min required coin
    -- > addMintAssetAndOutMinRequiredCoin self policyScript assetName amount outBuilder
  , new :: TxBuilderConfig -> Effect TxBuilder
    -- ^ New
    -- > new cfg
  , getReferenceIns :: TxBuilder -> Effect TxIns
    -- ^ Get reference inputs
    -- > getReferenceIns self
  , getExplicitIn :: TxBuilder -> Effect Value
    -- ^ Get explicit input
    -- > getExplicitIn self
  , getImplicitIn :: TxBuilder -> Effect Value
    -- ^ Get implicit input
    -- > getImplicitIn self
  , getTotalIn :: TxBuilder -> Effect Value
    -- ^ Get total input
    -- > getTotalIn self
  , getTotalOut :: TxBuilder -> Effect Value
    -- ^ Get total output
    -- > getTotalOut self
  , getExplicitOut :: TxBuilder -> Effect Value
    -- ^ Get explicit output
    -- > getExplicitOut self
  , getDeposit :: TxBuilder -> Effect BigNum
    -- ^ Get deposit
    -- > getDeposit self
  , getFeeIfSet :: TxBuilder -> Effect (Maybe BigNum)
    -- ^ Get fee if set
    -- > getFeeIfSet self
  , addChangeIfNeeded :: TxBuilder -> Address -> Effect Boolean
    -- ^ Add change if needed
    -- > addChangeIfNeeded self address
  , calcScriptDataHash :: TxBuilder -> Costmdls -> Effect Unit
    -- ^ Calc script data hash
    -- > calcScriptDataHash self costModels
  , setScriptDataHash :: TxBuilder -> ScriptDataHash -> Effect Unit
    -- ^ Set script data hash
    -- > setScriptDataHash self hash
  , removeScriptDataHash :: TxBuilder -> Effect Unit
    -- ^ Remove script data hash
    -- > removeScriptDataHash self
  , addRequiredSigner :: TxBuilder -> Ed25519KeyHash -> Effect Unit
    -- ^ Add required signer
    -- > addRequiredSigner self key
  , fullSize :: TxBuilder -> Effect Number
    -- ^ Full size
    -- > fullSize self
  , outSizes :: TxBuilder -> Effect Uint32Array
    -- ^ Output sizes
    -- > outSizes self
  , build :: TxBuilder -> Effect TxBody
    -- ^ Build
    -- > build self
  , buildTx :: TxBuilder -> Effect Tx
    -- ^ Build tx
    -- > buildTx self
  , buildTxUnsafe :: TxBuilder -> Effect Tx
    -- ^ Build tx unsafe
    -- > buildTxUnsafe self
  , minFee :: TxBuilder -> Effect BigNum
    -- ^ Min fee
    -- > minFee self
  }

-- | Transaction builder class API
txBuilder :: TxBuilderClass
txBuilder =
  { free: txBuilder_free
  , addInsFrom: txBuilder_addInsFrom
  , setIns: txBuilder_setIns
  , setCollateral: txBuilder_setCollateral
  , setCollateralReturn: txBuilder_setCollateralReturn
  , setCollateralReturnAndTotal: txBuilder_setCollateralReturnAndTotal
  , setTotalCollateral: txBuilder_setTotalCollateral
  , setTotalCollateralAndReturn: txBuilder_setTotalCollateralAndReturn
  , addReferenceIn: txBuilder_addReferenceIn
  , addKeyIn: txBuilder_addKeyIn
  , addScriptIn: txBuilder_addScriptIn
  , addNativeScriptIn: txBuilder_addNativeScriptIn
  , addPlutusScriptIn: txBuilder_addPlutusScriptIn
  , addBootstrapIn: txBuilder_addBootstrapIn
  , addIn: txBuilder_addIn
  , countMissingInScripts: txBuilder_countMissingInScripts
  , addRequiredNativeInScripts: txBuilder_addRequiredNativeInScripts
  , addRequiredPlutusInScripts: txBuilder_addRequiredPlutusInScripts
  , getNativeInScripts: \a1 -> Nullable.toMaybe <$> txBuilder_getNativeInScripts a1
  , getPlutusInScripts: \a1 -> Nullable.toMaybe <$> txBuilder_getPlutusInScripts a1
  , feeForIn: txBuilder_feeForIn
  , addOut: txBuilder_addOut
  , feeForOut: txBuilder_feeForOut
  , setFee: txBuilder_setFee
  , setTtl: txBuilder_setTtl
  , setTtlBignum: txBuilder_setTtlBignum
  , setValidityStartInterval: txBuilder_setValidityStartInterval
  , setValidityStartIntervalBignum: txBuilder_setValidityStartIntervalBignum
  , setCerts: txBuilder_setCerts
  , setWithdrawals: txBuilder_setWithdrawals
  , getAuxiliaryData: \a1 -> Nullable.toMaybe <$> txBuilder_getAuxiliaryData a1
  , setAuxiliaryData: txBuilder_setAuxiliaryData
  , setMetadata: txBuilder_setMetadata
  , addMetadatum: txBuilder_addMetadatum
  , addJsonMetadatum: txBuilder_addJsonMetadatum
  , addJsonMetadatumWithSchema: txBuilder_addJsonMetadatumWithSchema
  , setMint: txBuilder_setMint
  , getMint: \a1 -> Nullable.toMaybe <$> txBuilder_getMint a1
  , getMintScripts: \a1 -> Nullable.toMaybe <$> txBuilder_getMintScripts a1
  , setMintAsset: txBuilder_setMintAsset
  , addMintAsset: txBuilder_addMintAsset
  , addMintAssetAndOut: txBuilder_addMintAssetAndOut
  , addMintAssetAndOutMinRequiredCoin: txBuilder_addMintAssetAndOutMinRequiredCoin
  , new: txBuilder_new
  , getReferenceIns: txBuilder_getReferenceIns
  , getExplicitIn: txBuilder_getExplicitIn
  , getImplicitIn: txBuilder_getImplicitIn
  , getTotalIn: txBuilder_getTotalIn
  , getTotalOut: txBuilder_getTotalOut
  , getExplicitOut: txBuilder_getExplicitOut
  , getDeposit: txBuilder_getDeposit
  , getFeeIfSet: \a1 -> Nullable.toMaybe <$> txBuilder_getFeeIfSet a1
  , addChangeIfNeeded: txBuilder_addChangeIfNeeded
  , calcScriptDataHash: txBuilder_calcScriptDataHash
  , setScriptDataHash: txBuilder_setScriptDataHash
  , removeScriptDataHash: txBuilder_removeScriptDataHash
  , addRequiredSigner: txBuilder_addRequiredSigner
  , fullSize: txBuilder_fullSize
  , outSizes: txBuilder_outSizes
  , build: txBuilder_build
  , buildTx: txBuilder_buildTx
  , buildTxUnsafe: txBuilder_buildTxUnsafe
  , minFee: txBuilder_minFee
  }

instance HasFree TxBuilder where
  free = txBuilder.free

-------------------------------------------------------------------------------------
-- Transaction builder config

foreign import txBuilderConfig_free :: TxBuilderConfig -> Effect Unit

-- | Transaction builder config class
type TxBuilderConfigClass =
  { free :: TxBuilderConfig -> Effect Unit
    -- ^ Free
    -- > free self
  }

-- | Transaction builder config class API
txBuilderConfig :: TxBuilderConfigClass
txBuilderConfig =
  { free: txBuilderConfig_free
  }

instance HasFree TxBuilderConfig where
  free = txBuilderConfig.free

-------------------------------------------------------------------------------------
-- Transaction builder config builder

foreign import txBuilderConfigBuilder_free :: TxBuilderConfigBuilder -> Effect Unit
foreign import txBuilderConfigBuilder_new :: TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_feeAlgo :: TxBuilderConfigBuilder -> LinearFee -> TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_coinsPerUtxoWord :: TxBuilderConfigBuilder -> BigNum -> TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_coinsPerUtxoByte :: TxBuilderConfigBuilder -> BigNum -> TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_exUnitPrices :: TxBuilderConfigBuilder -> ExUnitPrices -> TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_poolDeposit :: TxBuilderConfigBuilder -> BigNum -> TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_keyDeposit :: TxBuilderConfigBuilder -> BigNum -> TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_maxValueSize :: TxBuilderConfigBuilder -> Int -> TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_maxTxSize :: TxBuilderConfigBuilder -> Int -> TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_preferPureChange :: TxBuilderConfigBuilder -> Boolean -> TxBuilderConfigBuilder
foreign import txBuilderConfigBuilder_build :: TxBuilderConfigBuilder -> TxBuilderConfig

-- | Transaction builder config builder class
type TxBuilderConfigBuilderClass =
  { free :: TxBuilderConfigBuilder -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: TxBuilderConfigBuilder
    -- ^ New
    -- > new
  , feeAlgo :: TxBuilderConfigBuilder -> LinearFee -> TxBuilderConfigBuilder
    -- ^ Fee algo
    -- > feeAlgo self feeAlgo
  , coinsPerUtxoWord :: TxBuilderConfigBuilder -> BigNum -> TxBuilderConfigBuilder
    -- ^ Coins per utxo word
    -- > coinsPerUtxoWord self coinsPerUtxoWord
  , coinsPerUtxoByte :: TxBuilderConfigBuilder -> BigNum -> TxBuilderConfigBuilder
    -- ^ Coins per utxo byte
    -- > coinsPerUtxoByte self coinsPerUtxoByte
  , exUnitPrices :: TxBuilderConfigBuilder -> ExUnitPrices -> TxBuilderConfigBuilder
    -- ^ Ex unit prices
    -- > exUnitPrices self exUnitPrices
  , poolDeposit :: TxBuilderConfigBuilder -> BigNum -> TxBuilderConfigBuilder
    -- ^ Pool deposit
    -- > poolDeposit self poolDeposit
  , keyDeposit :: TxBuilderConfigBuilder -> BigNum -> TxBuilderConfigBuilder
    -- ^ Key deposit
    -- > keyDeposit self keyDeposit
  , maxValueSize :: TxBuilderConfigBuilder -> Int -> TxBuilderConfigBuilder
    -- ^ Max value size
    -- > maxValueSize self maxValueSize
  , maxTxSize :: TxBuilderConfigBuilder -> Int -> TxBuilderConfigBuilder
    -- ^ Max tx size
    -- > maxTxSize self maxTxSize
  , preferPureChange :: TxBuilderConfigBuilder -> Boolean -> TxBuilderConfigBuilder
    -- ^ Prefer pure change
    -- > preferPureChange self preferPureChange
  , build :: TxBuilderConfigBuilder -> TxBuilderConfig
    -- ^ Build
    -- > build self
  }

-- | Transaction builder config builder class API
txBuilderConfigBuilder :: TxBuilderConfigBuilderClass
txBuilderConfigBuilder =
  { free: txBuilderConfigBuilder_free
  , new: txBuilderConfigBuilder_new
  , feeAlgo: txBuilderConfigBuilder_feeAlgo
  , coinsPerUtxoWord: txBuilderConfigBuilder_coinsPerUtxoWord
  , coinsPerUtxoByte: txBuilderConfigBuilder_coinsPerUtxoByte
  , exUnitPrices: txBuilderConfigBuilder_exUnitPrices
  , poolDeposit: txBuilderConfigBuilder_poolDeposit
  , keyDeposit: txBuilderConfigBuilder_keyDeposit
  , maxValueSize: txBuilderConfigBuilder_maxValueSize
  , maxTxSize: txBuilderConfigBuilder_maxTxSize
  , preferPureChange: txBuilderConfigBuilder_preferPureChange
  , build: txBuilderConfigBuilder_build
  }

instance HasFree TxBuilderConfigBuilder where
  free = txBuilderConfigBuilder.free

-------------------------------------------------------------------------------------
-- Transaction hash

foreign import txHash_free :: TxHash -> Effect Unit
foreign import txHash_fromBytes :: Bytes -> TxHash
foreign import txHash_toBytes :: TxHash -> Bytes
foreign import txHash_toBech32 :: TxHash -> String -> String
foreign import txHash_fromBech32 :: String -> TxHash
foreign import txHash_toHex :: TxHash -> String
foreign import txHash_fromHex :: String -> TxHash

-- | Transaction hash class
type TxHashClass =
  { free :: TxHash -> Effect Unit
    -- ^ Free
    -- > free self
  , fromBytes :: Bytes -> TxHash
    -- ^ From bytes
    -- > fromBytes bytes
  , toBytes :: TxHash -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , toBech32 :: TxHash -> String -> String
    -- ^ To bech32
    -- > toBech32 self prefix
  , fromBech32 :: String -> TxHash
    -- ^ From bech32
    -- > fromBech32 bechStr
  , toHex :: TxHash -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> TxHash
    -- ^ From hex
    -- > fromHex hex
  }

-- | Transaction hash class API
txHash :: TxHashClass
txHash =
  { free: txHash_free
  , fromBytes: txHash_fromBytes
  , toBytes: txHash_toBytes
  , toBech32: txHash_toBech32
  , fromBech32: txHash_fromBech32
  , toHex: txHash_toHex
  , fromHex: txHash_fromHex
  }

instance HasFree TxHash where
  free = txHash.free

instance Show TxHash where
  show = txHash.toHex

instance IsHex TxHash where
  toHex = txHash.toHex
  fromHex = txHash.fromHex

instance IsBytes TxHash where
  toBytes = txHash.toBytes
  fromBytes = txHash.fromBytes

-------------------------------------------------------------------------------------
-- Transaction input

foreign import txIn_free :: TxIn -> Effect Unit
foreign import txIn_toBytes :: TxIn -> Bytes
foreign import txIn_fromBytes :: Bytes -> TxIn
foreign import txIn_toHex :: TxIn -> String
foreign import txIn_fromHex :: String -> TxIn
foreign import txIn_toJson :: TxIn -> String
foreign import txIn_toJsValue :: TxIn -> TxInJson
foreign import txIn_fromJson :: String -> TxIn
foreign import txIn_txId :: TxIn -> TxHash
foreign import txIn_index :: TxIn -> Number
foreign import txIn_new :: TxHash -> Number -> TxIn

-- | Transaction input class
type TxInClass =
  { free :: TxIn -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: TxIn -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> TxIn
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: TxIn -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> TxIn
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: TxIn -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: TxIn -> TxInJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> TxIn
    -- ^ From json
    -- > fromJson json
  , txId :: TxIn -> TxHash
    -- ^ Transaction id
    -- > txId self
  , index :: TxIn -> Number
    -- ^ Index
    -- > index self
  , new :: TxHash -> Number -> TxIn
    -- ^ New
    -- > new txId index
  }

-- | Transaction input class API
txIn :: TxInClass
txIn =
  { free: txIn_free
  , toBytes: txIn_toBytes
  , fromBytes: txIn_fromBytes
  , toHex: txIn_toHex
  , fromHex: txIn_fromHex
  , toJson: txIn_toJson
  , toJsValue: txIn_toJsValue
  , fromJson: txIn_fromJson
  , txId: txIn_txId
  , index: txIn_index
  , new: txIn_new
  }

instance HasFree TxIn where
  free = txIn.free

instance Show TxIn where
  show = txIn.toHex

instance ToJsValue TxIn where
  toJsValue = txIn.toJsValue

instance IsHex TxIn where
  toHex = txIn.toHex
  fromHex = txIn.fromHex

instance IsBytes TxIn where
  toBytes = txIn.toBytes
  fromBytes = txIn.fromBytes

instance IsJson TxIn where
  toJson = txIn.toJson
  fromJson = txIn.fromJson

-------------------------------------------------------------------------------------
-- Transaction inputs

foreign import txIns_free :: TxIns -> Effect Unit
foreign import txIns_toBytes :: TxIns -> Bytes
foreign import txIns_fromBytes :: Bytes -> TxIns
foreign import txIns_toHex :: TxIns -> String
foreign import txIns_fromHex :: String -> TxIns
foreign import txIns_toJson :: TxIns -> String
foreign import txIns_toJsValue :: TxIns -> TxInsJson
foreign import txIns_fromJson :: String -> TxIns
foreign import txIns_new :: Effect TxIns
foreign import txIns_len :: TxIns -> Effect Int
foreign import txIns_get :: TxIns -> Int -> Effect TxIn
foreign import txIns_add :: TxIns -> TxIn -> Effect Unit
foreign import txIns_toOption :: TxIns -> Nullable TxIns

-- | Transaction inputs class
type TxInsClass =
  { free :: TxIns -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: TxIns -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> TxIns
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: TxIns -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> TxIns
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: TxIns -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: TxIns -> TxInsJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> TxIns
    -- ^ From json
    -- > fromJson json
  , new :: Effect TxIns
    -- ^ New
    -- > new
  , len :: TxIns -> Effect Int
    -- ^ Len
    -- > len self
  , get :: TxIns -> Int -> Effect TxIn
    -- ^ Get
    -- > get self index
  , add :: TxIns -> TxIn -> Effect Unit
    -- ^ Add
    -- > add self elem
  , toOption :: TxIns -> Maybe TxIns
    -- ^ To option
    -- > toOption self
  }

-- | Transaction inputs class API
txIns :: TxInsClass
txIns =
  { free: txIns_free
  , toBytes: txIns_toBytes
  , fromBytes: txIns_fromBytes
  , toHex: txIns_toHex
  , fromHex: txIns_fromHex
  , toJson: txIns_toJson
  , toJsValue: txIns_toJsValue
  , fromJson: txIns_fromJson
  , new: txIns_new
  , len: txIns_len
  , get: txIns_get
  , add: txIns_add
  , toOption: \a1 -> Nullable.toMaybe $ txIns_toOption a1
  }

instance HasFree TxIns where
  free = txIns.free

instance Show TxIns where
  show = txIns.toHex

instance MutableList TxIns TxIn where
  addItem = txIns.add
  getItem = txIns.get
  emptyList = txIns.new

instance MutableLen TxIns where
  getLen = txIns.len


instance ToJsValue TxIns where
  toJsValue = txIns.toJsValue

instance IsHex TxIns where
  toHex = txIns.toHex
  fromHex = txIns.fromHex

instance IsBytes TxIns where
  toBytes = txIns.toBytes
  fromBytes = txIns.fromBytes

instance IsJson TxIns where
  toJson = txIns.toJson
  fromJson = txIns.fromJson

-------------------------------------------------------------------------------------
-- Transaction metadatum

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

-- | Transaction metadatum class
type TxMetadatumClass =
  { free :: TxMetadatum -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: TxMetadatum -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> TxMetadatum
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: TxMetadatum -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> TxMetadatum
    -- ^ From hex
    -- > fromHex hexStr
  , newMap :: MetadataMap -> TxMetadatum
    -- ^ New map
    -- > newMap map
  , newList :: MetadataList -> TxMetadatum
    -- ^ New list
    -- > newList list
  , newInt :: Int -> TxMetadatum
    -- ^ New int
    -- > newInt int
  , newBytes :: Bytes -> TxMetadatum
    -- ^ New bytes
    -- > newBytes bytes
  , newText :: String -> TxMetadatum
    -- ^ New text
    -- > newText text
  , kind :: TxMetadatum -> Number
    -- ^ Kind
    -- > kind self
  , asMap :: TxMetadatum -> MetadataMap
    -- ^ As map
    -- > asMap self
  , asList :: TxMetadatum -> MetadataList
    -- ^ As list
    -- > asList self
  , asInt :: TxMetadatum -> Int
    -- ^ As int
    -- > asInt self
  , asBytes :: TxMetadatum -> Bytes
    -- ^ As bytes
    -- > asBytes self
  , asText :: TxMetadatum -> String
    -- ^ As text
    -- > asText self
  }

-- | Transaction metadatum class API
txMetadatum :: TxMetadatumClass
txMetadatum =
  { free: txMetadatum_free
  , toBytes: txMetadatum_toBytes
  , fromBytes: txMetadatum_fromBytes
  , toHex: txMetadatum_toHex
  , fromHex: txMetadatum_fromHex
  , newMap: txMetadatum_newMap
  , newList: txMetadatum_newList
  , newInt: txMetadatum_newInt
  , newBytes: txMetadatum_newBytes
  , newText: txMetadatum_newText
  , kind: txMetadatum_kind
  , asMap: txMetadatum_asMap
  , asList: txMetadatum_asList
  , asInt: txMetadatum_asInt
  , asBytes: txMetadatum_asBytes
  , asText: txMetadatum_asText
  }

instance HasFree TxMetadatum where
  free = txMetadatum.free

instance Show TxMetadatum where
  show = txMetadatum.toHex

instance IsHex TxMetadatum where
  toHex = txMetadatum.toHex
  fromHex = txMetadatum.fromHex

instance IsBytes TxMetadatum where
  toBytes = txMetadatum.toBytes
  fromBytes = txMetadatum.fromBytes

-------------------------------------------------------------------------------------
-- Transaction metadatum labels

foreign import txMetadatumLabels_free :: TxMetadatumLabels -> Effect Unit
foreign import txMetadatumLabels_toBytes :: TxMetadatumLabels -> Bytes
foreign import txMetadatumLabels_fromBytes :: Bytes -> TxMetadatumLabels
foreign import txMetadatumLabels_toHex :: TxMetadatumLabels -> String
foreign import txMetadatumLabels_fromHex :: String -> TxMetadatumLabels
foreign import txMetadatumLabels_new :: Effect TxMetadatumLabels
foreign import txMetadatumLabels_len :: TxMetadatumLabels -> Effect Int
foreign import txMetadatumLabels_get :: TxMetadatumLabels -> Int -> Effect BigNum
foreign import txMetadatumLabels_add :: TxMetadatumLabels -> BigNum -> Effect Unit

-- | Transaction metadatum labels class
type TxMetadatumLabelsClass =
  { free :: TxMetadatumLabels -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: TxMetadatumLabels -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> TxMetadatumLabels
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: TxMetadatumLabels -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> TxMetadatumLabels
    -- ^ From hex
    -- > fromHex hexStr
  , new :: Effect TxMetadatumLabels
    -- ^ New
    -- > new
  , len :: TxMetadatumLabels -> Effect Int
    -- ^ Len
    -- > len self
  , get :: TxMetadatumLabels -> Int -> Effect BigNum
    -- ^ Get
    -- > get self index
  , add :: TxMetadatumLabels -> BigNum -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Transaction metadatum labels class API
txMetadatumLabels :: TxMetadatumLabelsClass
txMetadatumLabels =
  { free: txMetadatumLabels_free
  , toBytes: txMetadatumLabels_toBytes
  , fromBytes: txMetadatumLabels_fromBytes
  , toHex: txMetadatumLabels_toHex
  , fromHex: txMetadatumLabels_fromHex
  , new: txMetadatumLabels_new
  , len: txMetadatumLabels_len
  , get: txMetadatumLabels_get
  , add: txMetadatumLabels_add
  }

instance HasFree TxMetadatumLabels where
  free = txMetadatumLabels.free

instance Show TxMetadatumLabels where
  show = txMetadatumLabels.toHex

instance MutableList TxMetadatumLabels BigNum where
  addItem = txMetadatumLabels.add
  getItem = txMetadatumLabels.get
  emptyList = txMetadatumLabels.new

instance MutableLen TxMetadatumLabels where
  getLen = txMetadatumLabels.len


instance IsHex TxMetadatumLabels where
  toHex = txMetadatumLabels.toHex
  fromHex = txMetadatumLabels.fromHex

instance IsBytes TxMetadatumLabels where
  toBytes = txMetadatumLabels.toBytes
  fromBytes = txMetadatumLabels.fromBytes

-------------------------------------------------------------------------------------
-- Transaction output

foreign import txOut_free :: TxOut -> Effect Unit
foreign import txOut_toBytes :: TxOut -> Bytes
foreign import txOut_fromBytes :: Bytes -> TxOut
foreign import txOut_toHex :: TxOut -> String
foreign import txOut_fromHex :: String -> TxOut
foreign import txOut_toJson :: TxOut -> String
foreign import txOut_toJsValue :: TxOut -> TxOutJson
foreign import txOut_fromJson :: String -> TxOut
foreign import txOut_address :: TxOut -> Address
foreign import txOut_amount :: TxOut -> Value
foreign import txOut_dataHash :: TxOut -> Nullable DataHash
foreign import txOut_plutusData :: TxOut -> Nullable PlutusData
foreign import txOut_scriptRef :: TxOut -> Nullable ScriptRef
foreign import txOut_setScriptRef :: TxOut -> ScriptRef -> Effect Unit
foreign import txOut_setPlutusData :: TxOut -> PlutusData -> Effect Unit
foreign import txOut_setDataHash :: TxOut -> DataHash -> Effect Unit
foreign import txOut_hasPlutusData :: TxOut -> Boolean
foreign import txOut_hasDataHash :: TxOut -> Boolean
foreign import txOut_hasScriptRef :: TxOut -> Boolean
foreign import txOut_new :: Address -> Value -> TxOut

-- | Transaction output class
type TxOutClass =
  { free :: TxOut -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: TxOut -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> TxOut
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: TxOut -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> TxOut
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: TxOut -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: TxOut -> TxOutJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> TxOut
    -- ^ From json
    -- > fromJson json
  , address :: TxOut -> Address
    -- ^ Address
    -- > address self
  , amount :: TxOut -> Value
    -- ^ Amount
    -- > amount self
  , dataHash :: TxOut -> Maybe DataHash
    -- ^ Data hash
    -- > dataHash self
  , plutusData :: TxOut -> Maybe PlutusData
    -- ^ Plutus data
    -- > plutusData self
  , scriptRef :: TxOut -> Maybe ScriptRef
    -- ^ Script ref
    -- > scriptRef self
  , setScriptRef :: TxOut -> ScriptRef -> Effect Unit
    -- ^ Set script ref
    -- > setScriptRef self scriptRef
  , setPlutusData :: TxOut -> PlutusData -> Effect Unit
    -- ^ Set plutus data
    -- > setPlutusData self data
  , setDataHash :: TxOut -> DataHash -> Effect Unit
    -- ^ Set data hash
    -- > setDataHash self dataHash
  , hasPlutusData :: TxOut -> Boolean
    -- ^ Has plutus data
    -- > hasPlutusData self
  , hasDataHash :: TxOut -> Boolean
    -- ^ Has data hash
    -- > hasDataHash self
  , hasScriptRef :: TxOut -> Boolean
    -- ^ Has script ref
    -- > hasScriptRef self
  , new :: Address -> Value -> TxOut
    -- ^ New
    -- > new address amount
  }

-- | Transaction output class API
txOut :: TxOutClass
txOut =
  { free: txOut_free
  , toBytes: txOut_toBytes
  , fromBytes: txOut_fromBytes
  , toHex: txOut_toHex
  , fromHex: txOut_fromHex
  , toJson: txOut_toJson
  , toJsValue: txOut_toJsValue
  , fromJson: txOut_fromJson
  , address: txOut_address
  , amount: txOut_amount
  , dataHash: \a1 -> Nullable.toMaybe $ txOut_dataHash a1
  , plutusData: \a1 -> Nullable.toMaybe $ txOut_plutusData a1
  , scriptRef: \a1 -> Nullable.toMaybe $ txOut_scriptRef a1
  , setScriptRef: txOut_setScriptRef
  , setPlutusData: txOut_setPlutusData
  , setDataHash: txOut_setDataHash
  , hasPlutusData: txOut_hasPlutusData
  , hasDataHash: txOut_hasDataHash
  , hasScriptRef: txOut_hasScriptRef
  , new: txOut_new
  }

instance HasFree TxOut where
  free = txOut.free

instance Show TxOut where
  show = txOut.toHex

instance ToJsValue TxOut where
  toJsValue = txOut.toJsValue

instance IsHex TxOut where
  toHex = txOut.toHex
  fromHex = txOut.fromHex

instance IsBytes TxOut where
  toBytes = txOut.toBytes
  fromBytes = txOut.fromBytes

instance IsJson TxOut where
  toJson = txOut.toJson
  fromJson = txOut.fromJson

-------------------------------------------------------------------------------------
-- Transaction output amount builder

foreign import txOutAmountBuilder_free :: TxOutAmountBuilder -> Effect Unit
foreign import txOutAmountBuilder_withValue :: TxOutAmountBuilder -> Value -> TxOutAmountBuilder
foreign import txOutAmountBuilder_withCoin :: TxOutAmountBuilder -> BigNum -> TxOutAmountBuilder
foreign import txOutAmountBuilder_withCoinAndAsset :: TxOutAmountBuilder -> BigNum -> MultiAsset -> TxOutAmountBuilder
foreign import txOutAmountBuilder_withAssetAndMinRequiredCoin :: TxOutAmountBuilder -> MultiAsset -> BigNum -> TxOutAmountBuilder
foreign import txOutAmountBuilder_withAssetAndMinRequiredCoinByUtxoCost :: TxOutAmountBuilder -> MultiAsset -> DataCost -> TxOutAmountBuilder
foreign import txOutAmountBuilder_build :: TxOutAmountBuilder -> TxOut

-- | Transaction output amount builder class
type TxOutAmountBuilderClass =
  { free :: TxOutAmountBuilder -> Effect Unit
    -- ^ Free
    -- > free self
  , withValue :: TxOutAmountBuilder -> Value -> TxOutAmountBuilder
    -- ^ With value
    -- > withValue self amount
  , withCoin :: TxOutAmountBuilder -> BigNum -> TxOutAmountBuilder
    -- ^ With coin
    -- > withCoin self coin
  , withCoinAndAsset :: TxOutAmountBuilder -> BigNum -> MultiAsset -> TxOutAmountBuilder
    -- ^ With coin and asset
    -- > withCoinAndAsset self coin multiasset
  , withAssetAndMinRequiredCoin :: TxOutAmountBuilder -> MultiAsset -> BigNum -> TxOutAmountBuilder
    -- ^ With asset and min required coin
    -- > withAssetAndMinRequiredCoin self multiasset coinsPerUtxoWord
  , withAssetAndMinRequiredCoinByUtxoCost :: TxOutAmountBuilder -> MultiAsset -> DataCost -> TxOutAmountBuilder
    -- ^ With asset and min required coin by utxo cost
    -- > withAssetAndMinRequiredCoinByUtxoCost self multiasset dataCost
  , build :: TxOutAmountBuilder -> TxOut
    -- ^ Build
    -- > build self
  }

-- | Transaction output amount builder class API
txOutAmountBuilder :: TxOutAmountBuilderClass
txOutAmountBuilder =
  { free: txOutAmountBuilder_free
  , withValue: txOutAmountBuilder_withValue
  , withCoin: txOutAmountBuilder_withCoin
  , withCoinAndAsset: txOutAmountBuilder_withCoinAndAsset
  , withAssetAndMinRequiredCoin: txOutAmountBuilder_withAssetAndMinRequiredCoin
  , withAssetAndMinRequiredCoinByUtxoCost: txOutAmountBuilder_withAssetAndMinRequiredCoinByUtxoCost
  , build: txOutAmountBuilder_build
  }

instance HasFree TxOutAmountBuilder where
  free = txOutAmountBuilder.free

-------------------------------------------------------------------------------------
-- Transaction output builder

foreign import txOutBuilder_free :: TxOutBuilder -> Effect Unit
foreign import txOutBuilder_new :: TxOutBuilder
foreign import txOutBuilder_withAddress :: TxOutBuilder -> Address -> TxOutBuilder
foreign import txOutBuilder_withDataHash :: TxOutBuilder -> DataHash -> TxOutBuilder
foreign import txOutBuilder_withPlutusData :: TxOutBuilder -> PlutusData -> TxOutBuilder
foreign import txOutBuilder_withScriptRef :: TxOutBuilder -> ScriptRef -> TxOutBuilder
foreign import txOutBuilder_next :: TxOutBuilder -> TxOutAmountBuilder

-- | Transaction output builder class
type TxOutBuilderClass =
  { free :: TxOutBuilder -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: TxOutBuilder
    -- ^ New
    -- > new
  , withAddress :: TxOutBuilder -> Address -> TxOutBuilder
    -- ^ With address
    -- > withAddress self address
  , withDataHash :: TxOutBuilder -> DataHash -> TxOutBuilder
    -- ^ With data hash
    -- > withDataHash self dataHash
  , withPlutusData :: TxOutBuilder -> PlutusData -> TxOutBuilder
    -- ^ With plutus data
    -- > withPlutusData self data
  , withScriptRef :: TxOutBuilder -> ScriptRef -> TxOutBuilder
    -- ^ With script ref
    -- > withScriptRef self scriptRef
  , next :: TxOutBuilder -> TxOutAmountBuilder
    -- ^ Next
    -- > next self
  }

-- | Transaction output builder class API
txOutBuilder :: TxOutBuilderClass
txOutBuilder =
  { free: txOutBuilder_free
  , new: txOutBuilder_new
  , withAddress: txOutBuilder_withAddress
  , withDataHash: txOutBuilder_withDataHash
  , withPlutusData: txOutBuilder_withPlutusData
  , withScriptRef: txOutBuilder_withScriptRef
  , next: txOutBuilder_next
  }

instance HasFree TxOutBuilder where
  free = txOutBuilder.free

-------------------------------------------------------------------------------------
-- Transaction outputs

foreign import txOuts_free :: TxOuts -> Effect Unit
foreign import txOuts_toBytes :: TxOuts -> Bytes
foreign import txOuts_fromBytes :: Bytes -> TxOuts
foreign import txOuts_toHex :: TxOuts -> String
foreign import txOuts_fromHex :: String -> TxOuts
foreign import txOuts_toJson :: TxOuts -> String
foreign import txOuts_toJsValue :: TxOuts -> TxOutsJson
foreign import txOuts_fromJson :: String -> TxOuts
foreign import txOuts_new :: Effect TxOuts
foreign import txOuts_len :: TxOuts -> Effect Int
foreign import txOuts_get :: TxOuts -> Int -> Effect TxOut
foreign import txOuts_add :: TxOuts -> TxOut -> Effect Unit

-- | Transaction outputs class
type TxOutsClass =
  { free :: TxOuts -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: TxOuts -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> TxOuts
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: TxOuts -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> TxOuts
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: TxOuts -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: TxOuts -> TxOutsJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> TxOuts
    -- ^ From json
    -- > fromJson json
  , new :: Effect TxOuts
    -- ^ New
    -- > new
  , len :: TxOuts -> Effect Int
    -- ^ Len
    -- > len self
  , get :: TxOuts -> Int -> Effect TxOut
    -- ^ Get
    -- > get self index
  , add :: TxOuts -> TxOut -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Transaction outputs class API
txOuts :: TxOutsClass
txOuts =
  { free: txOuts_free
  , toBytes: txOuts_toBytes
  , fromBytes: txOuts_fromBytes
  , toHex: txOuts_toHex
  , fromHex: txOuts_fromHex
  , toJson: txOuts_toJson
  , toJsValue: txOuts_toJsValue
  , fromJson: txOuts_fromJson
  , new: txOuts_new
  , len: txOuts_len
  , get: txOuts_get
  , add: txOuts_add
  }

instance HasFree TxOuts where
  free = txOuts.free

instance Show TxOuts where
  show = txOuts.toHex

instance MutableList TxOuts TxOut where
  addItem = txOuts.add
  getItem = txOuts.get
  emptyList = txOuts.new

instance MutableLen TxOuts where
  getLen = txOuts.len


instance ToJsValue TxOuts where
  toJsValue = txOuts.toJsValue

instance IsHex TxOuts where
  toHex = txOuts.toHex
  fromHex = txOuts.fromHex

instance IsBytes TxOuts where
  toBytes = txOuts.toBytes
  fromBytes = txOuts.fromBytes

instance IsJson TxOuts where
  toJson = txOuts.toJson
  fromJson = txOuts.fromJson

-------------------------------------------------------------------------------------
-- Transaction unspent output

foreign import txUnspentOut_free :: TxUnspentOut -> Effect Unit
foreign import txUnspentOut_toBytes :: TxUnspentOut -> Bytes
foreign import txUnspentOut_fromBytes :: Bytes -> TxUnspentOut
foreign import txUnspentOut_toHex :: TxUnspentOut -> String
foreign import txUnspentOut_fromHex :: String -> TxUnspentOut
foreign import txUnspentOut_toJson :: TxUnspentOut -> String
foreign import txUnspentOut_toJsValue :: TxUnspentOut -> TxUnspentOutJson
foreign import txUnspentOut_fromJson :: String -> TxUnspentOut
foreign import txUnspentOut_new :: TxIn -> TxOut -> TxUnspentOut
foreign import txUnspentOut_in :: TxUnspentOut -> TxIn
foreign import txUnspentOut_out :: TxUnspentOut -> TxOut

-- | Transaction unspent output class
type TxUnspentOutClass =
  { free :: TxUnspentOut -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: TxUnspentOut -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> TxUnspentOut
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: TxUnspentOut -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> TxUnspentOut
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: TxUnspentOut -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: TxUnspentOut -> TxUnspentOutJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> TxUnspentOut
    -- ^ From json
    -- > fromJson json
  , new :: TxIn -> TxOut -> TxUnspentOut
    -- ^ New
    -- > new in out
  , in :: TxUnspentOut -> TxIn
    -- ^ Input
    -- > in self
  , out :: TxUnspentOut -> TxOut
    -- ^ Output
    -- > out self
  }

-- | Transaction unspent output class API
txUnspentOut :: TxUnspentOutClass
txUnspentOut =
  { free: txUnspentOut_free
  , toBytes: txUnspentOut_toBytes
  , fromBytes: txUnspentOut_fromBytes
  , toHex: txUnspentOut_toHex
  , fromHex: txUnspentOut_fromHex
  , toJson: txUnspentOut_toJson
  , toJsValue: txUnspentOut_toJsValue
  , fromJson: txUnspentOut_fromJson
  , new: txUnspentOut_new
  , in: txUnspentOut_in
  , out: txUnspentOut_out
  }

instance HasFree TxUnspentOut where
  free = txUnspentOut.free

instance Show TxUnspentOut where
  show = txUnspentOut.toHex

instance ToJsValue TxUnspentOut where
  toJsValue = txUnspentOut.toJsValue

instance IsHex TxUnspentOut where
  toHex = txUnspentOut.toHex
  fromHex = txUnspentOut.fromHex

instance IsBytes TxUnspentOut where
  toBytes = txUnspentOut.toBytes
  fromBytes = txUnspentOut.fromBytes

instance IsJson TxUnspentOut where
  toJson = txUnspentOut.toJson
  fromJson = txUnspentOut.fromJson

-------------------------------------------------------------------------------------
-- Transaction unspent outputs

foreign import txUnspentOuts_free :: TxUnspentOuts -> Effect Unit
foreign import txUnspentOuts_toJson :: TxUnspentOuts -> String
foreign import txUnspentOuts_toJsValue :: TxUnspentOuts -> TxUnspentOutsJson
foreign import txUnspentOuts_fromJson :: String -> TxUnspentOuts
foreign import txUnspentOuts_new :: Effect TxUnspentOuts
foreign import txUnspentOuts_len :: TxUnspentOuts -> Effect Int
foreign import txUnspentOuts_get :: TxUnspentOuts -> Int -> Effect TxUnspentOut
foreign import txUnspentOuts_add :: TxUnspentOuts -> TxUnspentOut -> Effect Unit

-- | Transaction unspent outputs class
type TxUnspentOutsClass =
  { free :: TxUnspentOuts -> Effect Unit
    -- ^ Free
    -- > free self
  , toJson :: TxUnspentOuts -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: TxUnspentOuts -> TxUnspentOutsJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> TxUnspentOuts
    -- ^ From json
    -- > fromJson json
  , new :: Effect TxUnspentOuts
    -- ^ New
    -- > new
  , len :: TxUnspentOuts -> Effect Int
    -- ^ Len
    -- > len self
  , get :: TxUnspentOuts -> Int -> Effect TxUnspentOut
    -- ^ Get
    -- > get self index
  , add :: TxUnspentOuts -> TxUnspentOut -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Transaction unspent outputs class API
txUnspentOuts :: TxUnspentOutsClass
txUnspentOuts =
  { free: txUnspentOuts_free
  , toJson: txUnspentOuts_toJson
  , toJsValue: txUnspentOuts_toJsValue
  , fromJson: txUnspentOuts_fromJson
  , new: txUnspentOuts_new
  , len: txUnspentOuts_len
  , get: txUnspentOuts_get
  , add: txUnspentOuts_add
  }

instance HasFree TxUnspentOuts where
  free = txUnspentOuts.free

instance MutableList TxUnspentOuts TxUnspentOut where
  addItem = txUnspentOuts.add
  getItem = txUnspentOuts.get
  emptyList = txUnspentOuts.new

instance MutableLen TxUnspentOuts where
  getLen = txUnspentOuts.len


instance ToJsValue TxUnspentOuts where
  toJsValue = txUnspentOuts.toJsValue

instance IsJson TxUnspentOuts where
  toJson = txUnspentOuts.toJson
  fromJson = txUnspentOuts.fromJson

-------------------------------------------------------------------------------------
-- Transaction witness set

foreign import txWitnessSet_free :: TxWitnessSet -> Effect Unit
foreign import txWitnessSet_toBytes :: TxWitnessSet -> Bytes
foreign import txWitnessSet_fromBytes :: Bytes -> TxWitnessSet
foreign import txWitnessSet_toHex :: TxWitnessSet -> String
foreign import txWitnessSet_fromHex :: String -> TxWitnessSet
foreign import txWitnessSet_toJson :: TxWitnessSet -> String
foreign import txWitnessSet_toJsValue :: TxWitnessSet -> TxWitnessSetJson
foreign import txWitnessSet_fromJson :: String -> TxWitnessSet
foreign import txWitnessSet_setVkeys :: TxWitnessSet -> Vkeywitnesses -> Effect Unit
foreign import txWitnessSet_vkeys :: TxWitnessSet -> Effect (Nullable Vkeywitnesses)
foreign import txWitnessSet_setNativeScripts :: TxWitnessSet -> NativeScripts -> Effect Unit
foreign import txWitnessSet_nativeScripts :: TxWitnessSet -> Effect (Nullable NativeScripts)
foreign import txWitnessSet_setBootstraps :: TxWitnessSet -> BootstrapWitnesses -> Effect Unit
foreign import txWitnessSet_bootstraps :: TxWitnessSet -> Effect (Nullable BootstrapWitnesses)
foreign import txWitnessSet_setPlutusScripts :: TxWitnessSet -> PlutusScripts -> Effect Unit
foreign import txWitnessSet_plutusScripts :: TxWitnessSet -> Effect (Nullable PlutusScripts)
foreign import txWitnessSet_setPlutusData :: TxWitnessSet -> PlutusList -> Effect Unit
foreign import txWitnessSet_plutusData :: TxWitnessSet -> Effect (Nullable PlutusList)
foreign import txWitnessSet_setRedeemers :: TxWitnessSet -> Redeemers -> Effect Unit
foreign import txWitnessSet_redeemers :: TxWitnessSet -> Effect (Nullable Redeemers)
foreign import txWitnessSet_new :: Effect TxWitnessSet

-- | Transaction witness set class
type TxWitnessSetClass =
  { free :: TxWitnessSet -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: TxWitnessSet -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> TxWitnessSet
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: TxWitnessSet -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> TxWitnessSet
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: TxWitnessSet -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: TxWitnessSet -> TxWitnessSetJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> TxWitnessSet
    -- ^ From json
    -- > fromJson json
  , setVkeys :: TxWitnessSet -> Vkeywitnesses -> Effect Unit
    -- ^ Set vkeys
    -- > setVkeys self vkeys
  , vkeys :: TxWitnessSet -> Effect (Maybe Vkeywitnesses)
    -- ^ Vkeys
    -- > vkeys self
  , setNativeScripts :: TxWitnessSet -> NativeScripts -> Effect Unit
    -- ^ Set native scripts
    -- > setNativeScripts self nativeScripts
  , nativeScripts :: TxWitnessSet -> Effect (Maybe NativeScripts)
    -- ^ Native scripts
    -- > nativeScripts self
  , setBootstraps :: TxWitnessSet -> BootstrapWitnesses -> Effect Unit
    -- ^ Set bootstraps
    -- > setBootstraps self bootstraps
  , bootstraps :: TxWitnessSet -> Effect (Maybe BootstrapWitnesses)
    -- ^ Bootstraps
    -- > bootstraps self
  , setPlutusScripts :: TxWitnessSet -> PlutusScripts -> Effect Unit
    -- ^ Set plutus scripts
    -- > setPlutusScripts self plutusScripts
  , plutusScripts :: TxWitnessSet -> Effect (Maybe PlutusScripts)
    -- ^ Plutus scripts
    -- > plutusScripts self
  , setPlutusData :: TxWitnessSet -> PlutusList -> Effect Unit
    -- ^ Set plutus data
    -- > setPlutusData self plutusData
  , plutusData :: TxWitnessSet -> Effect (Maybe PlutusList)
    -- ^ Plutus data
    -- > plutusData self
  , setRedeemers :: TxWitnessSet -> Redeemers -> Effect Unit
    -- ^ Set redeemers
    -- > setRedeemers self redeemers
  , redeemers :: TxWitnessSet -> Effect (Maybe Redeemers)
    -- ^ Redeemers
    -- > redeemers self
  , new :: Effect TxWitnessSet
    -- ^ New
    -- > new
  }

-- | Transaction witness set class API
txWitnessSet :: TxWitnessSetClass
txWitnessSet =
  { free: txWitnessSet_free
  , toBytes: txWitnessSet_toBytes
  , fromBytes: txWitnessSet_fromBytes
  , toHex: txWitnessSet_toHex
  , fromHex: txWitnessSet_fromHex
  , toJson: txWitnessSet_toJson
  , toJsValue: txWitnessSet_toJsValue
  , fromJson: txWitnessSet_fromJson
  , setVkeys: txWitnessSet_setVkeys
  , vkeys: \a1 -> Nullable.toMaybe <$> txWitnessSet_vkeys a1
  , setNativeScripts: txWitnessSet_setNativeScripts
  , nativeScripts: \a1 -> Nullable.toMaybe <$> txWitnessSet_nativeScripts a1
  , setBootstraps: txWitnessSet_setBootstraps
  , bootstraps: \a1 -> Nullable.toMaybe <$> txWitnessSet_bootstraps a1
  , setPlutusScripts: txWitnessSet_setPlutusScripts
  , plutusScripts: \a1 -> Nullable.toMaybe <$> txWitnessSet_plutusScripts a1
  , setPlutusData: txWitnessSet_setPlutusData
  , plutusData: \a1 -> Nullable.toMaybe <$> txWitnessSet_plutusData a1
  , setRedeemers: txWitnessSet_setRedeemers
  , redeemers: \a1 -> Nullable.toMaybe <$> txWitnessSet_redeemers a1
  , new: txWitnessSet_new
  }

instance HasFree TxWitnessSet where
  free = txWitnessSet.free

instance Show TxWitnessSet where
  show = txWitnessSet.toHex

instance ToJsValue TxWitnessSet where
  toJsValue = txWitnessSet.toJsValue

instance IsHex TxWitnessSet where
  toHex = txWitnessSet.toHex
  fromHex = txWitnessSet.fromHex

instance IsBytes TxWitnessSet where
  toBytes = txWitnessSet.toBytes
  fromBytes = txWitnessSet.fromBytes

instance IsJson TxWitnessSet where
  toJson = txWitnessSet.toJson
  fromJson = txWitnessSet.fromJson

-------------------------------------------------------------------------------------
-- Transaction witness sets

foreign import txWitnessSets_free :: TxWitnessSets -> Effect Unit
foreign import txWitnessSets_toBytes :: TxWitnessSets -> Bytes
foreign import txWitnessSets_fromBytes :: Bytes -> TxWitnessSets
foreign import txWitnessSets_toHex :: TxWitnessSets -> String
foreign import txWitnessSets_fromHex :: String -> TxWitnessSets
foreign import txWitnessSets_toJson :: TxWitnessSets -> String
foreign import txWitnessSets_toJsValue :: TxWitnessSets -> TxWitnessSetsJson
foreign import txWitnessSets_fromJson :: String -> TxWitnessSets
foreign import txWitnessSets_new :: Effect TxWitnessSets
foreign import txWitnessSets_len :: TxWitnessSets -> Effect Number
foreign import txWitnessSets_get :: TxWitnessSets -> Number -> Effect TxWitnessSet
foreign import txWitnessSets_add :: TxWitnessSets -> TxWitnessSet -> Effect Unit

-- | Transaction witness sets class
type TxWitnessSetsClass =
  { free :: TxWitnessSets -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: TxWitnessSets -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> TxWitnessSets
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: TxWitnessSets -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> TxWitnessSets
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: TxWitnessSets -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: TxWitnessSets -> TxWitnessSetsJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> TxWitnessSets
    -- ^ From json
    -- > fromJson json
  , new :: Effect TxWitnessSets
    -- ^ New
    -- > new
  , len :: TxWitnessSets -> Effect Number
    -- ^ Len
    -- > len self
  , get :: TxWitnessSets -> Number -> Effect TxWitnessSet
    -- ^ Get
    -- > get self index
  , add :: TxWitnessSets -> TxWitnessSet -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Transaction witness sets class API
txWitnessSets :: TxWitnessSetsClass
txWitnessSets =
  { free: txWitnessSets_free
  , toBytes: txWitnessSets_toBytes
  , fromBytes: txWitnessSets_fromBytes
  , toHex: txWitnessSets_toHex
  , fromHex: txWitnessSets_fromHex
  , toJson: txWitnessSets_toJson
  , toJsValue: txWitnessSets_toJsValue
  , fromJson: txWitnessSets_fromJson
  , new: txWitnessSets_new
  , len: txWitnessSets_len
  , get: txWitnessSets_get
  , add: txWitnessSets_add
  }

instance HasFree TxWitnessSets where
  free = txWitnessSets.free

instance Show TxWitnessSets where
  show = txWitnessSets.toHex

instance ToJsValue TxWitnessSets where
  toJsValue = txWitnessSets.toJsValue

instance IsHex TxWitnessSets where
  toHex = txWitnessSets.toHex
  fromHex = txWitnessSets.fromHex

instance IsBytes TxWitnessSets where
  toBytes = txWitnessSets.toBytes
  fromBytes = txWitnessSets.fromBytes

instance IsJson TxWitnessSets where
  toJson = txWitnessSets.toJson
  fromJson = txWitnessSets.fromJson

-------------------------------------------------------------------------------------
-- Tx builder constants

foreign import txBuilderConstants_free :: TxBuilderConstants -> Effect Unit
foreign import txBuilderConstants_plutusDefaultCostModels :: Costmdls
foreign import txBuilderConstants_plutusAlonzoCostModels :: Costmdls
foreign import txBuilderConstants_plutusVasilCostModels :: Costmdls

-- | Tx builder constants class
type TxBuilderConstantsClass =
  { free :: TxBuilderConstants -> Effect Unit
    -- ^ Free
    -- > free self
  , plutusDefaultCostModels :: Costmdls
    -- ^ Plutus default cost models
    -- > plutusDefaultCostModels
  , plutusAlonzoCostModels :: Costmdls
    -- ^ Plutus alonzo cost models
    -- > plutusAlonzoCostModels
  , plutusVasilCostModels :: Costmdls
    -- ^ Plutus vasil cost models
    -- > plutusVasilCostModels
  }

-- | Tx builder constants class API
txBuilderConstants :: TxBuilderConstantsClass
txBuilderConstants =
  { free: txBuilderConstants_free
  , plutusDefaultCostModels: txBuilderConstants_plutusDefaultCostModels
  , plutusAlonzoCostModels: txBuilderConstants_plutusAlonzoCostModels
  , plutusVasilCostModels: txBuilderConstants_plutusVasilCostModels
  }

instance HasFree TxBuilderConstants where
  free = txBuilderConstants.free

-------------------------------------------------------------------------------------
-- Tx inputs builder

foreign import txInsBuilder_free :: TxInsBuilder -> Effect Unit
foreign import txInsBuilder_new :: Effect TxInsBuilder
foreign import txInsBuilder_addKeyIn :: TxInsBuilder -> Ed25519KeyHash -> TxIn -> Value -> Effect Unit
foreign import txInsBuilder_addScriptIn :: TxInsBuilder -> ScriptHash -> TxIn -> Value -> Effect Unit
foreign import txInsBuilder_addNativeScriptIn :: TxInsBuilder -> NativeScript -> TxIn -> Value -> Effect Unit
foreign import txInsBuilder_addPlutusScriptIn :: TxInsBuilder -> PlutusWitness -> TxIn -> Value -> Effect Unit
foreign import txInsBuilder_addBootstrapIn :: TxInsBuilder -> ByronAddress -> TxIn -> Value -> Effect Unit
foreign import txInsBuilder_addIn :: TxInsBuilder -> Address -> TxIn -> Value -> Effect Unit
foreign import txInsBuilder_countMissingInScripts :: TxInsBuilder -> Effect Number
foreign import txInsBuilder_addRequiredNativeInScripts :: TxInsBuilder -> NativeScripts -> Effect Number
foreign import txInsBuilder_addRequiredPlutusInScripts :: TxInsBuilder -> PlutusWitnesses -> Effect Number
foreign import txInsBuilder_getRefIns :: TxInsBuilder -> Effect TxIns
foreign import txInsBuilder_getNativeInScripts :: TxInsBuilder -> Effect (Nullable NativeScripts)
foreign import txInsBuilder_getPlutusInScripts :: TxInsBuilder -> Effect (Nullable PlutusWitnesses)
foreign import txInsBuilder_len :: TxInsBuilder -> Effect Number
foreign import txInsBuilder_addRequiredSigner :: TxInsBuilder -> Ed25519KeyHash -> Effect Unit
foreign import txInsBuilder_addRequiredSigners :: TxInsBuilder -> Ed25519KeyHashes -> Effect Unit
foreign import txInsBuilder_totalValue :: TxInsBuilder -> Effect Value
foreign import txInsBuilder_ins :: TxInsBuilder -> Effect TxIns
foreign import txInsBuilder_insOption :: TxInsBuilder -> Effect (Nullable TxIns)

-- | Tx inputs builder class
type TxInsBuilderClass =
  { free :: TxInsBuilder -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: Effect TxInsBuilder
    -- ^ New
    -- > new
  , addKeyIn :: TxInsBuilder -> Ed25519KeyHash -> TxIn -> Value -> Effect Unit
    -- ^ Add key input
    -- > addKeyIn self hash in amount
  , addScriptIn :: TxInsBuilder -> ScriptHash -> TxIn -> Value -> Effect Unit
    -- ^ Add script input
    -- > addScriptIn self hash in amount
  , addNativeScriptIn :: TxInsBuilder -> NativeScript -> TxIn -> Value -> Effect Unit
    -- ^ Add native script input
    -- > addNativeScriptIn self script in amount
  , addPlutusScriptIn :: TxInsBuilder -> PlutusWitness -> TxIn -> Value -> Effect Unit
    -- ^ Add plutus script input
    -- > addPlutusScriptIn self witness in amount
  , addBootstrapIn :: TxInsBuilder -> ByronAddress -> TxIn -> Value -> Effect Unit
    -- ^ Add bootstrap input
    -- > addBootstrapIn self hash in amount
  , addIn :: TxInsBuilder -> Address -> TxIn -> Value -> Effect Unit
    -- ^ Add input
    -- > addIn self address in amount
  , countMissingInScripts :: TxInsBuilder -> Effect Number
    -- ^ Count missing input scripts
    -- > countMissingInScripts self
  , addRequiredNativeInScripts :: TxInsBuilder -> NativeScripts -> Effect Number
    -- ^ Add required native input scripts
    -- > addRequiredNativeInScripts self scripts
  , addRequiredPlutusInScripts :: TxInsBuilder -> PlutusWitnesses -> Effect Number
    -- ^ Add required plutus input scripts
    -- > addRequiredPlutusInScripts self scripts
  , getRefIns :: TxInsBuilder -> Effect TxIns
    -- ^ Get ref inputs
    -- > getRefIns self
  , getNativeInScripts :: TxInsBuilder -> Effect (Maybe NativeScripts)
    -- ^ Get native input scripts
    -- > getNativeInScripts self
  , getPlutusInScripts :: TxInsBuilder -> Effect (Maybe PlutusWitnesses)
    -- ^ Get plutus input scripts
    -- > getPlutusInScripts self
  , len :: TxInsBuilder -> Effect Number
    -- ^ Len
    -- > len self
  , addRequiredSigner :: TxInsBuilder -> Ed25519KeyHash -> Effect Unit
    -- ^ Add required signer
    -- > addRequiredSigner self key
  , addRequiredSigners :: TxInsBuilder -> Ed25519KeyHashes -> Effect Unit
    -- ^ Add required signers
    -- > addRequiredSigners self keys
  , totalValue :: TxInsBuilder -> Effect Value
    -- ^ Total value
    -- > totalValue self
  , ins :: TxInsBuilder -> Effect TxIns
    -- ^ Inputs
    -- > ins self
  , insOption :: TxInsBuilder -> Effect (Maybe TxIns)
    -- ^ Inputs option
    -- > insOption self
  }

-- | Tx inputs builder class API
txInsBuilder :: TxInsBuilderClass
txInsBuilder =
  { free: txInsBuilder_free
  , new: txInsBuilder_new
  , addKeyIn: txInsBuilder_addKeyIn
  , addScriptIn: txInsBuilder_addScriptIn
  , addNativeScriptIn: txInsBuilder_addNativeScriptIn
  , addPlutusScriptIn: txInsBuilder_addPlutusScriptIn
  , addBootstrapIn: txInsBuilder_addBootstrapIn
  , addIn: txInsBuilder_addIn
  , countMissingInScripts: txInsBuilder_countMissingInScripts
  , addRequiredNativeInScripts: txInsBuilder_addRequiredNativeInScripts
  , addRequiredPlutusInScripts: txInsBuilder_addRequiredPlutusInScripts
  , getRefIns: txInsBuilder_getRefIns
  , getNativeInScripts: \a1 -> Nullable.toMaybe <$> txInsBuilder_getNativeInScripts a1
  , getPlutusInScripts: \a1 -> Nullable.toMaybe <$> txInsBuilder_getPlutusInScripts a1
  , len: txInsBuilder_len
  , addRequiredSigner: txInsBuilder_addRequiredSigner
  , addRequiredSigners: txInsBuilder_addRequiredSigners
  , totalValue: txInsBuilder_totalValue
  , ins: txInsBuilder_ins
  , insOption: \a1 -> Nullable.toMaybe <$> txInsBuilder_insOption a1
  }

instance HasFree TxInsBuilder where
  free = txInsBuilder.free

-------------------------------------------------------------------------------------
-- URL

foreign import url_free :: URL -> Effect Unit
foreign import url_toBytes :: URL -> Bytes
foreign import url_fromBytes :: Bytes -> URL
foreign import url_toHex :: URL -> String
foreign import url_fromHex :: String -> URL
foreign import url_toJson :: URL -> String
foreign import url_toJsValue :: URL -> URLJson
foreign import url_fromJson :: String -> URL
foreign import url_new :: String -> URL
foreign import url_url :: URL -> String

-- | URL class
type URLClass =
  { free :: URL -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: URL -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> URL
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: URL -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> URL
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: URL -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: URL -> URLJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> URL
    -- ^ From json
    -- > fromJson json
  , new :: String -> URL
    -- ^ New
    -- > new url
  , url :: URL -> String
    -- ^ Url
    -- > url self
  }

-- | URL class API
url :: URLClass
url =
  { free: url_free
  , toBytes: url_toBytes
  , fromBytes: url_fromBytes
  , toHex: url_toHex
  , fromHex: url_fromHex
  , toJson: url_toJson
  , toJsValue: url_toJsValue
  , fromJson: url_fromJson
  , new: url_new
  , url: url_url
  }

instance HasFree URL where
  free = url.free

instance Show URL where
  show = url.toHex

instance ToJsValue URL where
  toJsValue = url.toJsValue

instance IsHex URL where
  toHex = url.toHex
  fromHex = url.fromHex

instance IsBytes URL where
  toBytes = url.toBytes
  fromBytes = url.fromBytes

instance IsJson URL where
  toJson = url.toJson
  fromJson = url.fromJson

-------------------------------------------------------------------------------------
-- Unit interval

foreign import unitInterval_free :: UnitInterval -> Effect Unit
foreign import unitInterval_toBytes :: UnitInterval -> Bytes
foreign import unitInterval_fromBytes :: Bytes -> UnitInterval
foreign import unitInterval_toHex :: UnitInterval -> String
foreign import unitInterval_fromHex :: String -> UnitInterval
foreign import unitInterval_toJson :: UnitInterval -> String
foreign import unitInterval_toJsValue :: UnitInterval -> UnitIntervalJson
foreign import unitInterval_fromJson :: String -> UnitInterval
foreign import unitInterval_numerator :: UnitInterval -> BigNum
foreign import unitInterval_denominator :: UnitInterval -> BigNum
foreign import unitInterval_new :: BigNum -> BigNum -> UnitInterval

-- | Unit interval class
type UnitIntervalClass =
  { free :: UnitInterval -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: UnitInterval -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> UnitInterval
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: UnitInterval -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> UnitInterval
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: UnitInterval -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: UnitInterval -> UnitIntervalJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> UnitInterval
    -- ^ From json
    -- > fromJson json
  , numerator :: UnitInterval -> BigNum
    -- ^ Numerator
    -- > numerator self
  , denominator :: UnitInterval -> BigNum
    -- ^ Denominator
    -- > denominator self
  , new :: BigNum -> BigNum -> UnitInterval
    -- ^ New
    -- > new numerator denominator
  }

-- | Unit interval class API
unitInterval :: UnitIntervalClass
unitInterval =
  { free: unitInterval_free
  , toBytes: unitInterval_toBytes
  , fromBytes: unitInterval_fromBytes
  , toHex: unitInterval_toHex
  , fromHex: unitInterval_fromHex
  , toJson: unitInterval_toJson
  , toJsValue: unitInterval_toJsValue
  , fromJson: unitInterval_fromJson
  , numerator: unitInterval_numerator
  , denominator: unitInterval_denominator
  , new: unitInterval_new
  }

instance HasFree UnitInterval where
  free = unitInterval.free

instance Show UnitInterval where
  show = unitInterval.toHex

instance ToJsValue UnitInterval where
  toJsValue = unitInterval.toJsValue

instance IsHex UnitInterval where
  toHex = unitInterval.toHex
  fromHex = unitInterval.fromHex

instance IsBytes UnitInterval where
  toBytes = unitInterval.toBytes
  fromBytes = unitInterval.fromBytes

instance IsJson UnitInterval where
  toJson = unitInterval.toJson
  fromJson = unitInterval.fromJson

-------------------------------------------------------------------------------------
-- Update

foreign import update_free :: Update -> Effect Unit
foreign import update_toBytes :: Update -> Bytes
foreign import update_fromBytes :: Bytes -> Update
foreign import update_toHex :: Update -> String
foreign import update_fromHex :: String -> Update
foreign import update_toJson :: Update -> String
foreign import update_toJsValue :: Update -> UpdateJson
foreign import update_fromJson :: String -> Update
foreign import update_proposedProtocolParameterUpdates :: Update -> ProposedProtocolParameterUpdates
foreign import update_epoch :: Update -> Number
foreign import update_new :: ProposedProtocolParameterUpdates -> Number -> Update

-- | Update class
type UpdateClass =
  { free :: Update -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Update -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Update
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Update -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Update
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Update -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Update -> UpdateJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Update
    -- ^ From json
    -- > fromJson json
  , proposedProtocolParameterUpdates :: Update -> ProposedProtocolParameterUpdates
    -- ^ Proposed protocol parameter updates
    -- > proposedProtocolParameterUpdates self
  , epoch :: Update -> Number
    -- ^ Epoch
    -- > epoch self
  , new :: ProposedProtocolParameterUpdates -> Number -> Update
    -- ^ New
    -- > new proposedProtocolParameterUpdates epoch
  }

-- | Update class API
update :: UpdateClass
update =
  { free: update_free
  , toBytes: update_toBytes
  , fromBytes: update_fromBytes
  , toHex: update_toHex
  , fromHex: update_fromHex
  , toJson: update_toJson
  , toJsValue: update_toJsValue
  , fromJson: update_fromJson
  , proposedProtocolParameterUpdates: update_proposedProtocolParameterUpdates
  , epoch: update_epoch
  , new: update_new
  }

instance HasFree Update where
  free = update.free

instance Show Update where
  show = update.toHex

instance ToJsValue Update where
  toJsValue = update.toJsValue

instance IsHex Update where
  toHex = update.toHex
  fromHex = update.fromHex

instance IsBytes Update where
  toBytes = update.toBytes
  fromBytes = update.fromBytes

instance IsJson Update where
  toJson = update.toJson
  fromJson = update.fromJson

-------------------------------------------------------------------------------------
-- VRFCert

foreign import vrfCert_free :: VRFCert -> Effect Unit
foreign import vrfCert_toBytes :: VRFCert -> Bytes
foreign import vrfCert_fromBytes :: Bytes -> VRFCert
foreign import vrfCert_toHex :: VRFCert -> String
foreign import vrfCert_fromHex :: String -> VRFCert
foreign import vrfCert_toJson :: VRFCert -> String
foreign import vrfCert_toJsValue :: VRFCert -> VRFCertJson
foreign import vrfCert_fromJson :: String -> VRFCert
foreign import vrfCert_out :: VRFCert -> Bytes
foreign import vrfCert_proof :: VRFCert -> Bytes
foreign import vrfCert_new :: Bytes -> Bytes -> VRFCert

-- | VRFCert class
type VRFCertClass =
  { free :: VRFCert -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: VRFCert -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> VRFCert
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: VRFCert -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> VRFCert
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: VRFCert -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: VRFCert -> VRFCertJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> VRFCert
    -- ^ From json
    -- > fromJson json
  , out :: VRFCert -> Bytes
    -- ^ Output
    -- > out self
  , proof :: VRFCert -> Bytes
    -- ^ Proof
    -- > proof self
  , new :: Bytes -> Bytes -> VRFCert
    -- ^ New
    -- > new out proof
  }

-- | VRFCert class API
vrfCert :: VRFCertClass
vrfCert =
  { free: vrfCert_free
  , toBytes: vrfCert_toBytes
  , fromBytes: vrfCert_fromBytes
  , toHex: vrfCert_toHex
  , fromHex: vrfCert_fromHex
  , toJson: vrfCert_toJson
  , toJsValue: vrfCert_toJsValue
  , fromJson: vrfCert_fromJson
  , out: vrfCert_out
  , proof: vrfCert_proof
  , new: vrfCert_new
  }

instance HasFree VRFCert where
  free = vrfCert.free

instance Show VRFCert where
  show = vrfCert.toHex

instance ToJsValue VRFCert where
  toJsValue = vrfCert.toJsValue

instance IsHex VRFCert where
  toHex = vrfCert.toHex
  fromHex = vrfCert.fromHex

instance IsBytes VRFCert where
  toBytes = vrfCert.toBytes
  fromBytes = vrfCert.fromBytes

instance IsJson VRFCert where
  toJson = vrfCert.toJson
  fromJson = vrfCert.fromJson

-------------------------------------------------------------------------------------
-- VRFKey hash

foreign import vrfKeyHash_free :: VRFKeyHash -> Effect Unit
foreign import vrfKeyHash_fromBytes :: Bytes -> VRFKeyHash
foreign import vrfKeyHash_toBytes :: VRFKeyHash -> Bytes
foreign import vrfKeyHash_toBech32 :: VRFKeyHash -> String -> String
foreign import vrfKeyHash_fromBech32 :: String -> VRFKeyHash
foreign import vrfKeyHash_toHex :: VRFKeyHash -> String
foreign import vrfKeyHash_fromHex :: String -> VRFKeyHash

-- | VRFKey hash class
type VRFKeyHashClass =
  { free :: VRFKeyHash -> Effect Unit
    -- ^ Free
    -- > free self
  , fromBytes :: Bytes -> VRFKeyHash
    -- ^ From bytes
    -- > fromBytes bytes
  , toBytes :: VRFKeyHash -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , toBech32 :: VRFKeyHash -> String -> String
    -- ^ To bech32
    -- > toBech32 self prefix
  , fromBech32 :: String -> VRFKeyHash
    -- ^ From bech32
    -- > fromBech32 bechStr
  , toHex :: VRFKeyHash -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> VRFKeyHash
    -- ^ From hex
    -- > fromHex hex
  }

-- | VRFKey hash class API
vrfKeyHash :: VRFKeyHashClass
vrfKeyHash =
  { free: vrfKeyHash_free
  , fromBytes: vrfKeyHash_fromBytes
  , toBytes: vrfKeyHash_toBytes
  , toBech32: vrfKeyHash_toBech32
  , fromBech32: vrfKeyHash_fromBech32
  , toHex: vrfKeyHash_toHex
  , fromHex: vrfKeyHash_fromHex
  }

instance HasFree VRFKeyHash where
  free = vrfKeyHash.free

instance Show VRFKeyHash where
  show = vrfKeyHash.toHex

instance IsHex VRFKeyHash where
  toHex = vrfKeyHash.toHex
  fromHex = vrfKeyHash.fromHex

instance IsBytes VRFKeyHash where
  toBytes = vrfKeyHash.toBytes
  fromBytes = vrfKeyHash.fromBytes

-------------------------------------------------------------------------------------
-- VRFVKey

foreign import vrfvKey_free :: VRFVKey -> Effect Unit
foreign import vrfvKey_fromBytes :: Bytes -> VRFVKey
foreign import vrfvKey_toBytes :: VRFVKey -> Bytes
foreign import vrfvKey_toBech32 :: VRFVKey -> String -> String
foreign import vrfvKey_fromBech32 :: String -> VRFVKey
foreign import vrfvKey_toHex :: VRFVKey -> String
foreign import vrfvKey_fromHex :: String -> VRFVKey

-- | VRFVKey class
type VRFVKeyClass =
  { free :: VRFVKey -> Effect Unit
    -- ^ Free
    -- > free self
  , fromBytes :: Bytes -> VRFVKey
    -- ^ From bytes
    -- > fromBytes bytes
  , toBytes :: VRFVKey -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , toBech32 :: VRFVKey -> String -> String
    -- ^ To bech32
    -- > toBech32 self prefix
  , fromBech32 :: String -> VRFVKey
    -- ^ From bech32
    -- > fromBech32 bechStr
  , toHex :: VRFVKey -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> VRFVKey
    -- ^ From hex
    -- > fromHex hex
  }

-- | VRFVKey class API
vrfvKey :: VRFVKeyClass
vrfvKey =
  { free: vrfvKey_free
  , fromBytes: vrfvKey_fromBytes
  , toBytes: vrfvKey_toBytes
  , toBech32: vrfvKey_toBech32
  , fromBech32: vrfvKey_fromBech32
  , toHex: vrfvKey_toHex
  , fromHex: vrfvKey_fromHex
  }

instance HasFree VRFVKey where
  free = vrfvKey.free

instance Show VRFVKey where
  show = vrfvKey.toHex

instance IsHex VRFVKey where
  toHex = vrfvKey.toHex
  fromHex = vrfvKey.fromHex

instance IsBytes VRFVKey where
  toBytes = vrfvKey.toBytes
  fromBytes = vrfvKey.fromBytes

-------------------------------------------------------------------------------------
-- Value

foreign import value_free :: Value -> Effect Unit
foreign import value_toBytes :: Value -> Bytes
foreign import value_fromBytes :: Bytes -> Value
foreign import value_toHex :: Value -> String
foreign import value_fromHex :: String -> Value
foreign import value_toJson :: Value -> String
foreign import value_toJsValue :: Value -> ValueJson
foreign import value_fromJson :: String -> Value
foreign import value_new :: BigNum -> Value
foreign import value_newFromAssets :: MultiAsset -> Value
foreign import value_newWithAssets :: BigNum -> MultiAsset -> Value
foreign import value_zero :: Value
foreign import value_isZero :: Value -> Boolean
foreign import value_coin :: Value -> BigNum
foreign import value_setCoin :: Value -> BigNum -> Effect Unit
foreign import value_multiasset :: Value -> Nullable MultiAsset
foreign import value_setMultiasset :: Value -> MultiAsset -> Effect Unit
foreign import value_checkedAdd :: Value -> Value -> Value
foreign import value_checkedSub :: Value -> Value -> Value
foreign import value_clampedSub :: Value -> Value -> Value
foreign import value_compare :: Value -> Value -> Nullable Int

-- | Value class
type ValueClass =
  { free :: Value -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Value -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Value
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Value -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Value
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Value -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Value -> ValueJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Value
    -- ^ From json
    -- > fromJson json
  , new :: BigNum -> Value
    -- ^ New
    -- > new coin
  , newFromAssets :: MultiAsset -> Value
    -- ^ New from assets
    -- > newFromAssets multiasset
  , newWithAssets :: BigNum -> MultiAsset -> Value
    -- ^ New with assets
    -- > newWithAssets coin multiasset
  , zero :: Value
    -- ^ Zero
    -- > zero
  , isZero :: Value -> Boolean
    -- ^ Is zero
    -- > isZero self
  , coin :: Value -> BigNum
    -- ^ Coin
    -- > coin self
  , setCoin :: Value -> BigNum -> Effect Unit
    -- ^ Set coin
    -- > setCoin self coin
  , multiasset :: Value -> Maybe MultiAsset
    -- ^ Multiasset
    -- > multiasset self
  , setMultiasset :: Value -> MultiAsset -> Effect Unit
    -- ^ Set multiasset
    -- > setMultiasset self multiasset
  , checkedAdd :: Value -> Value -> Value
    -- ^ Checked add
    -- > checkedAdd self rhs
  , checkedSub :: Value -> Value -> Value
    -- ^ Checked sub
    -- > checkedSub self rhsValue
  , clampedSub :: Value -> Value -> Value
    -- ^ Clamped sub
    -- > clampedSub self rhsValue
  , compare :: Value -> Value -> Maybe Int
    -- ^ Compare
    -- > compare self rhsValue
  }

-- | Value class API
value :: ValueClass
value =
  { free: value_free
  , toBytes: value_toBytes
  , fromBytes: value_fromBytes
  , toHex: value_toHex
  , fromHex: value_fromHex
  , toJson: value_toJson
  , toJsValue: value_toJsValue
  , fromJson: value_fromJson
  , new: value_new
  , newFromAssets: value_newFromAssets
  , newWithAssets: value_newWithAssets
  , zero: value_zero
  , isZero: value_isZero
  , coin: value_coin
  , setCoin: value_setCoin
  , multiasset: \a1 -> Nullable.toMaybe $ value_multiasset a1
  , setMultiasset: value_setMultiasset
  , checkedAdd: value_checkedAdd
  , checkedSub: value_checkedSub
  , clampedSub: value_clampedSub
  , compare: \a1 a2 -> Nullable.toMaybe $ value_compare a1 a2
  }

instance HasFree Value where
  free = value.free

instance Show Value where
  show = value.toHex

instance ToJsValue Value where
  toJsValue = value.toJsValue

instance IsHex Value where
  toHex = value.toHex
  fromHex = value.fromHex

instance IsBytes Value where
  toBytes = value.toBytes
  fromBytes = value.fromBytes

instance IsJson Value where
  toJson = value.toJson
  fromJson = value.fromJson

-------------------------------------------------------------------------------------
-- Vkey

foreign import vkey_free :: Vkey -> Effect Unit
foreign import vkey_toBytes :: Vkey -> Bytes
foreign import vkey_fromBytes :: Bytes -> Vkey
foreign import vkey_toHex :: Vkey -> String
foreign import vkey_fromHex :: String -> Vkey
foreign import vkey_toJson :: Vkey -> String
foreign import vkey_toJsValue :: Vkey -> VkeyJson
foreign import vkey_fromJson :: String -> Vkey
foreign import vkey_new :: PublicKey -> Vkey
foreign import vkey_publicKey :: Vkey -> PublicKey

-- | Vkey class
type VkeyClass =
  { free :: Vkey -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Vkey -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Vkey
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Vkey -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Vkey
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Vkey -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Vkey -> VkeyJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Vkey
    -- ^ From json
    -- > fromJson json
  , new :: PublicKey -> Vkey
    -- ^ New
    -- > new pk
  , publicKey :: Vkey -> PublicKey
    -- ^ Public key
    -- > publicKey self
  }

-- | Vkey class API
vkey :: VkeyClass
vkey =
  { free: vkey_free
  , toBytes: vkey_toBytes
  , fromBytes: vkey_fromBytes
  , toHex: vkey_toHex
  , fromHex: vkey_fromHex
  , toJson: vkey_toJson
  , toJsValue: vkey_toJsValue
  , fromJson: vkey_fromJson
  , new: vkey_new
  , publicKey: vkey_publicKey
  }

instance HasFree Vkey where
  free = vkey.free

instance Show Vkey where
  show = vkey.toHex

instance ToJsValue Vkey where
  toJsValue = vkey.toJsValue

instance IsHex Vkey where
  toHex = vkey.toHex
  fromHex = vkey.fromHex

instance IsBytes Vkey where
  toBytes = vkey.toBytes
  fromBytes = vkey.fromBytes

instance IsJson Vkey where
  toJson = vkey.toJson
  fromJson = vkey.fromJson

-------------------------------------------------------------------------------------
-- Vkeys

foreign import vkeys_free :: Vkeys -> Effect Unit
foreign import vkeys_new :: Effect Vkeys
foreign import vkeys_len :: Vkeys -> Effect Int
foreign import vkeys_get :: Vkeys -> Int -> Effect Vkey
foreign import vkeys_add :: Vkeys -> Vkey -> Effect Unit

-- | Vkeys class
type VkeysClass =
  { free :: Vkeys -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: Effect Vkeys
    -- ^ New
    -- > new
  , len :: Vkeys -> Effect Int
    -- ^ Len
    -- > len self
  , get :: Vkeys -> Int -> Effect Vkey
    -- ^ Get
    -- > get self index
  , add :: Vkeys -> Vkey -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Vkeys class API
vkeys :: VkeysClass
vkeys =
  { free: vkeys_free
  , new: vkeys_new
  , len: vkeys_len
  , get: vkeys_get
  , add: vkeys_add
  }

instance HasFree Vkeys where
  free = vkeys.free

instance MutableList Vkeys Vkey where
  addItem = vkeys.add
  getItem = vkeys.get
  emptyList = vkeys.new

instance MutableLen Vkeys where
  getLen = vkeys.len

-------------------------------------------------------------------------------------
-- Vkeywitness

foreign import vkeywitness_free :: Vkeywitness -> Effect Unit
foreign import vkeywitness_toBytes :: Vkeywitness -> Bytes
foreign import vkeywitness_fromBytes :: Bytes -> Vkeywitness
foreign import vkeywitness_toHex :: Vkeywitness -> String
foreign import vkeywitness_fromHex :: String -> Vkeywitness
foreign import vkeywitness_toJson :: Vkeywitness -> String
foreign import vkeywitness_toJsValue :: Vkeywitness -> VkeywitnessJson
foreign import vkeywitness_fromJson :: String -> Vkeywitness
foreign import vkeywitness_new :: Vkey -> Ed25519Signature -> Vkeywitness
foreign import vkeywitness_vkey :: Vkeywitness -> Vkey
foreign import vkeywitness_signature :: Vkeywitness -> Ed25519Signature

-- | Vkeywitness class
type VkeywitnessClass =
  { free :: Vkeywitness -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Vkeywitness -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Vkeywitness
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Vkeywitness -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Vkeywitness
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Vkeywitness -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Vkeywitness -> VkeywitnessJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Vkeywitness
    -- ^ From json
    -- > fromJson json
  , new :: Vkey -> Ed25519Signature -> Vkeywitness
    -- ^ New
    -- > new vkey signature
  , vkey :: Vkeywitness -> Vkey
    -- ^ Vkey
    -- > vkey self
  , signature :: Vkeywitness -> Ed25519Signature
    -- ^ Signature
    -- > signature self
  }

-- | Vkeywitness class API
vkeywitness :: VkeywitnessClass
vkeywitness =
  { free: vkeywitness_free
  , toBytes: vkeywitness_toBytes
  , fromBytes: vkeywitness_fromBytes
  , toHex: vkeywitness_toHex
  , fromHex: vkeywitness_fromHex
  , toJson: vkeywitness_toJson
  , toJsValue: vkeywitness_toJsValue
  , fromJson: vkeywitness_fromJson
  , new: vkeywitness_new
  , vkey: vkeywitness_vkey
  , signature: vkeywitness_signature
  }

instance HasFree Vkeywitness where
  free = vkeywitness.free

instance Show Vkeywitness where
  show = vkeywitness.toHex

instance ToJsValue Vkeywitness where
  toJsValue = vkeywitness.toJsValue

instance IsHex Vkeywitness where
  toHex = vkeywitness.toHex
  fromHex = vkeywitness.fromHex

instance IsBytes Vkeywitness where
  toBytes = vkeywitness.toBytes
  fromBytes = vkeywitness.fromBytes

instance IsJson Vkeywitness where
  toJson = vkeywitness.toJson
  fromJson = vkeywitness.fromJson

-------------------------------------------------------------------------------------
-- Vkeywitnesses

foreign import vkeywitnesses_free :: Vkeywitnesses -> Effect Unit
foreign import vkeywitnesses_new :: Effect Vkeywitnesses
foreign import vkeywitnesses_len :: Vkeywitnesses -> Effect Int
foreign import vkeywitnesses_get :: Vkeywitnesses -> Int -> Effect Vkeywitness
foreign import vkeywitnesses_add :: Vkeywitnesses -> Vkeywitness -> Effect Unit

-- | Vkeywitnesses class
type VkeywitnessesClass =
  { free :: Vkeywitnesses -> Effect Unit
    -- ^ Free
    -- > free self
  , new :: Effect Vkeywitnesses
    -- ^ New
    -- > new
  , len :: Vkeywitnesses -> Effect Int
    -- ^ Len
    -- > len self
  , get :: Vkeywitnesses -> Int -> Effect Vkeywitness
    -- ^ Get
    -- > get self index
  , add :: Vkeywitnesses -> Vkeywitness -> Effect Unit
    -- ^ Add
    -- > add self elem
  }

-- | Vkeywitnesses class API
vkeywitnesses :: VkeywitnessesClass
vkeywitnesses =
  { free: vkeywitnesses_free
  , new: vkeywitnesses_new
  , len: vkeywitnesses_len
  , get: vkeywitnesses_get
  , add: vkeywitnesses_add
  }

instance HasFree Vkeywitnesses where
  free = vkeywitnesses.free

instance MutableList Vkeywitnesses Vkeywitness where
  addItem = vkeywitnesses.add
  getItem = vkeywitnesses.get
  emptyList = vkeywitnesses.new

instance MutableLen Vkeywitnesses where
  getLen = vkeywitnesses.len

-------------------------------------------------------------------------------------
-- Withdrawals

foreign import withdrawals_free :: Withdrawals -> Effect Unit
foreign import withdrawals_toBytes :: Withdrawals -> Bytes
foreign import withdrawals_fromBytes :: Bytes -> Withdrawals
foreign import withdrawals_toHex :: Withdrawals -> String
foreign import withdrawals_fromHex :: String -> Withdrawals
foreign import withdrawals_toJson :: Withdrawals -> String
foreign import withdrawals_toJsValue :: Withdrawals -> WithdrawalsJson
foreign import withdrawals_fromJson :: String -> Withdrawals
foreign import withdrawals_new :: Effect Withdrawals
foreign import withdrawals_len :: Withdrawals -> Effect Int
foreign import withdrawals_insert :: Withdrawals -> RewardAddress -> BigNum -> Effect (Nullable BigNum)
foreign import withdrawals_get :: Withdrawals -> RewardAddress -> Effect (Nullable BigNum)
foreign import withdrawals_keys :: Withdrawals -> Effect RewardAddresses

-- | Withdrawals class
type WithdrawalsClass =
  { free :: Withdrawals -> Effect Unit
    -- ^ Free
    -- > free self
  , toBytes :: Withdrawals -> Bytes
    -- ^ To bytes
    -- > toBytes self
  , fromBytes :: Bytes -> Withdrawals
    -- ^ From bytes
    -- > fromBytes bytes
  , toHex :: Withdrawals -> String
    -- ^ To hex
    -- > toHex self
  , fromHex :: String -> Withdrawals
    -- ^ From hex
    -- > fromHex hexStr
  , toJson :: Withdrawals -> String
    -- ^ To json
    -- > toJson self
  , toJsValue :: Withdrawals -> WithdrawalsJson
    -- ^ To js value
    -- > toJsValue self
  , fromJson :: String -> Withdrawals
    -- ^ From json
    -- > fromJson json
  , new :: Effect Withdrawals
    -- ^ New
    -- > new
  , len :: Withdrawals -> Effect Int
    -- ^ Len
    -- > len self
  , insert :: Withdrawals -> RewardAddress -> BigNum -> Effect (Maybe BigNum)
    -- ^ Insert
    -- > insert self key value
  , get :: Withdrawals -> RewardAddress -> Effect (Maybe BigNum)
    -- ^ Get
    -- > get self key
  , keys :: Withdrawals -> Effect RewardAddresses
    -- ^ Keys
    -- > keys self
  }

-- | Withdrawals class API
withdrawals :: WithdrawalsClass
withdrawals =
  { free: withdrawals_free
  , toBytes: withdrawals_toBytes
  , fromBytes: withdrawals_fromBytes
  , toHex: withdrawals_toHex
  , fromHex: withdrawals_fromHex
  , toJson: withdrawals_toJson
  , toJsValue: withdrawals_toJsValue
  , fromJson: withdrawals_fromJson
  , new: withdrawals_new
  , len: withdrawals_len
  , insert: \a1 a2 a3 -> Nullable.toMaybe <$> withdrawals_insert a1 a2 a3
  , get: \a1 a2 -> Nullable.toMaybe <$> withdrawals_get a1 a2
  , keys: withdrawals_keys
  }

instance HasFree Withdrawals where
  free = withdrawals.free

instance Show Withdrawals where
  show = withdrawals.toHex

instance ToJsValue Withdrawals where
  toJsValue = withdrawals.toJsValue

instance IsHex Withdrawals where
  toHex = withdrawals.toHex
  fromHex = withdrawals.fromHex

instance IsBytes Withdrawals where
  toBytes = withdrawals.toBytes
  fromBytes = withdrawals.fromBytes

instance IsJson Withdrawals where
  toJson = withdrawals.toJson
  fromJson = withdrawals.fromJson

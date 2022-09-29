"use strict";

import * as CSL from "@emurgo/cardano-serialization-lib-browser";

// funs

export const minFee = tx => linear_fee => CSL.min_fee(tx, linear_fee);
export const calculateExUnitsCeilCost = ex_units => ex_unit_prices => CSL.calculate_ex_units_ceil_cost(ex_units, ex_unit_prices);
export const minScriptFee = tx => ex_unit_prices => CSL.min_script_fee(tx, ex_unit_prices);
export const encryptWithPassword = password => salt => nonce => data => CSL.encrypt_with_password(password, salt, nonce, data);
export const decryptWithPassword = password => data => CSL.decrypt_with_password(password, data);
export const makeDaedalusBootstrapWitness = tx_body_hash => addr => key => CSL.make_daedalus_bootstrap_witness(tx_body_hash, addr, key);
export const makeIcarusBootstrapWitness = tx_body_hash => addr => key => CSL.make_icarus_bootstrap_witness(tx_body_hash, addr, key);
export const makeVkeyWitness = tx_body_hash => sk => CSL.make_vkey_witness(tx_body_hash, sk);
export const hashAuxiliaryData = auxiliary_data => CSL.hash_auxiliary_data(auxiliary_data);
export const hashTx = tx_body => CSL.hash_transaction(tx_body);
export const hashPlutusData = plutus_data => CSL.hash_plutus_data(plutus_data);
export const hashScriptData = redeemers => cost_models => datums => CSL.hash_script_data(redeemers, cost_models, datums);
export const getImplicitIn = txbody => pool_deposit => key_deposit => CSL.get_implicit_input(txbody, pool_deposit, key_deposit);
export const getDeposit = txbody => pool_deposit => key_deposit => CSL.get_deposit(txbody, pool_deposit, key_deposit);
export const minAdaForOut = output => data_cost => CSL.min_ada_for_output(output, data_cost);
export const minAdaRequired = assets => has_data_hash => coins_per_utxo_word => CSL.min_ada_required(assets, has_data_hash, coins_per_utxo_word);
export const encodeJsonStrToNativeScript = json => self_xpub => schema => CSL.encode_json_str_to_native_script(json, self_xpub, schema);
export const encodeJsonStrToPlutusDatum = json => schema => CSL.encode_json_str_to_plutus_datum(json, schema);
export const decodePlutusDatumToJsonStr = datum => schema => CSL.decode_plutus_datum_to_json_str(datum, schema);
export const encodeArbitraryBytesAsMetadatum = bytes => CSL.encode_arbitrary_bytes_as_metadatum(bytes);
export const decodeArbitraryBytesFromMetadatum = metadata => CSL.decode_arbitrary_bytes_from_metadatum(metadata);
export const encodeJsonStrToMetadatum = json => schema => CSL.encode_json_str_to_metadatum(json, schema);
export const decodeMetadatumToJsonStr = metadatum => schema => CSL.decode_metadatum_to_json_str(metadatum, schema);

// Address
export const address_free = self => () => self.free();
export const address_fromBytes = data => CSL.Address.from_bytes(data);
export const address_toJson = self => self.to_json();
export const address_toJsValue = self => self.to_js_value();
export const address_fromJson = json => CSL.Address.from_json(json);
export const address_toHex = self => self.to_hex();
export const address_fromHex = hex_str => CSL.Address.from_hex(hex_str);
export const address_toBytes = self => self.to_bytes();
export const address_toBech32 = self => prefix => self.to_bech32(prefix);
export const address_fromBech32 = bech_str => CSL.Address.from_bech32(bech_str);
export const address_networkId = self => self.network_id();

// AssetName
export const assetName_free = self => () => self.free();
export const assetName_toBytes = self => self.to_bytes();
export const assetName_fromBytes = bytes => CSL.AssetName.from_bytes(bytes);
export const assetName_toHex = self => self.to_hex();
export const assetName_fromHex = hex_str => CSL.AssetName.from_hex(hex_str);
export const assetName_toJson = self => self.to_json();
export const assetName_toJsValue = self => self.to_js_value();
export const assetName_fromJson = json => CSL.AssetName.from_json(json);
export const assetName_new = name => CSL.AssetName.new(name);
export const assetName_name = self => self.name();

// AssetNames
export const assetNames_free = self => () => self.free();
export const assetNames_toBytes = self => self.to_bytes();
export const assetNames_fromBytes = bytes => CSL.AssetNames.from_bytes(bytes);
export const assetNames_toHex = self => self.to_hex();
export const assetNames_fromHex = hex_str => CSL.AssetNames.from_hex(hex_str);
export const assetNames_toJson = self => self.to_json();
export const assetNames_toJsValue = self => self.to_js_value();
export const assetNames_fromJson = json => CSL.AssetNames.from_json(json);
export const assetNames_new = CSL.AssetNames.new();
export const assetNames_len = self => self.len();
export const assetNames_get = self => index => self.get(index);
export const assetNames_add = self => elem => () => self.add(elem);

// Assets
export const assets_free = self => () => self.free();
export const assets_toBytes = self => self.to_bytes();
export const assets_fromBytes = bytes => CSL.Assets.from_bytes(bytes);
export const assets_toHex = self => self.to_hex();
export const assets_fromHex = hex_str => CSL.Assets.from_hex(hex_str);
export const assets_toJson = self => self.to_json();
export const assets_toJsValue = self => self.to_js_value();
export const assets_fromJson = json => CSL.Assets.from_json(json);
export const assets_new = CSL.Assets.new();
export const assets_len = self => self.len();
export const assets_insert = self => key => value => self.insert(key, value);
export const assets_get = self => key => self.get(key);
export const assets_keys = self => self.keys();

// AuxiliaryData
export const auxiliaryData_free = self => () => self.free();
export const auxiliaryData_toBytes = self => self.to_bytes();
export const auxiliaryData_fromBytes = bytes => CSL.AuxiliaryData.from_bytes(bytes);
export const auxiliaryData_toHex = self => self.to_hex();
export const auxiliaryData_fromHex = hex_str => CSL.AuxiliaryData.from_hex(hex_str);
export const auxiliaryData_toJson = self => self.to_json();
export const auxiliaryData_toJsValue = self => self.to_js_value();
export const auxiliaryData_fromJson = json => CSL.AuxiliaryData.from_json(json);
export const auxiliaryData_new = CSL.AuxiliaryData.new();
export const auxiliaryData_metadata = self => self.metadata();
export const auxiliaryData_setMetadata = self => metadata => () => self.set_metadata(metadata);
export const auxiliaryData_nativeScripts = self => self.native_scripts();
export const auxiliaryData_setNativeScripts = self => native_scripts => () => self.set_native_scripts(native_scripts);
export const auxiliaryData_plutusScripts = self => self.plutus_scripts();
export const auxiliaryData_setPlutusScripts = self => plutus_scripts => () => self.set_plutus_scripts(plutus_scripts);

// AuxiliaryDataHash
export const auxiliaryDataHash_free = self => () => self.free();
export const auxiliaryDataHash_fromBytes = bytes => CSL.AuxiliaryDataHash.from_bytes(bytes);
export const auxiliaryDataHash_toBytes = self => self.to_bytes();
export const auxiliaryDataHash_toBech32 = self => prefix => self.to_bech32(prefix);
export const auxiliaryDataHash_fromBech32 = bech_str => CSL.AuxiliaryDataHash.from_bech32(bech_str);
export const auxiliaryDataHash_toHex = self => self.to_hex();
export const auxiliaryDataHash_fromHex = hex => CSL.AuxiliaryDataHash.from_hex(hex);

// AuxiliaryDataSet
export const auxiliaryDataSet_free = self => () => self.free();
export const auxiliaryDataSet_new = CSL.AuxiliaryDataSet.new();
export const auxiliaryDataSet_len = self => self.len();
export const auxiliaryDataSet_insert = self => tx_index => data => self.insert(tx_index, data);
export const auxiliaryDataSet_get = self => tx_index => self.get(tx_index);
export const auxiliaryDataSet_indices = self => self.indices();

// BaseAddress
export const baseAddress_free = self => () => self.free();
export const baseAddress_new = network => payment => stake => CSL.BaseAddress.new(network, payment, stake);
export const baseAddress_paymentCred = self => self.payment_cred();
export const baseAddress_stakeCred = self => self.stake_cred();
export const baseAddress_toAddress = self => self.to_address();
export const baseAddress_fromAddress = addr => CSL.BaseAddress.from_address(addr);

// BigInt
export const bigInt_free = self => () => self.free();
export const bigInt_toBytes = self => self.to_bytes();
export const bigInt_fromBytes = bytes => CSL.BigInt.from_bytes(bytes);
export const bigInt_toHex = self => self.to_hex();
export const bigInt_fromHex = hex_str => CSL.BigInt.from_hex(hex_str);
export const bigInt_toJson = self => self.to_json();
export const bigInt_toJsValue = self => self.to_js_value();
export const bigInt_fromJson = json => CSL.BigInt.from_json(json);
export const bigInt_isZero = self => self.is_zero();
export const bigInt_asU64 = self => self.as_u64();
export const bigInt_asInt = self => self.as_int();
export const bigInt_fromStr = text => CSL.BigInt.from_str(text);
export const bigInt_toStr = self => self.to_str();
export const bigInt_add = self => other => self.add(other);
export const bigInt_mul = self => other => self.mul(other);
export const bigInt_one = CSL.BigInt.one();
export const bigInt_increment = self => self.increment();
export const bigInt_divCeil = self => other => self.div_ceil(other);

// BigNum
export const bigNum_free = self => () => self.free();
export const bigNum_toBytes = self => self.to_bytes();
export const bigNum_fromBytes = bytes => CSL.BigNum.from_bytes(bytes);
export const bigNum_toHex = self => self.to_hex();
export const bigNum_fromHex = hex_str => CSL.BigNum.from_hex(hex_str);
export const bigNum_toJson = self => self.to_json();
export const bigNum_toJsValue = self => self.to_js_value();
export const bigNum_fromJson = json => CSL.BigNum.from_json(json);
export const bigNum_fromStr = string => CSL.BigNum.from_str(string);
export const bigNum_toStr = self => self.to_str();
export const bigNum_zero = CSL.BigNum.zero();
export const bigNum_one = CSL.BigNum.one();
export const bigNum_isZero = self => self.is_zero();
export const bigNum_divFloor = self => other => self.div_floor(other);
export const bigNum_checkedMul = self => other => self.checked_mul(other);
export const bigNum_checkedAdd = self => other => self.checked_add(other);
export const bigNum_checkedSub = self => other => self.checked_sub(other);
export const bigNum_clampedSub = self => other => self.clamped_sub(other);
export const bigNum_compare = self => rhs_value => self.compare(rhs_value);
export const bigNum_lessThan = self => rhs_value => self.less_than(rhs_value);
export const bigNum_max = a => b => CSL.BigNum.max(a, b);

// Bip32PrivateKey
export const bip32PrivateKey_free = self => () => self.free();
export const bip32PrivateKey_derive = self => index => self.derive(index);
export const bip32PrivateKey_from128Xprv = bytes => CSL.Bip32PrivateKey.from_128_xprv(bytes);
export const bip32PrivateKey_to128Xprv = self => self.to_128_xprv();
export const bip32PrivateKey_generateEd25519Bip32 = CSL.Bip32PrivateKey.generate_ed25519_bip32();
export const bip32PrivateKey_toRawKey = self => self.to_raw_key();
export const bip32PrivateKey_toPublic = self => self.to_public();
export const bip32PrivateKey_fromBytes = bytes => CSL.Bip32PrivateKey.from_bytes(bytes);
export const bip32PrivateKey_asBytes = self => self.as_bytes();
export const bip32PrivateKey_fromBech32 = bech32_str => CSL.Bip32PrivateKey.from_bech32(bech32_str);
export const bip32PrivateKey_toBech32 = self => self.to_bech32();
export const bip32PrivateKey_fromBip39Entropy = entropy => password => CSL.Bip32PrivateKey.from_bip39_entropy(entropy, password);
export const bip32PrivateKey_chaincode = self => self.chaincode();
export const bip32PrivateKey_toHex = self => self.to_hex();
export const bip32PrivateKey_fromHex = hex_str => CSL.Bip32PrivateKey.from_hex(hex_str);

// Bip32PublicKey
export const bip32PublicKey_free = self => () => self.free();
export const bip32PublicKey_derive = self => index => self.derive(index);
export const bip32PublicKey_toRawKey = self => self.to_raw_key();
export const bip32PublicKey_fromBytes = bytes => CSL.Bip32PublicKey.from_bytes(bytes);
export const bip32PublicKey_asBytes = self => self.as_bytes();
export const bip32PublicKey_fromBech32 = bech32_str => CSL.Bip32PublicKey.from_bech32(bech32_str);
export const bip32PublicKey_toBech32 = self => self.to_bech32();
export const bip32PublicKey_chaincode = self => self.chaincode();
export const bip32PublicKey_toHex = self => self.to_hex();
export const bip32PublicKey_fromHex = hex_str => CSL.Bip32PublicKey.from_hex(hex_str);

// Block
export const block_free = self => () => self.free();
export const block_toBytes = self => self.to_bytes();
export const block_fromBytes = bytes => CSL.Block.from_bytes(bytes);
export const block_toHex = self => self.to_hex();
export const block_fromHex = hex_str => CSL.Block.from_hex(hex_str);
export const block_toJson = self => self.to_json();
export const block_toJsValue = self => self.to_js_value();
export const block_fromJson = json => CSL.Block.from_json(json);
export const block_header = self => self.header();
export const block_txBodies = self => self.transaction_bodies();
export const block_txWitnessSets = self => self.transaction_witness_sets();
export const block_auxiliaryDataSet = self => self.auxiliary_data_set();
export const block_invalidTxs = self => self.invalid_transactions();
export const block_new = header => transaction_bodies => transaction_witness_sets => auxiliary_data_set => invalid_transactions => CSL.Block.new(header, transaction_bodies, transaction_witness_sets, auxiliary_data_set, invalid_transactions);

// BlockHash
export const blockHash_free = self => () => self.free();
export const blockHash_fromBytes = bytes => CSL.BlockHash.from_bytes(bytes);
export const blockHash_toBytes = self => self.to_bytes();
export const blockHash_toBech32 = self => prefix => self.to_bech32(prefix);
export const blockHash_fromBech32 = bech_str => CSL.BlockHash.from_bech32(bech_str);
export const blockHash_toHex = self => self.to_hex();
export const blockHash_fromHex = hex => CSL.BlockHash.from_hex(hex);

// BootstrapWitness
export const bootstrapWitness_free = self => () => self.free();
export const bootstrapWitness_toBytes = self => self.to_bytes();
export const bootstrapWitness_fromBytes = bytes => CSL.BootstrapWitness.from_bytes(bytes);
export const bootstrapWitness_toHex = self => self.to_hex();
export const bootstrapWitness_fromHex = hex_str => CSL.BootstrapWitness.from_hex(hex_str);
export const bootstrapWitness_toJson = self => self.to_json();
export const bootstrapWitness_toJsValue = self => self.to_js_value();
export const bootstrapWitness_fromJson = json => CSL.BootstrapWitness.from_json(json);
export const bootstrapWitness_vkey = self => self.vkey();
export const bootstrapWitness_signature = self => self.signature();
export const bootstrapWitness_chainCode = self => self.chain_code();
export const bootstrapWitness_attributes = self => self.attributes();
export const bootstrapWitness_new = vkey => signature => chain_code => attributes => CSL.BootstrapWitness.new(vkey, signature, chain_code, attributes);

// BootstrapWitnesses
export const bootstrapWitnesses_free = self => () => self.free();
export const bootstrapWitnesses_new = CSL.BootstrapWitnesses.new();
export const bootstrapWitnesses_len = self => self.len();
export const bootstrapWitnesses_get = self => index => self.get(index);
export const bootstrapWitnesses_add = self => elem => () => self.add(elem);

// ByronAddress
export const byronAddress_free = self => () => self.free();
export const byronAddress_toBase58 = self => self.to_base58();
export const byronAddress_toBytes = self => self.to_bytes();
export const byronAddress_fromBytes = bytes => CSL.ByronAddress.from_bytes(bytes);
export const byronAddress_byronProtocolMagic = self => self.byron_protocol_magic();
export const byronAddress_attributes = self => self.attributes();
export const byronAddress_networkId = self => self.network_id();
export const byronAddress_fromBase58 = s => CSL.ByronAddress.from_base58(s);
export const byronAddress_icarusFromKey = key => protocol_magic => CSL.ByronAddress.icarus_from_key(key, protocol_magic);
export const byronAddress_isValid = s => CSL.ByronAddress.is_valid(s);
export const byronAddress_toAddress = self => self.to_address();
export const byronAddress_fromAddress = addr => CSL.ByronAddress.from_address(addr);

// Certificate
export const certificate_free = self => () => self.free();
export const certificate_toBytes = self => self.to_bytes();
export const certificate_fromBytes = bytes => CSL.Certificate.from_bytes(bytes);
export const certificate_toHex = self => self.to_hex();
export const certificate_fromHex = hex_str => CSL.Certificate.from_hex(hex_str);
export const certificate_toJson = self => self.to_json();
export const certificate_toJsValue = self => self.to_js_value();
export const certificate_fromJson = json => CSL.Certificate.from_json(json);
export const certificate_newStakeRegistration = stake_registration => CSL.Certificate.new_stake_registration(stake_registration);
export const certificate_newStakeDeregistration = stake_deregistration => CSL.Certificate.new_stake_deregistration(stake_deregistration);
export const certificate_newStakeDelegation = stake_delegation => CSL.Certificate.new_stake_delegation(stake_delegation);
export const certificate_newPoolRegistration = pool_registration => CSL.Certificate.new_pool_registration(pool_registration);
export const certificate_newPoolRetirement = pool_retirement => CSL.Certificate.new_pool_retirement(pool_retirement);
export const certificate_newGenesisKeyDelegation = genesis_key_delegation => CSL.Certificate.new_genesis_key_delegation(genesis_key_delegation);
export const certificate_newMoveInstantaneousRewardsCert = move_instantaneous_rewards_cert => CSL.Certificate.new_move_instantaneous_rewards_cert(move_instantaneous_rewards_cert);
export const certificate_kind = self => self.kind();
export const certificate_asStakeRegistration = self => self.as_stake_registration();
export const certificate_asStakeDeregistration = self => self.as_stake_deregistration();
export const certificate_asStakeDelegation = self => self.as_stake_delegation();
export const certificate_asPoolRegistration = self => self.as_pool_registration();
export const certificate_asPoolRetirement = self => self.as_pool_retirement();
export const certificate_asGenesisKeyDelegation = self => self.as_genesis_key_delegation();
export const certificate_asMoveInstantaneousRewardsCert = self => self.as_move_instantaneous_rewards_cert();

// Certificates
export const certificates_free = self => () => self.free();
export const certificates_toBytes = self => self.to_bytes();
export const certificates_fromBytes = bytes => CSL.Certificates.from_bytes(bytes);
export const certificates_toHex = self => self.to_hex();
export const certificates_fromHex = hex_str => CSL.Certificates.from_hex(hex_str);
export const certificates_toJson = self => self.to_json();
export const certificates_toJsValue = self => self.to_js_value();
export const certificates_fromJson = json => CSL.Certificates.from_json(json);
export const certificates_new = CSL.Certificates.new();
export const certificates_len = self => self.len();
export const certificates_get = self => index => self.get(index);
export const certificates_add = self => elem => () => self.add(elem);

// ConstrPlutusData
export const constrPlutusData_free = self => () => self.free();
export const constrPlutusData_toBytes = self => self.to_bytes();
export const constrPlutusData_fromBytes = bytes => CSL.ConstrPlutusData.from_bytes(bytes);
export const constrPlutusData_toHex = self => self.to_hex();
export const constrPlutusData_fromHex = hex_str => CSL.ConstrPlutusData.from_hex(hex_str);
export const constrPlutusData_toJson = self => self.to_json();
export const constrPlutusData_toJsValue = self => self.to_js_value();
export const constrPlutusData_fromJson = json => CSL.ConstrPlutusData.from_json(json);
export const constrPlutusData_alternative = self => self.alternative();
export const constrPlutusData_data = self => self.data();
export const constrPlutusData_new = alternative => data => CSL.ConstrPlutusData.new(alternative, data);

// CostModel
export const costModel_free = self => () => self.free();
export const costModel_toBytes = self => self.to_bytes();
export const costModel_fromBytes = bytes => CSL.CostModel.from_bytes(bytes);
export const costModel_toHex = self => self.to_hex();
export const costModel_fromHex = hex_str => CSL.CostModel.from_hex(hex_str);
export const costModel_toJson = self => self.to_json();
export const costModel_toJsValue = self => self.to_js_value();
export const costModel_fromJson = json => CSL.CostModel.from_json(json);
export const costModel_new = CSL.CostModel.new();
export const costModel_set = self => operation => cost => self.set(operation, cost);
export const costModel_get = self => operation => self.get(operation);
export const costModel_len = self => self.len();

// Costmdls
export const costmdls_free = self => () => self.free();
export const costmdls_toBytes = self => self.to_bytes();
export const costmdls_fromBytes = bytes => CSL.Costmdls.from_bytes(bytes);
export const costmdls_toHex = self => self.to_hex();
export const costmdls_fromHex = hex_str => CSL.Costmdls.from_hex(hex_str);
export const costmdls_toJson = self => self.to_json();
export const costmdls_toJsValue = self => self.to_js_value();
export const costmdls_fromJson = json => CSL.Costmdls.from_json(json);
export const costmdls_new = CSL.Costmdls.new();
export const costmdls_len = self => self.len();
export const costmdls_insert = self => key => value => self.insert(key, value);
export const costmdls_get = self => key => self.get(key);
export const costmdls_keys = self => self.keys();
export const costmdls_retainLanguageVersions = self => languages => self.retain_language_versions(languages);

// DNSRecordAorAAAA
export const dNSRecordAorAAAA_free = self => () => self.free();
export const dNSRecordAorAAAA_toBytes = self => self.to_bytes();
export const dNSRecordAorAAAA_fromBytes = bytes => CSL.DNSRecordAorAAAA.from_bytes(bytes);
export const dNSRecordAorAAAA_toHex = self => self.to_hex();
export const dNSRecordAorAAAA_fromHex = hex_str => CSL.DNSRecordAorAAAA.from_hex(hex_str);
export const dNSRecordAorAAAA_toJson = self => self.to_json();
export const dNSRecordAorAAAA_toJsValue = self => self.to_js_value();
export const dNSRecordAorAAAA_fromJson = json => CSL.DNSRecordAorAAAA.from_json(json);
export const dNSRecordAorAAAA_new = dns_name => CSL.DNSRecordAorAAAA.new(dns_name);
export const dNSRecordAorAAAA_record = self => self.record();

// DNSRecordSRV
export const dNSRecordSRV_free = self => () => self.free();
export const dNSRecordSRV_toBytes = self => self.to_bytes();
export const dNSRecordSRV_fromBytes = bytes => CSL.DNSRecordSRV.from_bytes(bytes);
export const dNSRecordSRV_toHex = self => self.to_hex();
export const dNSRecordSRV_fromHex = hex_str => CSL.DNSRecordSRV.from_hex(hex_str);
export const dNSRecordSRV_toJson = self => self.to_json();
export const dNSRecordSRV_toJsValue = self => self.to_js_value();
export const dNSRecordSRV_fromJson = json => CSL.DNSRecordSRV.from_json(json);
export const dNSRecordSRV_new = dns_name => CSL.DNSRecordSRV.new(dns_name);
export const dNSRecordSRV_record = self => self.record();

// DataCost
export const dataCost_free = self => () => self.free();
export const dataCost_newCoinsPerWord = coins_per_word => CSL.DataCost.new_coins_per_word(coins_per_word);
export const dataCost_newCoinsPerByte = coins_per_byte => CSL.DataCost.new_coins_per_byte(coins_per_byte);
export const dataCost_coinsPerByte = self => self.coins_per_byte();

// DataHash
export const dataHash_free = self => () => self.free();
export const dataHash_fromBytes = bytes => CSL.DataHash.from_bytes(bytes);
export const dataHash_toBytes = self => self.to_bytes();
export const dataHash_toBech32 = self => prefix => self.to_bech32(prefix);
export const dataHash_fromBech32 = bech_str => CSL.DataHash.from_bech32(bech_str);
export const dataHash_toHex = self => self.to_hex();
export const dataHash_fromHex = hex => CSL.DataHash.from_hex(hex);

// DatumSource
export const datumSource_free = self => () => self.free();
export const datumSource_new = datum => CSL.DatumSource.new(datum);
export const datumSource_newRefIn = input => CSL.DatumSource.new_ref_input(input);

// Ed25519KeyHash
export const ed25519KeyHash_free = self => () => self.free();
export const ed25519KeyHash_fromBytes = bytes => CSL.Ed25519KeyHash.from_bytes(bytes);
export const ed25519KeyHash_toBytes = self => self.to_bytes();
export const ed25519KeyHash_toBech32 = self => prefix => self.to_bech32(prefix);
export const ed25519KeyHash_fromBech32 = bech_str => CSL.Ed25519KeyHash.from_bech32(bech_str);
export const ed25519KeyHash_toHex = self => self.to_hex();
export const ed25519KeyHash_fromHex = hex => CSL.Ed25519KeyHash.from_hex(hex);

// Ed25519KeyHashes
export const ed25519KeyHashes_free = self => () => self.free();
export const ed25519KeyHashes_toBytes = self => self.to_bytes();
export const ed25519KeyHashes_fromBytes = bytes => CSL.Ed25519KeyHashes.from_bytes(bytes);
export const ed25519KeyHashes_toHex = self => self.to_hex();
export const ed25519KeyHashes_fromHex = hex_str => CSL.Ed25519KeyHashes.from_hex(hex_str);
export const ed25519KeyHashes_toJson = self => self.to_json();
export const ed25519KeyHashes_toJsValue = self => self.to_js_value();
export const ed25519KeyHashes_fromJson = json => CSL.Ed25519KeyHashes.from_json(json);
export const ed25519KeyHashes_new = CSL.Ed25519KeyHashes.new();
export const ed25519KeyHashes_len = self => self.len();
export const ed25519KeyHashes_get = self => index => self.get(index);
export const ed25519KeyHashes_add = self => elem => () => self.add(elem);
export const ed25519KeyHashes_toOption = self => self.to_option();

// Ed25519Signature
export const ed25519Signature_free = self => () => self.free();
export const ed25519Signature_toBytes = self => self.to_bytes();
export const ed25519Signature_toBech32 = self => self.to_bech32();
export const ed25519Signature_toHex = self => self.to_hex();
export const ed25519Signature_fromBech32 = bech32_str => CSL.Ed25519Signature.from_bech32(bech32_str);
export const ed25519Signature_fromHex = input => CSL.Ed25519Signature.from_hex(input);
export const ed25519Signature_fromBytes = bytes => CSL.Ed25519Signature.from_bytes(bytes);

// EnterpriseAddress
export const enterpriseAddress_free = self => () => self.free();
export const enterpriseAddress_new = network => payment => CSL.EnterpriseAddress.new(network, payment);
export const enterpriseAddress_paymentCred = self => self.payment_cred();
export const enterpriseAddress_toAddress = self => self.to_address();
export const enterpriseAddress_fromAddress = addr => CSL.EnterpriseAddress.from_address(addr);

// ExUnitPrices
export const exUnitPrices_free = self => () => self.free();
export const exUnitPrices_toBytes = self => self.to_bytes();
export const exUnitPrices_fromBytes = bytes => CSL.ExUnitPrices.from_bytes(bytes);
export const exUnitPrices_toHex = self => self.to_hex();
export const exUnitPrices_fromHex = hex_str => CSL.ExUnitPrices.from_hex(hex_str);
export const exUnitPrices_toJson = self => self.to_json();
export const exUnitPrices_toJsValue = self => self.to_js_value();
export const exUnitPrices_fromJson = json => CSL.ExUnitPrices.from_json(json);
export const exUnitPrices_memPrice = self => self.mem_price();
export const exUnitPrices_stepPrice = self => self.step_price();
export const exUnitPrices_new = mem_price => step_price => CSL.ExUnitPrices.new(mem_price, step_price);

// ExUnits
export const exUnits_free = self => () => self.free();
export const exUnits_toBytes = self => self.to_bytes();
export const exUnits_fromBytes = bytes => CSL.ExUnits.from_bytes(bytes);
export const exUnits_toHex = self => self.to_hex();
export const exUnits_fromHex = hex_str => CSL.ExUnits.from_hex(hex_str);
export const exUnits_toJson = self => self.to_json();
export const exUnits_toJsValue = self => self.to_js_value();
export const exUnits_fromJson = json => CSL.ExUnits.from_json(json);
export const exUnits_mem = self => self.mem();
export const exUnits_steps = self => self.steps();
export const exUnits_new = mem => steps => CSL.ExUnits.new(mem, steps);

// GeneralTransactionMetadata
export const generalTxMetadata_free = self => () => self.free();
export const generalTxMetadata_toBytes = self => self.to_bytes();
export const generalTxMetadata_fromBytes = bytes => CSL.GeneralTransactionMetadata.from_bytes(bytes);
export const generalTxMetadata_toHex = self => self.to_hex();
export const generalTxMetadata_fromHex = hex_str => CSL.GeneralTransactionMetadata.from_hex(hex_str);
export const generalTxMetadata_toJson = self => self.to_json();
export const generalTxMetadata_toJsValue = self => self.to_js_value();
export const generalTxMetadata_fromJson = json => CSL.GeneralTransactionMetadata.from_json(json);
export const generalTxMetadata_new = CSL.GeneralTransactionMetadata.new();
export const generalTxMetadata_len = self => self.len();
export const generalTxMetadata_insert = self => key => value => self.insert(key, value);
export const generalTxMetadata_get = self => key => self.get(key);
export const generalTxMetadata_keys = self => self.keys();

// GenesisDelegateHash
export const genesisDelegateHash_free = self => () => self.free();
export const genesisDelegateHash_fromBytes = bytes => CSL.GenesisDelegateHash.from_bytes(bytes);
export const genesisDelegateHash_toBytes = self => self.to_bytes();
export const genesisDelegateHash_toBech32 = self => prefix => self.to_bech32(prefix);
export const genesisDelegateHash_fromBech32 = bech_str => CSL.GenesisDelegateHash.from_bech32(bech_str);
export const genesisDelegateHash_toHex = self => self.to_hex();
export const genesisDelegateHash_fromHex = hex => CSL.GenesisDelegateHash.from_hex(hex);

// GenesisHash
export const genesisHash_free = self => () => self.free();
export const genesisHash_fromBytes = bytes => CSL.GenesisHash.from_bytes(bytes);
export const genesisHash_toBytes = self => self.to_bytes();
export const genesisHash_toBech32 = self => prefix => self.to_bech32(prefix);
export const genesisHash_fromBech32 = bech_str => CSL.GenesisHash.from_bech32(bech_str);
export const genesisHash_toHex = self => self.to_hex();
export const genesisHash_fromHex = hex => CSL.GenesisHash.from_hex(hex);

// GenesisHashes
export const genesisHashes_free = self => () => self.free();
export const genesisHashes_toBytes = self => self.to_bytes();
export const genesisHashes_fromBytes = bytes => CSL.GenesisHashes.from_bytes(bytes);
export const genesisHashes_toHex = self => self.to_hex();
export const genesisHashes_fromHex = hex_str => CSL.GenesisHashes.from_hex(hex_str);
export const genesisHashes_toJson = self => self.to_json();
export const genesisHashes_toJsValue = self => self.to_js_value();
export const genesisHashes_fromJson = json => CSL.GenesisHashes.from_json(json);
export const genesisHashes_new = CSL.GenesisHashes.new();
export const genesisHashes_len = self => self.len();
export const genesisHashes_get = self => index => self.get(index);
export const genesisHashes_add = self => elem => () => self.add(elem);

// GenesisKeyDelegation
export const genesisKeyDelegation_free = self => () => self.free();
export const genesisKeyDelegation_toBytes = self => self.to_bytes();
export const genesisKeyDelegation_fromBytes = bytes => CSL.GenesisKeyDelegation.from_bytes(bytes);
export const genesisKeyDelegation_toHex = self => self.to_hex();
export const genesisKeyDelegation_fromHex = hex_str => CSL.GenesisKeyDelegation.from_hex(hex_str);
export const genesisKeyDelegation_toJson = self => self.to_json();
export const genesisKeyDelegation_toJsValue = self => self.to_js_value();
export const genesisKeyDelegation_fromJson = json => CSL.GenesisKeyDelegation.from_json(json);
export const genesisKeyDelegation_genesishash = self => self.genesishash();
export const genesisKeyDelegation_genesisDelegateHash = self => self.genesis_delegate_hash();
export const genesisKeyDelegation_vrfKeyhash = self => self.vrf_keyhash();
export const genesisKeyDelegation_new = genesishash => genesis_delegate_hash => vrf_keyhash => CSL.GenesisKeyDelegation.new(genesishash, genesis_delegate_hash, vrf_keyhash);

// Header
export const header_free = self => () => self.free();
export const header_toBytes = self => self.to_bytes();
export const header_fromBytes = bytes => CSL.Header.from_bytes(bytes);
export const header_toHex = self => self.to_hex();
export const header_fromHex = hex_str => CSL.Header.from_hex(hex_str);
export const header_toJson = self => self.to_json();
export const header_toJsValue = self => self.to_js_value();
export const header_fromJson = json => CSL.Header.from_json(json);
export const header_headerBody = self => self.header_body();
export const header_bodySignature = self => self.body_signature();
export const header_new = header_body => body_signature => CSL.Header.new(header_body, body_signature);

// HeaderBody
export const headerBody_free = self => () => self.free();
export const headerBody_toBytes = self => self.to_bytes();
export const headerBody_fromBytes = bytes => CSL.HeaderBody.from_bytes(bytes);
export const headerBody_toHex = self => self.to_hex();
export const headerBody_fromHex = hex_str => CSL.HeaderBody.from_hex(hex_str);
export const headerBody_toJson = self => self.to_json();
export const headerBody_toJsValue = self => self.to_js_value();
export const headerBody_fromJson = json => CSL.HeaderBody.from_json(json);
export const headerBody_blockNumber = self => self.block_number();
export const headerBody_slot = self => self.slot();
export const headerBody_slotBignum = self => self.slot_bignum();
export const headerBody_prevHash = self => self.prev_hash();
export const headerBody_issuerVkey = self => self.issuer_vkey();
export const headerBody_vrfVkey = self => self.vrf_vkey();
export const headerBody_hasNonceAndLeaderVrf = self => self.has_nonce_and_leader_vrf();
export const headerBody_nonceVrfOrNothing = self => self.nonce_vrf_or_nothing();
export const headerBody_leaderVrfOrNothing = self => self.leader_vrf_or_nothing();
export const headerBody_hasVrfResult = self => self.has_vrf_result();
export const headerBody_vrfResultOrNothing = self => self.vrf_result_or_nothing();
export const headerBody_blockBodySize = self => self.block_body_size();
export const headerBody_blockBodyHash = self => self.block_body_hash();
export const headerBody_operationalCert = self => self.operational_cert();
export const headerBody_protocolVersion = self => self.protocol_version();
export const headerBody_new = block_number => slot => prev_hash => issuer_vkey => vrf_vkey => vrf_result => block_body_size => block_body_hash => operational_cert => protocol_version => CSL.HeaderBody.new(block_number, slot, prev_hash, issuer_vkey, vrf_vkey, vrf_result, block_body_size, block_body_hash, operational_cert, protocol_version);
export const headerBody_newHeaderbody = block_number => slot => prev_hash => issuer_vkey => vrf_vkey => vrf_result => block_body_size => block_body_hash => operational_cert => protocol_version => CSL.HeaderBody.new_headerbody(block_number, slot, prev_hash, issuer_vkey, vrf_vkey, vrf_result, block_body_size, block_body_hash, operational_cert, protocol_version);

// Int
export const int_free = self => () => self.free();
export const int_toBytes = self => self.to_bytes();
export const int_fromBytes = bytes => CSL.Int.from_bytes(bytes);
export const int_toHex = self => self.to_hex();
export const int_fromHex = hex_str => CSL.Int.from_hex(hex_str);
export const int_toJson = self => self.to_json();
export const int_toJsValue = self => self.to_js_value();
export const int_fromJson = json => CSL.Int.from_json(json);
export const int_new = x => CSL.Int.new(x);
export const int_newNegative = x => CSL.Int.new_negative(x);
export const int_newI32 = x => CSL.Int.new_i32(x);
export const int_isPositive = self => self.is_positive();
export const int_asPositive = self => self.as_positive();
export const int_asNegative = self => self.as_negative();
export const int_asI32 = self => self.as_i32();
export const int_asI32OrNothing = self => self.as_i32_or_nothing();
export const int_asI32OrFail = self => self.as_i32_or_fail();
export const int_toStr = self => self.to_str();
export const int_fromStr = string => CSL.Int.from_str(string);

// Ipv4
export const ipv4_free = self => () => self.free();
export const ipv4_toBytes = self => self.to_bytes();
export const ipv4_fromBytes = bytes => CSL.Ipv4.from_bytes(bytes);
export const ipv4_toHex = self => self.to_hex();
export const ipv4_fromHex = hex_str => CSL.Ipv4.from_hex(hex_str);
export const ipv4_toJson = self => self.to_json();
export const ipv4_toJsValue = self => self.to_js_value();
export const ipv4_fromJson = json => CSL.Ipv4.from_json(json);
export const ipv4_new = data => CSL.Ipv4.new(data);
export const ipv4_ip = self => self.ip();

// Ipv6
export const ipv6_free = self => () => self.free();
export const ipv6_toBytes = self => self.to_bytes();
export const ipv6_fromBytes = bytes => CSL.Ipv6.from_bytes(bytes);
export const ipv6_toHex = self => self.to_hex();
export const ipv6_fromHex = hex_str => CSL.Ipv6.from_hex(hex_str);
export const ipv6_toJson = self => self.to_json();
export const ipv6_toJsValue = self => self.to_js_value();
export const ipv6_fromJson = json => CSL.Ipv6.from_json(json);
export const ipv6_new = data => CSL.Ipv6.new(data);
export const ipv6_ip = self => self.ip();

// KESSignature
export const kESSignature_free = self => () => self.free();
export const kESSignature_toBytes = self => self.to_bytes();
export const kESSignature_fromBytes = bytes => CSL.KESSignature.from_bytes(bytes);

// KESVKey
export const kESVKey_free = self => () => self.free();
export const kESVKey_fromBytes = bytes => CSL.KESVKey.from_bytes(bytes);
export const kESVKey_toBytes = self => self.to_bytes();
export const kESVKey_toBech32 = self => prefix => self.to_bech32(prefix);
export const kESVKey_fromBech32 = bech_str => CSL.KESVKey.from_bech32(bech_str);
export const kESVKey_toHex = self => self.to_hex();
export const kESVKey_fromHex = hex => CSL.KESVKey.from_hex(hex);

// Language
export const language_free = self => () => self.free();
export const language_toBytes = self => self.to_bytes();
export const language_fromBytes = bytes => CSL.Language.from_bytes(bytes);
export const language_toHex = self => self.to_hex();
export const language_fromHex = hex_str => CSL.Language.from_hex(hex_str);
export const language_toJson = self => self.to_json();
export const language_toJsValue = self => self.to_js_value();
export const language_fromJson = json => CSL.Language.from_json(json);
export const language_newPlutusV1 = CSL.Language.new_plutus_v1();
export const language_newPlutusV2 = CSL.Language.new_plutus_v2();
export const language_kind = self => self.kind();

// Languages
export const languages_free = self => () => self.free();
export const languages_new = CSL.Languages.new();
export const languages_len = self => self.len();
export const languages_get = self => index => self.get(index);
export const languages_add = self => elem => () => self.add(elem);

// LegacyDaedalusPrivateKey
export const legacyDaedalusPrivateKey_free = self => () => self.free();
export const legacyDaedalusPrivateKey_fromBytes = bytes => CSL.LegacyDaedalusPrivateKey.from_bytes(bytes);
export const legacyDaedalusPrivateKey_asBytes = self => self.as_bytes();
export const legacyDaedalusPrivateKey_chaincode = self => self.chaincode();

// LinearFee
export const linearFee_free = self => () => self.free();
export const linearFee_constant = self => self.constant();
export const linearFee_coefficient = self => self.coefficient();
export const linearFee_new = coefficient => constant => CSL.LinearFee.new(coefficient, constant);

// MIRToStakeCredentials
export const mIRToStakeCredentials_free = self => () => self.free();
export const mIRToStakeCredentials_toBytes = self => self.to_bytes();
export const mIRToStakeCredentials_fromBytes = bytes => CSL.MIRToStakeCredentials.from_bytes(bytes);
export const mIRToStakeCredentials_toHex = self => self.to_hex();
export const mIRToStakeCredentials_fromHex = hex_str => CSL.MIRToStakeCredentials.from_hex(hex_str);
export const mIRToStakeCredentials_toJson = self => self.to_json();
export const mIRToStakeCredentials_toJsValue = self => self.to_js_value();
export const mIRToStakeCredentials_fromJson = json => CSL.MIRToStakeCredentials.from_json(json);
export const mIRToStakeCredentials_new = CSL.MIRToStakeCredentials.new();
export const mIRToStakeCredentials_len = self => self.len();
export const mIRToStakeCredentials_insert = self => cred => delta => self.insert(cred, delta);
export const mIRToStakeCredentials_get = self => cred => self.get(cred);
export const mIRToStakeCredentials_keys = self => self.keys();

// MetadataList
export const metadataList_free = self => () => self.free();
export const metadataList_toBytes = self => self.to_bytes();
export const metadataList_fromBytes = bytes => CSL.MetadataList.from_bytes(bytes);
export const metadataList_toHex = self => self.to_hex();
export const metadataList_fromHex = hex_str => CSL.MetadataList.from_hex(hex_str);
export const metadataList_new = CSL.MetadataList.new();
export const metadataList_len = self => self.len();
export const metadataList_get = self => index => self.get(index);
export const metadataList_add = self => elem => () => self.add(elem);

// MetadataMap
export const metadataMap_free = self => () => self.free();
export const metadataMap_toBytes = self => self.to_bytes();
export const metadataMap_fromBytes = bytes => CSL.MetadataMap.from_bytes(bytes);
export const metadataMap_toHex = self => self.to_hex();
export const metadataMap_fromHex = hex_str => CSL.MetadataMap.from_hex(hex_str);
export const metadataMap_new = CSL.MetadataMap.new();
export const metadataMap_len = self => self.len();
export const metadataMap_insert = self => key => value => self.insert(key, value);
export const metadataMap_insertStr = self => key => value => self.insert_str(key, value);
export const metadataMap_insertI32 = self => key => value => self.insert_i32(key, value);
export const metadataMap_get = self => key => self.get(key);
export const metadataMap_getStr = self => key => self.get_str(key);
export const metadataMap_getI32 = self => key => self.get_i32(key);
export const metadataMap_has = self => key => self.has(key);
export const metadataMap_keys = self => self.keys();

// Mint
export const mint_free = self => () => self.free();
export const mint_toBytes = self => self.to_bytes();
export const mint_fromBytes = bytes => CSL.Mint.from_bytes(bytes);
export const mint_toHex = self => self.to_hex();
export const mint_fromHex = hex_str => CSL.Mint.from_hex(hex_str);
export const mint_toJson = self => self.to_json();
export const mint_toJsValue = self => self.to_js_value();
export const mint_fromJson = json => CSL.Mint.from_json(json);
export const mint_new = CSL.Mint.new();
export const mint_newFromEntry = key => value => CSL.Mint.new_from_entry(key, value);
export const mint_len = self => self.len();
export const mint_insert = self => key => value => self.insert(key, value);
export const mint_get = self => key => self.get(key);
export const mint_keys = self => self.keys();
export const mint_asPositiveMultiasset = self => self.as_positive_multiasset();
export const mint_asNegativeMultiasset = self => self.as_negative_multiasset();

// MintAssets
export const mintAssets_free = self => () => self.free();
export const mintAssets_new = CSL.MintAssets.new();
export const mintAssets_newFromEntry = key => value => CSL.MintAssets.new_from_entry(key, value);
export const mintAssets_len = self => self.len();
export const mintAssets_insert = self => key => value => self.insert(key, value);
export const mintAssets_get = self => key => self.get(key);
export const mintAssets_keys = self => self.keys();

// MoveInstantaneousReward
export const moveInstantaneousReward_free = self => () => self.free();
export const moveInstantaneousReward_toBytes = self => self.to_bytes();
export const moveInstantaneousReward_fromBytes = bytes => CSL.MoveInstantaneousReward.from_bytes(bytes);
export const moveInstantaneousReward_toHex = self => self.to_hex();
export const moveInstantaneousReward_fromHex = hex_str => CSL.MoveInstantaneousReward.from_hex(hex_str);
export const moveInstantaneousReward_toJson = self => self.to_json();
export const moveInstantaneousReward_toJsValue = self => self.to_js_value();
export const moveInstantaneousReward_fromJson = json => CSL.MoveInstantaneousReward.from_json(json);
export const moveInstantaneousReward_newToOtherPot = pot => amount => CSL.MoveInstantaneousReward.new_to_other_pot(pot, amount);
export const moveInstantaneousReward_newToStakeCreds = pot => amounts => CSL.MoveInstantaneousReward.new_to_stake_creds(pot, amounts);
export const moveInstantaneousReward_pot = self => self.pot();
export const moveInstantaneousReward_kind = self => self.kind();
export const moveInstantaneousReward_asToOtherPot = self => self.as_to_other_pot();
export const moveInstantaneousReward_asToStakeCreds = self => self.as_to_stake_creds();

// MoveInstantaneousRewardsCert
export const moveInstantaneousRewardsCert_free = self => () => self.free();
export const moveInstantaneousRewardsCert_toBytes = self => self.to_bytes();
export const moveInstantaneousRewardsCert_fromBytes = bytes => CSL.MoveInstantaneousRewardsCert.from_bytes(bytes);
export const moveInstantaneousRewardsCert_toHex = self => self.to_hex();
export const moveInstantaneousRewardsCert_fromHex = hex_str => CSL.MoveInstantaneousRewardsCert.from_hex(hex_str);
export const moveInstantaneousRewardsCert_toJson = self => self.to_json();
export const moveInstantaneousRewardsCert_toJsValue = self => self.to_js_value();
export const moveInstantaneousRewardsCert_fromJson = json => CSL.MoveInstantaneousRewardsCert.from_json(json);
export const moveInstantaneousRewardsCert_moveInstantaneousReward = self => self.move_instantaneous_reward();
export const moveInstantaneousRewardsCert_new = move_instantaneous_reward => CSL.MoveInstantaneousRewardsCert.new(move_instantaneous_reward);

// MultiAsset
export const multiAsset_free = self => () => self.free();
export const multiAsset_toBytes = self => self.to_bytes();
export const multiAsset_fromBytes = bytes => CSL.MultiAsset.from_bytes(bytes);
export const multiAsset_toHex = self => self.to_hex();
export const multiAsset_fromHex = hex_str => CSL.MultiAsset.from_hex(hex_str);
export const multiAsset_toJson = self => self.to_json();
export const multiAsset_toJsValue = self => self.to_js_value();
export const multiAsset_fromJson = json => CSL.MultiAsset.from_json(json);
export const multiAsset_new = CSL.MultiAsset.new();
export const multiAsset_len = self => self.len();
export const multiAsset_insert = self => policy_id => assets => self.insert(policy_id, assets);
export const multiAsset_get = self => policy_id => self.get(policy_id);
export const multiAsset_setAsset = self => policy_id => asset_name => value => self.set_asset(policy_id, asset_name, value);
export const multiAsset_getAsset = self => policy_id => asset_name => self.get_asset(policy_id, asset_name);
export const multiAsset_keys = self => self.keys();
export const multiAsset_sub = self => rhs_ma => self.sub(rhs_ma);

// MultiHostName
export const multiHostName_free = self => () => self.free();
export const multiHostName_toBytes = self => self.to_bytes();
export const multiHostName_fromBytes = bytes => CSL.MultiHostName.from_bytes(bytes);
export const multiHostName_toHex = self => self.to_hex();
export const multiHostName_fromHex = hex_str => CSL.MultiHostName.from_hex(hex_str);
export const multiHostName_toJson = self => self.to_json();
export const multiHostName_toJsValue = self => self.to_js_value();
export const multiHostName_fromJson = json => CSL.MultiHostName.from_json(json);
export const multiHostName_dnsName = self => self.dns_name();
export const multiHostName_new = dns_name => CSL.MultiHostName.new(dns_name);

// NativeScript
export const nativeScript_free = self => () => self.free();
export const nativeScript_toBytes = self => self.to_bytes();
export const nativeScript_fromBytes = bytes => CSL.NativeScript.from_bytes(bytes);
export const nativeScript_toHex = self => self.to_hex();
export const nativeScript_fromHex = hex_str => CSL.NativeScript.from_hex(hex_str);
export const nativeScript_toJson = self => self.to_json();
export const nativeScript_toJsValue = self => self.to_js_value();
export const nativeScript_fromJson = json => CSL.NativeScript.from_json(json);
export const nativeScript_hash = self => self.hash();
export const nativeScript_newScriptPubkey = script_pubkey => CSL.NativeScript.new_script_pubkey(script_pubkey);
export const nativeScript_newScriptAll = script_all => CSL.NativeScript.new_script_all(script_all);
export const nativeScript_newScriptAny = script_any => CSL.NativeScript.new_script_any(script_any);
export const nativeScript_newScriptNOfK = script_n_of_k => CSL.NativeScript.new_script_n_of_k(script_n_of_k);
export const nativeScript_newTimelockStart = timelock_start => CSL.NativeScript.new_timelock_start(timelock_start);
export const nativeScript_newTimelockExpiry = timelock_expiry => CSL.NativeScript.new_timelock_expiry(timelock_expiry);
export const nativeScript_kind = self => self.kind();
export const nativeScript_asScriptPubkey = self => self.as_script_pubkey();
export const nativeScript_asScriptAll = self => self.as_script_all();
export const nativeScript_asScriptAny = self => self.as_script_any();
export const nativeScript_asScriptNOfK = self => self.as_script_n_of_k();
export const nativeScript_asTimelockStart = self => self.as_timelock_start();
export const nativeScript_asTimelockExpiry = self => self.as_timelock_expiry();
export const nativeScript_getRequiredSigners = self => self.get_required_signers();

// NativeScripts
export const nativeScripts_free = self => () => self.free();
export const nativeScripts_new = CSL.NativeScripts.new();
export const nativeScripts_len = self => self.len();
export const nativeScripts_get = self => index => self.get(index);
export const nativeScripts_add = self => elem => () => self.add(elem);

// NetworkId
export const networkId_free = self => () => self.free();
export const networkId_toBytes = self => self.to_bytes();
export const networkId_fromBytes = bytes => CSL.NetworkId.from_bytes(bytes);
export const networkId_toHex = self => self.to_hex();
export const networkId_fromHex = hex_str => CSL.NetworkId.from_hex(hex_str);
export const networkId_toJson = self => self.to_json();
export const networkId_toJsValue = self => self.to_js_value();
export const networkId_fromJson = json => CSL.NetworkId.from_json(json);
export const networkId_testnet = CSL.NetworkId.testnet();
export const networkId_mainnet = CSL.NetworkId.mainnet();
export const networkId_kind = self => self.kind();

// NetworkInfo
export const networkInfo_free = self => () => self.free();
export const networkInfo_new = network_id => protocol_magic => CSL.NetworkInfo.new(network_id, protocol_magic);
export const networkInfo_networkId = self => self.network_id();
export const networkInfo_protocolMagic = self => self.protocol_magic();
export const networkInfo_testnet = CSL.NetworkInfo.testnet();
export const networkInfo_mainnet = CSL.NetworkInfo.mainnet();

// Nonce
export const nonce_free = self => () => self.free();
export const nonce_toBytes = self => self.to_bytes();
export const nonce_fromBytes = bytes => CSL.Nonce.from_bytes(bytes);
export const nonce_toHex = self => self.to_hex();
export const nonce_fromHex = hex_str => CSL.Nonce.from_hex(hex_str);
export const nonce_toJson = self => self.to_json();
export const nonce_toJsValue = self => self.to_js_value();
export const nonce_fromJson = json => CSL.Nonce.from_json(json);
export const nonce_newIdentity = CSL.Nonce.new_identity();
export const nonce_newFromHash = hash => CSL.Nonce.new_from_hash(hash);
export const nonce_getHash = self => self.get_hash();

// OperationalCert
export const operationalCert_free = self => () => self.free();
export const operationalCert_toBytes = self => self.to_bytes();
export const operationalCert_fromBytes = bytes => CSL.OperationalCert.from_bytes(bytes);
export const operationalCert_toHex = self => self.to_hex();
export const operationalCert_fromHex = hex_str => CSL.OperationalCert.from_hex(hex_str);
export const operationalCert_toJson = self => self.to_json();
export const operationalCert_toJsValue = self => self.to_js_value();
export const operationalCert_fromJson = json => CSL.OperationalCert.from_json(json);
export const operationalCert_hotVkey = self => self.hot_vkey();
export const operationalCert_sequenceNumber = self => self.sequence_number();
export const operationalCert_kesPeriod = self => self.kes_period();
export const operationalCert_sigma = self => self.sigma();
export const operationalCert_new = hot_vkey => sequence_number => kes_period => sigma => CSL.OperationalCert.new(hot_vkey, sequence_number, kes_period, sigma);

// PlutusData
export const plutusData_free = self => () => self.free();
export const plutusData_toBytes = self => self.to_bytes();
export const plutusData_fromBytes = bytes => CSL.PlutusData.from_bytes(bytes);
export const plutusData_toHex = self => self.to_hex();
export const plutusData_fromHex = hex_str => CSL.PlutusData.from_hex(hex_str);
export const plutusData_toJson = self => self.to_json();
export const plutusData_toJsValue = self => self.to_js_value();
export const plutusData_fromJson = json => CSL.PlutusData.from_json(json);
export const plutusData_newConstrPlutusData = constr_plutus_data => CSL.PlutusData.new_constr_plutus_data(constr_plutus_data);
export const plutusData_newEmptyConstrPlutusData = alternative => CSL.PlutusData.new_empty_constr_plutus_data(alternative);
export const plutusData_newMap = map => CSL.PlutusData.new_map(map);
export const plutusData_newList = list => CSL.PlutusData.new_list(list);
export const plutusData_newInteger = integer => CSL.PlutusData.new_integer(integer);
export const plutusData_newBytes = bytes => CSL.PlutusData.new_bytes(bytes);
export const plutusData_kind = self => self.kind();
export const plutusData_asConstrPlutusData = self => self.as_constr_plutus_data();
export const plutusData_asMap = self => self.as_map();
export const plutusData_asList = self => self.as_list();
export const plutusData_asInteger = self => self.as_integer();
export const plutusData_asBytes = self => self.as_bytes();

// PlutusList
export const plutusList_free = self => () => self.free();
export const plutusList_toBytes = self => self.to_bytes();
export const plutusList_fromBytes = bytes => CSL.PlutusList.from_bytes(bytes);
export const plutusList_toHex = self => self.to_hex();
export const plutusList_fromHex = hex_str => CSL.PlutusList.from_hex(hex_str);
export const plutusList_toJson = self => self.to_json();
export const plutusList_toJsValue = self => self.to_js_value();
export const plutusList_fromJson = json => CSL.PlutusList.from_json(json);
export const plutusList_new = CSL.PlutusList.new();
export const plutusList_len = self => self.len();
export const plutusList_get = self => index => self.get(index);
export const plutusList_add = self => elem => () => self.add(elem);

// PlutusMap
export const plutusMap_free = self => () => self.free();
export const plutusMap_toBytes = self => self.to_bytes();
export const plutusMap_fromBytes = bytes => CSL.PlutusMap.from_bytes(bytes);
export const plutusMap_toHex = self => self.to_hex();
export const plutusMap_fromHex = hex_str => CSL.PlutusMap.from_hex(hex_str);
export const plutusMap_toJson = self => self.to_json();
export const plutusMap_toJsValue = self => self.to_js_value();
export const plutusMap_fromJson = json => CSL.PlutusMap.from_json(json);
export const plutusMap_new = CSL.PlutusMap.new();
export const plutusMap_len = self => self.len();
export const plutusMap_insert = self => key => value => self.insert(key, value);
export const plutusMap_get = self => key => self.get(key);
export const plutusMap_keys = self => self.keys();

// PlutusScript
export const plutusScript_free = self => () => self.free();
export const plutusScript_toBytes = self => self.to_bytes();
export const plutusScript_fromBytes = bytes => CSL.PlutusScript.from_bytes(bytes);
export const plutusScript_toHex = self => self.to_hex();
export const plutusScript_fromHex = hex_str => CSL.PlutusScript.from_hex(hex_str);
export const plutusScript_new = bytes => CSL.PlutusScript.new(bytes);
export const plutusScript_newV2 = bytes => CSL.PlutusScript.new_v2(bytes);
export const plutusScript_newWithVersion = bytes => language => CSL.PlutusScript.new_with_version(bytes, language);
export const plutusScript_bytes = self => self.bytes();
export const plutusScript_fromBytesV2 = bytes => CSL.PlutusScript.from_bytes_v2(bytes);
export const plutusScript_fromBytesWithVersion = bytes => language => CSL.PlutusScript.from_bytes_with_version(bytes, language);
export const plutusScript_hash = self => self.hash();
export const plutusScript_languageVersion = self => self.language_version();

// PlutusScriptSource
export const plutusScriptSource_free = self => () => self.free();
export const plutusScriptSource_new = script => CSL.PlutusScriptSource.new(script);
export const plutusScriptSource_newRefIn = script_hash => input => CSL.PlutusScriptSource.new_ref_input(script_hash, input);

// PlutusScripts
export const plutusScripts_free = self => () => self.free();
export const plutusScripts_toBytes = self => self.to_bytes();
export const plutusScripts_fromBytes = bytes => CSL.PlutusScripts.from_bytes(bytes);
export const plutusScripts_toHex = self => self.to_hex();
export const plutusScripts_fromHex = hex_str => CSL.PlutusScripts.from_hex(hex_str);
export const plutusScripts_toJson = self => self.to_json();
export const plutusScripts_toJsValue = self => self.to_js_value();
export const plutusScripts_fromJson = json => CSL.PlutusScripts.from_json(json);
export const plutusScripts_new = CSL.PlutusScripts.new();
export const plutusScripts_len = self => self.len();
export const plutusScripts_get = self => index => self.get(index);
export const plutusScripts_add = self => elem => () => self.add(elem);

// PlutusWitness
export const plutusWitness_free = self => () => self.free();
export const plutusWitness_new = script => datum => redeemer => CSL.PlutusWitness.new(script, datum, redeemer);
export const plutusWitness_newWithRef = script => datum => redeemer => CSL.PlutusWitness.new_with_ref(script, datum, redeemer);
export const plutusWitness_script = self => self.script();
export const plutusWitness_datum = self => self.datum();
export const plutusWitness_redeemer = self => self.redeemer();

// PlutusWitnesses
export const plutusWitnesses_free = self => () => self.free();
export const plutusWitnesses_new = CSL.PlutusWitnesses.new();
export const plutusWitnesses_len = self => self.len();
export const plutusWitnesses_get = self => index => self.get(index);
export const plutusWitnesses_add = self => elem => () => self.add(elem);

// Pointer
export const pointer_free = self => () => self.free();
export const pointer_new = slot => tx_index => cert_index => CSL.Pointer.new(slot, tx_index, cert_index);
export const pointer_newPointer = slot => tx_index => cert_index => CSL.Pointer.new_pointer(slot, tx_index, cert_index);
export const pointer_slot = self => self.slot();
export const pointer_txIndex = self => self.tx_index();
export const pointer_certIndex = self => self.cert_index();
export const pointer_slotBignum = self => self.slot_bignum();
export const pointer_txIndexBignum = self => self.tx_index_bignum();
export const pointer_certIndexBignum = self => self.cert_index_bignum();

// PointerAddress
export const pointerAddress_free = self => () => self.free();
export const pointerAddress_new = network => payment => stake => CSL.PointerAddress.new(network, payment, stake);
export const pointerAddress_paymentCred = self => self.payment_cred();
export const pointerAddress_stakePointer = self => self.stake_pointer();
export const pointerAddress_toAddress = self => self.to_address();
export const pointerAddress_fromAddress = addr => CSL.PointerAddress.from_address(addr);

// PoolMetadata
export const poolMetadata_free = self => () => self.free();
export const poolMetadata_toBytes = self => self.to_bytes();
export const poolMetadata_fromBytes = bytes => CSL.PoolMetadata.from_bytes(bytes);
export const poolMetadata_toHex = self => self.to_hex();
export const poolMetadata_fromHex = hex_str => CSL.PoolMetadata.from_hex(hex_str);
export const poolMetadata_toJson = self => self.to_json();
export const poolMetadata_toJsValue = self => self.to_js_value();
export const poolMetadata_fromJson = json => CSL.PoolMetadata.from_json(json);
export const poolMetadata_url = self => self.url();
export const poolMetadata_poolMetadataHash = self => self.pool_metadata_hash();
export const poolMetadata_new = url => pool_metadata_hash => CSL.PoolMetadata.new(url, pool_metadata_hash);

// PoolMetadataHash
export const poolMetadataHash_free = self => () => self.free();
export const poolMetadataHash_fromBytes = bytes => CSL.PoolMetadataHash.from_bytes(bytes);
export const poolMetadataHash_toBytes = self => self.to_bytes();
export const poolMetadataHash_toBech32 = self => prefix => self.to_bech32(prefix);
export const poolMetadataHash_fromBech32 = bech_str => CSL.PoolMetadataHash.from_bech32(bech_str);
export const poolMetadataHash_toHex = self => self.to_hex();
export const poolMetadataHash_fromHex = hex => CSL.PoolMetadataHash.from_hex(hex);

// PoolParams
export const poolParams_free = self => () => self.free();
export const poolParams_toBytes = self => self.to_bytes();
export const poolParams_fromBytes = bytes => CSL.PoolParams.from_bytes(bytes);
export const poolParams_toHex = self => self.to_hex();
export const poolParams_fromHex = hex_str => CSL.PoolParams.from_hex(hex_str);
export const poolParams_toJson = self => self.to_json();
export const poolParams_toJsValue = self => self.to_js_value();
export const poolParams_fromJson = json => CSL.PoolParams.from_json(json);
export const poolParams_operator = self => self.operator();
export const poolParams_vrfKeyhash = self => self.vrf_keyhash();
export const poolParams_pledge = self => self.pledge();
export const poolParams_cost = self => self.cost();
export const poolParams_margin = self => self.margin();
export const poolParams_rewardAccount = self => self.reward_account();
export const poolParams_poolOwners = self => self.pool_owners();
export const poolParams_relays = self => self.relays();
export const poolParams_poolMetadata = self => self.pool_metadata();
export const poolParams_new = operator => vrf_keyhash => pledge => cost => margin => reward_account => pool_owners => relays => pool_metadata => CSL.PoolParams.new(operator, vrf_keyhash, pledge, cost, margin, reward_account, pool_owners, relays, pool_metadata);

// PoolRegistration
export const poolRegistration_free = self => () => self.free();
export const poolRegistration_toBytes = self => self.to_bytes();
export const poolRegistration_fromBytes = bytes => CSL.PoolRegistration.from_bytes(bytes);
export const poolRegistration_toHex = self => self.to_hex();
export const poolRegistration_fromHex = hex_str => CSL.PoolRegistration.from_hex(hex_str);
export const poolRegistration_toJson = self => self.to_json();
export const poolRegistration_toJsValue = self => self.to_js_value();
export const poolRegistration_fromJson = json => CSL.PoolRegistration.from_json(json);
export const poolRegistration_poolParams = self => self.pool_params();
export const poolRegistration_new = pool_params => CSL.PoolRegistration.new(pool_params);

// PoolRetirement
export const poolRetirement_free = self => () => self.free();
export const poolRetirement_toBytes = self => self.to_bytes();
export const poolRetirement_fromBytes = bytes => CSL.PoolRetirement.from_bytes(bytes);
export const poolRetirement_toHex = self => self.to_hex();
export const poolRetirement_fromHex = hex_str => CSL.PoolRetirement.from_hex(hex_str);
export const poolRetirement_toJson = self => self.to_json();
export const poolRetirement_toJsValue = self => self.to_js_value();
export const poolRetirement_fromJson = json => CSL.PoolRetirement.from_json(json);
export const poolRetirement_poolKeyhash = self => self.pool_keyhash();
export const poolRetirement_epoch = self => self.epoch();
export const poolRetirement_new = pool_keyhash => epoch => CSL.PoolRetirement.new(pool_keyhash, epoch);

// PrivateKey
export const privateKey_free = self => () => self.free();
export const privateKey_toPublic = self => self.to_public();
export const privateKey_generateEd25519 = CSL.PrivateKey.generate_ed25519();
export const privateKey_generateEd25519extended = CSL.PrivateKey.generate_ed25519extended();
export const privateKey_fromBech32 = bech32_str => CSL.PrivateKey.from_bech32(bech32_str);
export const privateKey_toBech32 = self => self.to_bech32();
export const privateKey_asBytes = self => self.as_bytes();
export const privateKey_fromExtendedBytes = bytes => CSL.PrivateKey.from_extended_bytes(bytes);
export const privateKey_fromNormalBytes = bytes => CSL.PrivateKey.from_normal_bytes(bytes);
export const privateKey_sign = self => message => self.sign(message);
export const privateKey_toHex = self => self.to_hex();
export const privateKey_fromHex = hex_str => CSL.PrivateKey.from_hex(hex_str);

// ProposedProtocolParameterUpdates
export const proposedProtocolParameterUpdates_free = self => () => self.free();
export const proposedProtocolParameterUpdates_toBytes = self => self.to_bytes();
export const proposedProtocolParameterUpdates_fromBytes = bytes => CSL.ProposedProtocolParameterUpdates.from_bytes(bytes);
export const proposedProtocolParameterUpdates_toHex = self => self.to_hex();
export const proposedProtocolParameterUpdates_fromHex = hex_str => CSL.ProposedProtocolParameterUpdates.from_hex(hex_str);
export const proposedProtocolParameterUpdates_toJson = self => self.to_json();
export const proposedProtocolParameterUpdates_toJsValue = self => self.to_js_value();
export const proposedProtocolParameterUpdates_fromJson = json => CSL.ProposedProtocolParameterUpdates.from_json(json);
export const proposedProtocolParameterUpdates_new = CSL.ProposedProtocolParameterUpdates.new();
export const proposedProtocolParameterUpdates_len = self => self.len();
export const proposedProtocolParameterUpdates_insert = self => key => value => self.insert(key, value);
export const proposedProtocolParameterUpdates_get = self => key => self.get(key);
export const proposedProtocolParameterUpdates_keys = self => self.keys();

// ProtocolParamUpdate
export const protocolParamUpdate_free = self => () => self.free();
export const protocolParamUpdate_toBytes = self => self.to_bytes();
export const protocolParamUpdate_fromBytes = bytes => CSL.ProtocolParamUpdate.from_bytes(bytes);
export const protocolParamUpdate_toHex = self => self.to_hex();
export const protocolParamUpdate_fromHex = hex_str => CSL.ProtocolParamUpdate.from_hex(hex_str);
export const protocolParamUpdate_toJson = self => self.to_json();
export const protocolParamUpdate_toJsValue = self => self.to_js_value();
export const protocolParamUpdate_fromJson = json => CSL.ProtocolParamUpdate.from_json(json);
export const protocolParamUpdate_setMinfeeA = self => minfee_a => () => self.set_minfee_a(minfee_a);
export const protocolParamUpdate_minfeeA = self => self.minfee_a();
export const protocolParamUpdate_setMinfeeB = self => minfee_b => () => self.set_minfee_b(minfee_b);
export const protocolParamUpdate_minfeeB = self => self.minfee_b();
export const protocolParamUpdate_setMaxBlockBodySize = self => max_block_body_size => () => self.set_max_block_body_size(max_block_body_size);
export const protocolParamUpdate_maxBlockBodySize = self => self.max_block_body_size();
export const protocolParamUpdate_setMaxTxSize = self => max_tx_size => () => self.set_max_tx_size(max_tx_size);
export const protocolParamUpdate_maxTxSize = self => self.max_tx_size();
export const protocolParamUpdate_setMaxBlockHeaderSize = self => max_block_header_size => () => self.set_max_block_header_size(max_block_header_size);
export const protocolParamUpdate_maxBlockHeaderSize = self => self.max_block_header_size();
export const protocolParamUpdate_setKeyDeposit = self => key_deposit => () => self.set_key_deposit(key_deposit);
export const protocolParamUpdate_keyDeposit = self => self.key_deposit();
export const protocolParamUpdate_setPoolDeposit = self => pool_deposit => () => self.set_pool_deposit(pool_deposit);
export const protocolParamUpdate_poolDeposit = self => self.pool_deposit();
export const protocolParamUpdate_setMaxEpoch = self => max_epoch => () => self.set_max_epoch(max_epoch);
export const protocolParamUpdate_maxEpoch = self => self.max_epoch();
export const protocolParamUpdate_setNOpt = self => n_opt => () => self.set_n_opt(n_opt);
export const protocolParamUpdate_nOpt = self => self.n_opt();
export const protocolParamUpdate_setPoolPledgeInfluence = self => pool_pledge_influence => () => self.set_pool_pledge_influence(pool_pledge_influence);
export const protocolParamUpdate_poolPledgeInfluence = self => self.pool_pledge_influence();
export const protocolParamUpdate_setExpansionRate = self => expansion_rate => () => self.set_expansion_rate(expansion_rate);
export const protocolParamUpdate_expansionRate = self => self.expansion_rate();
export const protocolParamUpdate_setTreasuryGrowthRate = self => treasury_growth_rate => () => self.set_treasury_growth_rate(treasury_growth_rate);
export const protocolParamUpdate_treasuryGrowthRate = self => self.treasury_growth_rate();
export const protocolParamUpdate_d = self => self.d();
export const protocolParamUpdate_extraEntropy = self => self.extra_entropy();
export const protocolParamUpdate_setProtocolVersion = self => protocol_version => () => self.set_protocol_version(protocol_version);
export const protocolParamUpdate_protocolVersion = self => self.protocol_version();
export const protocolParamUpdate_setMinPoolCost = self => min_pool_cost => () => self.set_min_pool_cost(min_pool_cost);
export const protocolParamUpdate_minPoolCost = self => self.min_pool_cost();
export const protocolParamUpdate_setAdaPerUtxoByte = self => ada_per_utxo_byte => () => self.set_ada_per_utxo_byte(ada_per_utxo_byte);
export const protocolParamUpdate_adaPerUtxoByte = self => self.ada_per_utxo_byte();
export const protocolParamUpdate_setCostModels = self => cost_models => () => self.set_cost_models(cost_models);
export const protocolParamUpdate_costModels = self => self.cost_models();
export const protocolParamUpdate_setExecutionCosts = self => execution_costs => () => self.set_execution_costs(execution_costs);
export const protocolParamUpdate_executionCosts = self => self.execution_costs();
export const protocolParamUpdate_setMaxTxExUnits = self => max_tx_ex_units => () => self.set_max_tx_ex_units(max_tx_ex_units);
export const protocolParamUpdate_maxTxExUnits = self => self.max_tx_ex_units();
export const protocolParamUpdate_setMaxBlockExUnits = self => max_block_ex_units => () => self.set_max_block_ex_units(max_block_ex_units);
export const protocolParamUpdate_maxBlockExUnits = self => self.max_block_ex_units();
export const protocolParamUpdate_setMaxValueSize = self => max_value_size => () => self.set_max_value_size(max_value_size);
export const protocolParamUpdate_maxValueSize = self => self.max_value_size();
export const protocolParamUpdate_setCollateralPercentage = self => collateral_percentage => () => self.set_collateral_percentage(collateral_percentage);
export const protocolParamUpdate_collateralPercentage = self => self.collateral_percentage();
export const protocolParamUpdate_setMaxCollateralIns = self => max_collateral_inputs => () => self.set_max_collateral_inputs(max_collateral_inputs);
export const protocolParamUpdate_maxCollateralIns = self => self.max_collateral_inputs();
export const protocolParamUpdate_new = CSL.ProtocolParamUpdate.new();

// ProtocolVersion
export const protocolVersion_free = self => () => self.free();
export const protocolVersion_toBytes = self => self.to_bytes();
export const protocolVersion_fromBytes = bytes => CSL.ProtocolVersion.from_bytes(bytes);
export const protocolVersion_toHex = self => self.to_hex();
export const protocolVersion_fromHex = hex_str => CSL.ProtocolVersion.from_hex(hex_str);
export const protocolVersion_toJson = self => self.to_json();
export const protocolVersion_toJsValue = self => self.to_js_value();
export const protocolVersion_fromJson = json => CSL.ProtocolVersion.from_json(json);
export const protocolVersion_major = self => self.major();
export const protocolVersion_minor = self => self.minor();
export const protocolVersion_new = major => minor => CSL.ProtocolVersion.new(major, minor);

// PublicKey
export const publicKey_free = self => () => self.free();
export const publicKey_fromBech32 = bech32_str => CSL.PublicKey.from_bech32(bech32_str);
export const publicKey_toBech32 = self => self.to_bech32();
export const publicKey_asBytes = self => self.as_bytes();
export const publicKey_fromBytes = bytes => CSL.PublicKey.from_bytes(bytes);
export const publicKey_verify = self => data => signature => self.verify(data, signature);
export const publicKey_hash = self => self.hash();
export const publicKey_toHex = self => self.to_hex();
export const publicKey_fromHex = hex_str => CSL.PublicKey.from_hex(hex_str);

// PublicKeys
export const publicKeys_free = self => () => self.free();
export const publicKeys_constructor = self => self.constructor();
export const publicKeys_size = self => self.size();
export const publicKeys_get = self => index => self.get(index);
export const publicKeys_add = self => key => () => self.add(key);

// Redeemer
export const redeemer_free = self => () => self.free();
export const redeemer_toBytes = self => self.to_bytes();
export const redeemer_fromBytes = bytes => CSL.Redeemer.from_bytes(bytes);
export const redeemer_toHex = self => self.to_hex();
export const redeemer_fromHex = hex_str => CSL.Redeemer.from_hex(hex_str);
export const redeemer_toJson = self => self.to_json();
export const redeemer_toJsValue = self => self.to_js_value();
export const redeemer_fromJson = json => CSL.Redeemer.from_json(json);
export const redeemer_tag = self => self.tag();
export const redeemer_index = self => self.index();
export const redeemer_data = self => self.data();
export const redeemer_exUnits = self => self.ex_units();
export const redeemer_new = tag => index => data => ex_units => CSL.Redeemer.new(tag, index, data, ex_units);

// RedeemerTag
export const redeemerTag_free = self => () => self.free();
export const redeemerTag_toBytes = self => self.to_bytes();
export const redeemerTag_fromBytes = bytes => CSL.RedeemerTag.from_bytes(bytes);
export const redeemerTag_toHex = self => self.to_hex();
export const redeemerTag_fromHex = hex_str => CSL.RedeemerTag.from_hex(hex_str);
export const redeemerTag_toJson = self => self.to_json();
export const redeemerTag_toJsValue = self => self.to_js_value();
export const redeemerTag_fromJson = json => CSL.RedeemerTag.from_json(json);
export const redeemerTag_newSpend = CSL.RedeemerTag.new_spend();
export const redeemerTag_newMint = CSL.RedeemerTag.new_mint();
export const redeemerTag_newCert = CSL.RedeemerTag.new_cert();
export const redeemerTag_newReward = CSL.RedeemerTag.new_reward();
export const redeemerTag_kind = self => self.kind();

// Redeemers
export const redeemers_free = self => () => self.free();
export const redeemers_toBytes = self => self.to_bytes();
export const redeemers_fromBytes = bytes => CSL.Redeemers.from_bytes(bytes);
export const redeemers_toHex = self => self.to_hex();
export const redeemers_fromHex = hex_str => CSL.Redeemers.from_hex(hex_str);
export const redeemers_toJson = self => self.to_json();
export const redeemers_toJsValue = self => self.to_js_value();
export const redeemers_fromJson = json => CSL.Redeemers.from_json(json);
export const redeemers_new = CSL.Redeemers.new();
export const redeemers_len = self => self.len();
export const redeemers_get = self => index => self.get(index);
export const redeemers_add = self => elem => () => self.add(elem);
export const redeemers_totalExUnits = self => self.total_ex_units();

// Relay
export const relay_free = self => () => self.free();
export const relay_toBytes = self => self.to_bytes();
export const relay_fromBytes = bytes => CSL.Relay.from_bytes(bytes);
export const relay_toHex = self => self.to_hex();
export const relay_fromHex = hex_str => CSL.Relay.from_hex(hex_str);
export const relay_toJson = self => self.to_json();
export const relay_toJsValue = self => self.to_js_value();
export const relay_fromJson = json => CSL.Relay.from_json(json);
export const relay_newSingleHostAddr = single_host_addr => CSL.Relay.new_single_host_addr(single_host_addr);
export const relay_newSingleHostName = single_host_name => CSL.Relay.new_single_host_name(single_host_name);
export const relay_newMultiHostName = multi_host_name => CSL.Relay.new_multi_host_name(multi_host_name);
export const relay_kind = self => self.kind();
export const relay_asSingleHostAddr = self => self.as_single_host_addr();
export const relay_asSingleHostName = self => self.as_single_host_name();
export const relay_asMultiHostName = self => self.as_multi_host_name();

// Relays
export const relays_free = self => () => self.free();
export const relays_toBytes = self => self.to_bytes();
export const relays_fromBytes = bytes => CSL.Relays.from_bytes(bytes);
export const relays_toHex = self => self.to_hex();
export const relays_fromHex = hex_str => CSL.Relays.from_hex(hex_str);
export const relays_toJson = self => self.to_json();
export const relays_toJsValue = self => self.to_js_value();
export const relays_fromJson = json => CSL.Relays.from_json(json);
export const relays_new = CSL.Relays.new();
export const relays_len = self => self.len();
export const relays_get = self => index => self.get(index);
export const relays_add = self => elem => () => self.add(elem);

// RewardAddress
export const rewardAddress_free = self => () => self.free();
export const rewardAddress_new = network => payment => CSL.RewardAddress.new(network, payment);
export const rewardAddress_paymentCred = self => self.payment_cred();
export const rewardAddress_toAddress = self => self.to_address();
export const rewardAddress_fromAddress = addr => CSL.RewardAddress.from_address(addr);

// RewardAddresses
export const rewardAddresses_free = self => () => self.free();
export const rewardAddresses_toBytes = self => self.to_bytes();
export const rewardAddresses_fromBytes = bytes => CSL.RewardAddresses.from_bytes(bytes);
export const rewardAddresses_toHex = self => self.to_hex();
export const rewardAddresses_fromHex = hex_str => CSL.RewardAddresses.from_hex(hex_str);
export const rewardAddresses_toJson = self => self.to_json();
export const rewardAddresses_toJsValue = self => self.to_js_value();
export const rewardAddresses_fromJson = json => CSL.RewardAddresses.from_json(json);
export const rewardAddresses_new = CSL.RewardAddresses.new();
export const rewardAddresses_len = self => self.len();
export const rewardAddresses_get = self => index => self.get(index);
export const rewardAddresses_add = self => elem => () => self.add(elem);

// ScriptAll
export const scriptAll_free = self => () => self.free();
export const scriptAll_toBytes = self => self.to_bytes();
export const scriptAll_fromBytes = bytes => CSL.ScriptAll.from_bytes(bytes);
export const scriptAll_toHex = self => self.to_hex();
export const scriptAll_fromHex = hex_str => CSL.ScriptAll.from_hex(hex_str);
export const scriptAll_toJson = self => self.to_json();
export const scriptAll_toJsValue = self => self.to_js_value();
export const scriptAll_fromJson = json => CSL.ScriptAll.from_json(json);
export const scriptAll_nativeScripts = self => self.native_scripts();
export const scriptAll_new = native_scripts => CSL.ScriptAll.new(native_scripts);

// ScriptAny
export const scriptAny_free = self => () => self.free();
export const scriptAny_toBytes = self => self.to_bytes();
export const scriptAny_fromBytes = bytes => CSL.ScriptAny.from_bytes(bytes);
export const scriptAny_toHex = self => self.to_hex();
export const scriptAny_fromHex = hex_str => CSL.ScriptAny.from_hex(hex_str);
export const scriptAny_toJson = self => self.to_json();
export const scriptAny_toJsValue = self => self.to_js_value();
export const scriptAny_fromJson = json => CSL.ScriptAny.from_json(json);
export const scriptAny_nativeScripts = self => self.native_scripts();
export const scriptAny_new = native_scripts => CSL.ScriptAny.new(native_scripts);

// ScriptDataHash
export const scriptDataHash_free = self => () => self.free();
export const scriptDataHash_fromBytes = bytes => CSL.ScriptDataHash.from_bytes(bytes);
export const scriptDataHash_toBytes = self => self.to_bytes();
export const scriptDataHash_toBech32 = self => prefix => self.to_bech32(prefix);
export const scriptDataHash_fromBech32 = bech_str => CSL.ScriptDataHash.from_bech32(bech_str);
export const scriptDataHash_toHex = self => self.to_hex();
export const scriptDataHash_fromHex = hex => CSL.ScriptDataHash.from_hex(hex);

// ScriptHash
export const scriptHash_free = self => () => self.free();
export const scriptHash_fromBytes = bytes => CSL.ScriptHash.from_bytes(bytes);
export const scriptHash_toBytes = self => self.to_bytes();
export const scriptHash_toBech32 = self => prefix => self.to_bech32(prefix);
export const scriptHash_fromBech32 = bech_str => CSL.ScriptHash.from_bech32(bech_str);
export const scriptHash_toHex = self => self.to_hex();
export const scriptHash_fromHex = hex => CSL.ScriptHash.from_hex(hex);

// ScriptHashes
export const scriptHashes_free = self => () => self.free();
export const scriptHashes_toBytes = self => self.to_bytes();
export const scriptHashes_fromBytes = bytes => CSL.ScriptHashes.from_bytes(bytes);
export const scriptHashes_toHex = self => self.to_hex();
export const scriptHashes_fromHex = hex_str => CSL.ScriptHashes.from_hex(hex_str);
export const scriptHashes_toJson = self => self.to_json();
export const scriptHashes_toJsValue = self => self.to_js_value();
export const scriptHashes_fromJson = json => CSL.ScriptHashes.from_json(json);
export const scriptHashes_new = CSL.ScriptHashes.new();
export const scriptHashes_len = self => self.len();
export const scriptHashes_get = self => index => self.get(index);
export const scriptHashes_add = self => elem => () => self.add(elem);

// ScriptNOfK
export const scriptNOfK_free = self => () => self.free();
export const scriptNOfK_toBytes = self => self.to_bytes();
export const scriptNOfK_fromBytes = bytes => CSL.ScriptNOfK.from_bytes(bytes);
export const scriptNOfK_toHex = self => self.to_hex();
export const scriptNOfK_fromHex = hex_str => CSL.ScriptNOfK.from_hex(hex_str);
export const scriptNOfK_toJson = self => self.to_json();
export const scriptNOfK_toJsValue = self => self.to_js_value();
export const scriptNOfK_fromJson = json => CSL.ScriptNOfK.from_json(json);
export const scriptNOfK_n = self => self.n();
export const scriptNOfK_nativeScripts = self => self.native_scripts();
export const scriptNOfK_new = n => native_scripts => CSL.ScriptNOfK.new(n, native_scripts);

// ScriptPubkey
export const scriptPubkey_free = self => () => self.free();
export const scriptPubkey_toBytes = self => self.to_bytes();
export const scriptPubkey_fromBytes = bytes => CSL.ScriptPubkey.from_bytes(bytes);
export const scriptPubkey_toHex = self => self.to_hex();
export const scriptPubkey_fromHex = hex_str => CSL.ScriptPubkey.from_hex(hex_str);
export const scriptPubkey_toJson = self => self.to_json();
export const scriptPubkey_toJsValue = self => self.to_js_value();
export const scriptPubkey_fromJson = json => CSL.ScriptPubkey.from_json(json);
export const scriptPubkey_addrKeyhash = self => self.addr_keyhash();
export const scriptPubkey_new = addr_keyhash => CSL.ScriptPubkey.new(addr_keyhash);

// ScriptRef
export const scriptRef_free = self => () => self.free();
export const scriptRef_toBytes = self => self.to_bytes();
export const scriptRef_fromBytes = bytes => CSL.ScriptRef.from_bytes(bytes);
export const scriptRef_toHex = self => self.to_hex();
export const scriptRef_fromHex = hex_str => CSL.ScriptRef.from_hex(hex_str);
export const scriptRef_toJson = self => self.to_json();
export const scriptRef_toJsValue = self => self.to_js_value();
export const scriptRef_fromJson = json => CSL.ScriptRef.from_json(json);
export const scriptRef_newNativeScript = native_script => CSL.ScriptRef.new_native_script(native_script);
export const scriptRef_newPlutusScript = plutus_script => CSL.ScriptRef.new_plutus_script(plutus_script);
export const scriptRef_isNativeScript = self => self.is_native_script();
export const scriptRef_isPlutusScript = self => self.is_plutus_script();
export const scriptRef_nativeScript = self => self.native_script();
export const scriptRef_plutusScript = self => self.plutus_script();

// SingleHostAddr
export const singleHostAddr_free = self => () => self.free();
export const singleHostAddr_toBytes = self => self.to_bytes();
export const singleHostAddr_fromBytes = bytes => CSL.SingleHostAddr.from_bytes(bytes);
export const singleHostAddr_toHex = self => self.to_hex();
export const singleHostAddr_fromHex = hex_str => CSL.SingleHostAddr.from_hex(hex_str);
export const singleHostAddr_toJson = self => self.to_json();
export const singleHostAddr_toJsValue = self => self.to_js_value();
export const singleHostAddr_fromJson = json => CSL.SingleHostAddr.from_json(json);
export const singleHostAddr_port = self => self.port();
export const singleHostAddr_ipv4 = self => self.ipv4();
export const singleHostAddr_ipv6 = self => self.ipv6();
export const singleHostAddr_new = port => ipv4 => ipv6 => CSL.SingleHostAddr.new(port, ipv4, ipv6);

// SingleHostName
export const singleHostName_free = self => () => self.free();
export const singleHostName_toBytes = self => self.to_bytes();
export const singleHostName_fromBytes = bytes => CSL.SingleHostName.from_bytes(bytes);
export const singleHostName_toHex = self => self.to_hex();
export const singleHostName_fromHex = hex_str => CSL.SingleHostName.from_hex(hex_str);
export const singleHostName_toJson = self => self.to_json();
export const singleHostName_toJsValue = self => self.to_js_value();
export const singleHostName_fromJson = json => CSL.SingleHostName.from_json(json);
export const singleHostName_port = self => self.port();
export const singleHostName_dnsName = self => self.dns_name();
export const singleHostName_new = port => dns_name => CSL.SingleHostName.new(port, dns_name);

// StakeCredential
export const stakeCredential_free = self => () => self.free();
export const stakeCredential_fromKeyhash = hash => CSL.StakeCredential.from_keyhash(hash);
export const stakeCredential_fromScripthash = hash => CSL.StakeCredential.from_scripthash(hash);
export const stakeCredential_toKeyhash = self => self.to_keyhash();
export const stakeCredential_toScripthash = self => self.to_scripthash();
export const stakeCredential_kind = self => self.kind();
export const stakeCredential_toBytes = self => self.to_bytes();
export const stakeCredential_fromBytes = bytes => CSL.StakeCredential.from_bytes(bytes);
export const stakeCredential_toHex = self => self.to_hex();
export const stakeCredential_fromHex = hex_str => CSL.StakeCredential.from_hex(hex_str);
export const stakeCredential_toJson = self => self.to_json();
export const stakeCredential_toJsValue = self => self.to_js_value();
export const stakeCredential_fromJson = json => CSL.StakeCredential.from_json(json);

// StakeCredentials
export const stakeCredentials_free = self => () => self.free();
export const stakeCredentials_toBytes = self => self.to_bytes();
export const stakeCredentials_fromBytes = bytes => CSL.StakeCredentials.from_bytes(bytes);
export const stakeCredentials_toHex = self => self.to_hex();
export const stakeCredentials_fromHex = hex_str => CSL.StakeCredentials.from_hex(hex_str);
export const stakeCredentials_toJson = self => self.to_json();
export const stakeCredentials_toJsValue = self => self.to_js_value();
export const stakeCredentials_fromJson = json => CSL.StakeCredentials.from_json(json);
export const stakeCredentials_new = CSL.StakeCredentials.new();
export const stakeCredentials_len = self => self.len();
export const stakeCredentials_get = self => index => self.get(index);
export const stakeCredentials_add = self => elem => () => self.add(elem);

// StakeDelegation
export const stakeDelegation_free = self => () => self.free();
export const stakeDelegation_toBytes = self => self.to_bytes();
export const stakeDelegation_fromBytes = bytes => CSL.StakeDelegation.from_bytes(bytes);
export const stakeDelegation_toHex = self => self.to_hex();
export const stakeDelegation_fromHex = hex_str => CSL.StakeDelegation.from_hex(hex_str);
export const stakeDelegation_toJson = self => self.to_json();
export const stakeDelegation_toJsValue = self => self.to_js_value();
export const stakeDelegation_fromJson = json => CSL.StakeDelegation.from_json(json);
export const stakeDelegation_stakeCredential = self => self.stake_credential();
export const stakeDelegation_poolKeyhash = self => self.pool_keyhash();
export const stakeDelegation_new = stake_credential => pool_keyhash => CSL.StakeDelegation.new(stake_credential, pool_keyhash);

// StakeDeregistration
export const stakeDeregistration_free = self => () => self.free();
export const stakeDeregistration_toBytes = self => self.to_bytes();
export const stakeDeregistration_fromBytes = bytes => CSL.StakeDeregistration.from_bytes(bytes);
export const stakeDeregistration_toHex = self => self.to_hex();
export const stakeDeregistration_fromHex = hex_str => CSL.StakeDeregistration.from_hex(hex_str);
export const stakeDeregistration_toJson = self => self.to_json();
export const stakeDeregistration_toJsValue = self => self.to_js_value();
export const stakeDeregistration_fromJson = json => CSL.StakeDeregistration.from_json(json);
export const stakeDeregistration_stakeCredential = self => self.stake_credential();
export const stakeDeregistration_new = stake_credential => CSL.StakeDeregistration.new(stake_credential);

// StakeRegistration
export const stakeRegistration_free = self => () => self.free();
export const stakeRegistration_toBytes = self => self.to_bytes();
export const stakeRegistration_fromBytes = bytes => CSL.StakeRegistration.from_bytes(bytes);
export const stakeRegistration_toHex = self => self.to_hex();
export const stakeRegistration_fromHex = hex_str => CSL.StakeRegistration.from_hex(hex_str);
export const stakeRegistration_toJson = self => self.to_json();
export const stakeRegistration_toJsValue = self => self.to_js_value();
export const stakeRegistration_fromJson = json => CSL.StakeRegistration.from_json(json);
export const stakeRegistration_stakeCredential = self => self.stake_credential();
export const stakeRegistration_new = stake_credential => CSL.StakeRegistration.new(stake_credential);

// Strings
export const strings_free = self => () => self.free();
export const strings_new = CSL.Strings.new();
export const strings_len = self => self.len();
export const strings_get = self => index => self.get(index);
export const strings_add = self => elem => () => self.add(elem);

// TimelockExpiry
export const timelockExpiry_free = self => () => self.free();
export const timelockExpiry_toBytes = self => self.to_bytes();
export const timelockExpiry_fromBytes = bytes => CSL.TimelockExpiry.from_bytes(bytes);
export const timelockExpiry_toHex = self => self.to_hex();
export const timelockExpiry_fromHex = hex_str => CSL.TimelockExpiry.from_hex(hex_str);
export const timelockExpiry_toJson = self => self.to_json();
export const timelockExpiry_toJsValue = self => self.to_js_value();
export const timelockExpiry_fromJson = json => CSL.TimelockExpiry.from_json(json);
export const timelockExpiry_slot = self => self.slot();
export const timelockExpiry_slotBignum = self => self.slot_bignum();
export const timelockExpiry_new = slot => CSL.TimelockExpiry.new(slot);
export const timelockExpiry_newTimelockexpiry = slot => CSL.TimelockExpiry.new_timelockexpiry(slot);

// TimelockStart
export const timelockStart_free = self => () => self.free();
export const timelockStart_toBytes = self => self.to_bytes();
export const timelockStart_fromBytes = bytes => CSL.TimelockStart.from_bytes(bytes);
export const timelockStart_toHex = self => self.to_hex();
export const timelockStart_fromHex = hex_str => CSL.TimelockStart.from_hex(hex_str);
export const timelockStart_toJson = self => self.to_json();
export const timelockStart_toJsValue = self => self.to_js_value();
export const timelockStart_fromJson = json => CSL.TimelockStart.from_json(json);
export const timelockStart_slot = self => self.slot();
export const timelockStart_slotBignum = self => self.slot_bignum();
export const timelockStart_new = slot => CSL.TimelockStart.new(slot);
export const timelockStart_newTimelockstart = slot => CSL.TimelockStart.new_timelockstart(slot);

// Transaction
export const tx_free = self => () => self.free();
export const tx_toBytes = self => self.to_bytes();
export const tx_fromBytes = bytes => CSL.Transaction.from_bytes(bytes);
export const tx_toHex = self => self.to_hex();
export const tx_fromHex = hex_str => CSL.Transaction.from_hex(hex_str);
export const tx_toJson = self => self.to_json();
export const tx_toJsValue = self => self.to_js_value();
export const tx_fromJson = json => CSL.Transaction.from_json(json);
export const tx_body = self => self.body();
export const tx_witnessSet = self => self.witness_set();
export const tx_isValid = self => self.is_valid();
export const tx_auxiliaryData = self => self.auxiliary_data();
export const tx_setIsValid = self => valid => () => self.set_is_valid(valid);
export const tx_new = body => witness_set => auxiliary_data => CSL.Transaction.new(body, witness_set, auxiliary_data);

// TransactionBodies
export const txBodies_free = self => () => self.free();
export const txBodies_toBytes = self => self.to_bytes();
export const txBodies_fromBytes = bytes => CSL.TransactionBodies.from_bytes(bytes);
export const txBodies_toHex = self => self.to_hex();
export const txBodies_fromHex = hex_str => CSL.TransactionBodies.from_hex(hex_str);
export const txBodies_toJson = self => self.to_json();
export const txBodies_toJsValue = self => self.to_js_value();
export const txBodies_fromJson = json => CSL.TransactionBodies.from_json(json);
export const txBodies_new = CSL.TransactionBodies.new();
export const txBodies_len = self => self.len();
export const txBodies_get = self => index => self.get(index);
export const txBodies_add = self => elem => () => self.add(elem);

// TransactionBody
export const txBody_free = self => () => self.free();
export const txBody_toBytes = self => self.to_bytes();
export const txBody_fromBytes = bytes => CSL.TransactionBody.from_bytes(bytes);
export const txBody_toHex = self => self.to_hex();
export const txBody_fromHex = hex_str => CSL.TransactionBody.from_hex(hex_str);
export const txBody_toJson = self => self.to_json();
export const txBody_toJsValue = self => self.to_js_value();
export const txBody_fromJson = json => CSL.TransactionBody.from_json(json);
export const txBody_ins = self => self.inputs();
export const txBody_outs = self => self.outputs();
export const txBody_fee = self => self.fee();
export const txBody_ttl = self => self.ttl();
export const txBody_ttlBignum = self => self.ttl_bignum();
export const txBody_setTtl = self => ttl => () => self.set_ttl(ttl);
export const txBody_removeTtl = self => () => self.remove_ttl();
export const txBody_setCerts = self => certs => () => self.set_certs(certs);
export const txBody_certs = self => self.certs();
export const txBody_setWithdrawals = self => withdrawals => () => self.set_withdrawals(withdrawals);
export const txBody_withdrawals = self => self.withdrawals();
export const txBody_setUpdate = self => update => () => self.set_update(update);
export const txBody_update = self => self.update();
export const txBody_setAuxiliaryDataHash = self => auxiliary_data_hash => () => self.set_auxiliary_data_hash(auxiliary_data_hash);
export const txBody_auxiliaryDataHash = self => self.auxiliary_data_hash();
export const txBody_setValidityStartInterval = self => validity_start_interval => () => self.set_validity_start_interval(validity_start_interval);
export const txBody_setValidityStartIntervalBignum = self => validity_start_interval => () => self.set_validity_start_interval_bignum(validity_start_interval);
export const txBody_validityStartIntervalBignum = self => self.validity_start_interval_bignum();
export const txBody_validityStartInterval = self => self.validity_start_interval();
export const txBody_setMint = self => mint => () => self.set_mint(mint);
export const txBody_mint = self => self.mint();
export const txBody_multiassets = self => self.multiassets();
export const txBody_setReferenceIns = self => reference_inputs => () => self.set_reference_inputs(reference_inputs);
export const txBody_referenceIns = self => self.reference_inputs();
export const txBody_setScriptDataHash = self => script_data_hash => () => self.set_script_data_hash(script_data_hash);
export const txBody_scriptDataHash = self => self.script_data_hash();
export const txBody_setCollateral = self => collateral => () => self.set_collateral(collateral);
export const txBody_collateral = self => self.collateral();
export const txBody_setRequiredSigners = self => required_signers => () => self.set_required_signers(required_signers);
export const txBody_requiredSigners = self => self.required_signers();
export const txBody_setNetworkId = self => network_id => () => self.set_network_id(network_id);
export const txBody_networkId = self => self.network_id();
export const txBody_setCollateralReturn = self => collateral_return => () => self.set_collateral_return(collateral_return);
export const txBody_collateralReturn = self => self.collateral_return();
export const txBody_setTotalCollateral = self => total_collateral => () => self.set_total_collateral(total_collateral);
export const txBody_totalCollateral = self => self.total_collateral();
export const txBody_new = inputs => outputs => fee => ttl => CSL.TransactionBody.new(inputs, outputs, fee, ttl);
export const txBody_newTxBody = inputs => outputs => fee => CSL.TransactionBody.new_tx_body(inputs, outputs, fee);

// TransactionBuilder
export const txBuilder_free = self => () => self.free();
export const txBuilder_addInsFrom = self => inputs => strategy => () => self.add_inputs_from(inputs, strategy);
export const txBuilder_setIns = self => inputs => () => self.set_inputs(inputs);
export const txBuilder_setCollateral = self => collateral => () => self.set_collateral(collateral);
export const txBuilder_setCollateralReturn = self => collateral_return => () => self.set_collateral_return(collateral_return);
export const txBuilder_setCollateralReturnAndTotal = self => collateral_return => () => self.set_collateral_return_and_total(collateral_return);
export const txBuilder_setTotalCollateral = self => total_collateral => () => self.set_total_collateral(total_collateral);
export const txBuilder_setTotalCollateralAndReturn = self => total_collateral => return_address => () => self.set_total_collateral_and_return(total_collateral, return_address);
export const txBuilder_addReferenceIn = self => reference_input => () => self.add_reference_input(reference_input);
export const txBuilder_addKeyIn = self => hash => input => amount => () => self.add_key_input(hash, input, amount);
export const txBuilder_addScriptIn = self => hash => input => amount => () => self.add_script_input(hash, input, amount);
export const txBuilder_addNativeScriptIn = self => script => input => amount => () => self.add_native_script_input(script, input, amount);
export const txBuilder_addPlutusScriptIn = self => witness => input => amount => () => self.add_plutus_script_input(witness, input, amount);
export const txBuilder_addBootstrapIn = self => hash => input => amount => () => self.add_bootstrap_input(hash, input, amount);
export const txBuilder_addIn = self => address => input => amount => () => self.add_input(address, input, amount);
export const txBuilder_countMissingInScripts = self => self.count_missing_input_scripts();
export const txBuilder_addRequiredNativeInScripts = self => scripts => self.add_required_native_input_scripts(scripts);
export const txBuilder_addRequiredPlutusInScripts = self => scripts => self.add_required_plutus_input_scripts(scripts);
export const txBuilder_getNativeInScripts = self => self.get_native_input_scripts();
export const txBuilder_getPlutusInScripts = self => self.get_plutus_input_scripts();
export const txBuilder_feeForIn = self => address => input => amount => self.fee_for_input(address, input, amount);
export const txBuilder_addOut = self => output => () => self.add_output(output);
export const txBuilder_feeForOut = self => output => self.fee_for_output(output);
export const txBuilder_setFee = self => fee => () => self.set_fee(fee);
export const txBuilder_setTtl = self => ttl => () => self.set_ttl(ttl);
export const txBuilder_setTtlBignum = self => ttl => () => self.set_ttl_bignum(ttl);
export const txBuilder_setValidityStartInterval = self => validity_start_interval => () => self.set_validity_start_interval(validity_start_interval);
export const txBuilder_setValidityStartIntervalBignum = self => validity_start_interval => () => self.set_validity_start_interval_bignum(validity_start_interval);
export const txBuilder_setCerts = self => certs => () => self.set_certs(certs);
export const txBuilder_setWithdrawals = self => withdrawals => () => self.set_withdrawals(withdrawals);
export const txBuilder_getAuxiliaryData = self => self.get_auxiliary_data();
export const txBuilder_setAuxiliaryData = self => auxiliary_data => () => self.set_auxiliary_data(auxiliary_data);
export const txBuilder_setMetadata = self => metadata => () => self.set_metadata(metadata);
export const txBuilder_addMetadatum = self => key => val => () => self.add_metadatum(key, val);
export const txBuilder_addJsonMetadatum = self => key => val => () => self.add_json_metadatum(key, val);
export const txBuilder_addJsonMetadatumWithSchema = self => key => val => schema => () => self.add_json_metadatum_with_schema(key, val, schema);
export const txBuilder_setMint = self => mint => mint_scripts => () => self.set_mint(mint, mint_scripts);
export const txBuilder_getMint = self => self.get_mint();
export const txBuilder_getMintScripts = self => self.get_mint_scripts();
export const txBuilder_setMintAsset = self => policy_script => mint_assets => () => self.set_mint_asset(policy_script, mint_assets);
export const txBuilder_addMintAsset = self => policy_script => asset_name => amount => () => self.add_mint_asset(policy_script, asset_name, amount);
export const txBuilder_addMintAssetAndOut = self => policy_script => asset_name => amount => output_builder => output_coin => () => self.add_mint_asset_and_output(policy_script, asset_name, amount, output_builder, output_coin);
export const txBuilder_addMintAssetAndOutMinRequiredCoin = self => policy_script => asset_name => amount => output_builder => () => self.add_mint_asset_and_output_min_required_coin(policy_script, asset_name, amount, output_builder);
export const txBuilder_new = cfg => () => CSL.TransactionBuilder.new(cfg);
export const txBuilder_getReferenceIns = self => self.get_reference_inputs();
export const txBuilder_getExplicitIn = self => self.get_explicit_input();
export const txBuilder_getImplicitIn = self => self.get_implicit_input();
export const txBuilder_getTotalIn = self => self.get_total_input();
export const txBuilder_getTotalOut = self => self.get_total_output();
export const txBuilder_getExplicitOut = self => self.get_explicit_output();
export const txBuilder_getDeposit = self => self.get_deposit();
export const txBuilder_getFeeIfSet = self => self.get_fee_if_set();
export const txBuilder_addChangeIfNeeded = self => address => self.add_change_if_needed(address);
export const txBuilder_calcScriptDataHash = self => cost_models => () => self.calc_script_data_hash(cost_models);
export const txBuilder_setScriptDataHash = self => hash => () => self.set_script_data_hash(hash);
export const txBuilder_removeScriptDataHash = self => () => self.remove_script_data_hash();
export const txBuilder_addRequiredSigner = self => key => () => self.add_required_signer(key);
export const txBuilder_fullSize = self => self.full_size();
export const txBuilder_outSizes = self => self.output_sizes();
export const txBuilder_build = self => self.build();
export const txBuilder_buildTx = self => self.build_tx();
export const txBuilder_buildTxUnsafe = self => self.build_tx_unsafe();
export const txBuilder_minFee = self => self.min_fee();

// TransactionBuilderConfig
export const txBuilderConfig_free = self => () => self.free();

// TransactionBuilderConfigBuilder
export const txBuilderConfigBuilder_free = self => () => self.free();
export const txBuilderConfigBuilder_new = CSL.TransactionBuilderConfigBuilder.new();
export const txBuilderConfigBuilder_feeAlgo = self => fee_algo => self.fee_algo(fee_algo);
export const txBuilderConfigBuilder_coinsPerUtxoWord = self => coins_per_utxo_word => self.coins_per_utxo_word(coins_per_utxo_word);
export const txBuilderConfigBuilder_coinsPerUtxoByte = self => coins_per_utxo_byte => self.coins_per_utxo_byte(coins_per_utxo_byte);
export const txBuilderConfigBuilder_exUnitPrices = self => ex_unit_prices => self.ex_unit_prices(ex_unit_prices);
export const txBuilderConfigBuilder_poolDeposit = self => pool_deposit => self.pool_deposit(pool_deposit);
export const txBuilderConfigBuilder_keyDeposit = self => key_deposit => self.key_deposit(key_deposit);
export const txBuilderConfigBuilder_maxValueSize = self => max_value_size => self.max_value_size(max_value_size);
export const txBuilderConfigBuilder_maxTxSize = self => max_tx_size => self.max_tx_size(max_tx_size);
export const txBuilderConfigBuilder_preferPureChange = self => prefer_pure_change => self.prefer_pure_change(prefer_pure_change);
export const txBuilderConfigBuilder_build = self => self.build();

// TransactionHash
export const txHash_free = self => () => self.free();
export const txHash_fromBytes = bytes => CSL.TransactionHash.from_bytes(bytes);
export const txHash_toBytes = self => self.to_bytes();
export const txHash_toBech32 = self => prefix => self.to_bech32(prefix);
export const txHash_fromBech32 = bech_str => CSL.TransactionHash.from_bech32(bech_str);
export const txHash_toHex = self => self.to_hex();
export const txHash_fromHex = hex => CSL.TransactionHash.from_hex(hex);

// TransactionInput
export const txIn_free = self => () => self.free();
export const txIn_toBytes = self => self.to_bytes();
export const txIn_fromBytes = bytes => CSL.TransactionInput.from_bytes(bytes);
export const txIn_toHex = self => self.to_hex();
export const txIn_fromHex = hex_str => CSL.TransactionInput.from_hex(hex_str);
export const txIn_toJson = self => self.to_json();
export const txIn_toJsValue = self => self.to_js_value();
export const txIn_fromJson = json => CSL.TransactionInput.from_json(json);
export const txIn_txId = self => self.transaction_id();
export const txIn_index = self => self.index();
export const txIn_new = transaction_id => index => CSL.TransactionInput.new(transaction_id, index);

// TransactionInputs
export const txIns_free = self => () => self.free();
export const txIns_toBytes = self => self.to_bytes();
export const txIns_fromBytes = bytes => CSL.TransactionInputs.from_bytes(bytes);
export const txIns_toHex = self => self.to_hex();
export const txIns_fromHex = hex_str => CSL.TransactionInputs.from_hex(hex_str);
export const txIns_toJson = self => self.to_json();
export const txIns_toJsValue = self => self.to_js_value();
export const txIns_fromJson = json => CSL.TransactionInputs.from_json(json);
export const txIns_new = CSL.TransactionInputs.new();
export const txIns_len = self => self.len();
export const txIns_get = self => index => self.get(index);
export const txIns_add = self => elem => () => self.add(elem);
export const txIns_toOption = self => self.to_option();

// TransactionMetadatum
export const txMetadatum_free = self => () => self.free();
export const txMetadatum_toBytes = self => self.to_bytes();
export const txMetadatum_fromBytes = bytes => CSL.TransactionMetadatum.from_bytes(bytes);
export const txMetadatum_toHex = self => self.to_hex();
export const txMetadatum_fromHex = hex_str => CSL.TransactionMetadatum.from_hex(hex_str);
export const txMetadatum_newMap = map => CSL.TransactionMetadatum.new_map(map);
export const txMetadatum_newList = list => CSL.TransactionMetadatum.new_list(list);
export const txMetadatum_newInt = int => CSL.TransactionMetadatum.new_int(int);
export const txMetadatum_newBytes = bytes => CSL.TransactionMetadatum.new_bytes(bytes);
export const txMetadatum_newText = text => CSL.TransactionMetadatum.new_text(text);
export const txMetadatum_kind = self => self.kind();
export const txMetadatum_asMap = self => self.as_map();
export const txMetadatum_asList = self => self.as_list();
export const txMetadatum_asInt = self => self.as_int();
export const txMetadatum_asBytes = self => self.as_bytes();
export const txMetadatum_asText = self => self.as_text();

// TransactionMetadatumLabels
export const txMetadatumLabels_free = self => () => self.free();
export const txMetadatumLabels_toBytes = self => self.to_bytes();
export const txMetadatumLabels_fromBytes = bytes => CSL.TransactionMetadatumLabels.from_bytes(bytes);
export const txMetadatumLabels_toHex = self => self.to_hex();
export const txMetadatumLabels_fromHex = hex_str => CSL.TransactionMetadatumLabels.from_hex(hex_str);
export const txMetadatumLabels_new = CSL.TransactionMetadatumLabels.new();
export const txMetadatumLabels_len = self => self.len();
export const txMetadatumLabels_get = self => index => self.get(index);
export const txMetadatumLabels_add = self => elem => () => self.add(elem);

// TransactionOutput
export const txOut_free = self => () => self.free();
export const txOut_toBytes = self => self.to_bytes();
export const txOut_fromBytes = bytes => CSL.TransactionOutput.from_bytes(bytes);
export const txOut_toHex = self => self.to_hex();
export const txOut_fromHex = hex_str => CSL.TransactionOutput.from_hex(hex_str);
export const txOut_toJson = self => self.to_json();
export const txOut_toJsValue = self => self.to_js_value();
export const txOut_fromJson = json => CSL.TransactionOutput.from_json(json);
export const txOut_address = self => self.address();
export const txOut_amount = self => self.amount();
export const txOut_dataHash = self => self.data_hash();
export const txOut_plutusData = self => self.plutus_data();
export const txOut_scriptRef = self => self.script_ref();
export const txOut_setScriptRef = self => script_ref => () => self.set_script_ref(script_ref);
export const txOut_setPlutusData = self => data => () => self.set_plutus_data(data);
export const txOut_setDataHash = self => data_hash => () => self.set_data_hash(data_hash);
export const txOut_hasPlutusData = self => self.has_plutus_data();
export const txOut_hasDataHash = self => self.has_data_hash();
export const txOut_hasScriptRef = self => self.has_script_ref();
export const txOut_new = address => amount => CSL.TransactionOutput.new(address, amount);

// TransactionOutputAmountBuilder
export const txOutAmountBuilder_free = self => () => self.free();
export const txOutAmountBuilder_withValue = self => amount => self.with_value(amount);
export const txOutAmountBuilder_withCoin = self => coin => self.with_coin(coin);
export const txOutAmountBuilder_withCoinAndAsset = self => coin => multiasset => self.with_coin_and_asset(coin, multiasset);
export const txOutAmountBuilder_withAssetAndMinRequiredCoin = self => multiasset => coins_per_utxo_word => self.with_asset_and_min_required_coin(multiasset, coins_per_utxo_word);
export const txOutAmountBuilder_withAssetAndMinRequiredCoinByUtxoCost = self => multiasset => data_cost => self.with_asset_and_min_required_coin_by_utxo_cost(multiasset, data_cost);
export const txOutAmountBuilder_build = self => self.build();

// TransactionOutputBuilder
export const txOutBuilder_free = self => () => self.free();
export const txOutBuilder_new = CSL.TransactionOutputBuilder.new();
export const txOutBuilder_withAddress = self => address => self.with_address(address);
export const txOutBuilder_withDataHash = self => data_hash => self.with_data_hash(data_hash);
export const txOutBuilder_withPlutusData = self => data => self.with_plutus_data(data);
export const txOutBuilder_withScriptRef = self => script_ref => self.with_script_ref(script_ref);
export const txOutBuilder_next = self => self.next();

// TransactionOutputs
export const txOuts_free = self => () => self.free();
export const txOuts_toBytes = self => self.to_bytes();
export const txOuts_fromBytes = bytes => CSL.TransactionOutputs.from_bytes(bytes);
export const txOuts_toHex = self => self.to_hex();
export const txOuts_fromHex = hex_str => CSL.TransactionOutputs.from_hex(hex_str);
export const txOuts_toJson = self => self.to_json();
export const txOuts_toJsValue = self => self.to_js_value();
export const txOuts_fromJson = json => CSL.TransactionOutputs.from_json(json);
export const txOuts_new = CSL.TransactionOutputs.new();
export const txOuts_len = self => self.len();
export const txOuts_get = self => index => self.get(index);
export const txOuts_add = self => elem => () => self.add(elem);

// TransactionUnspentOutput
export const txUnspentOut_free = self => () => self.free();
export const txUnspentOut_toBytes = self => self.to_bytes();
export const txUnspentOut_fromBytes = bytes => CSL.TransactionUnspentOutput.from_bytes(bytes);
export const txUnspentOut_toHex = self => self.to_hex();
export const txUnspentOut_fromHex = hex_str => CSL.TransactionUnspentOutput.from_hex(hex_str);
export const txUnspentOut_toJson = self => self.to_json();
export const txUnspentOut_toJsValue = self => self.to_js_value();
export const txUnspentOut_fromJson = json => CSL.TransactionUnspentOutput.from_json(json);
export const txUnspentOut_new = input => output => CSL.TransactionUnspentOutput.new(input, output);
export const txUnspentOut_in = self => self.input();
export const txUnspentOut_out = self => self.output();

// TransactionUnspentOutputs
export const txUnspentOuts_free = self => () => self.free();
export const txUnspentOuts_toJson = self => self.to_json();
export const txUnspentOuts_toJsValue = self => self.to_js_value();
export const txUnspentOuts_fromJson = json => CSL.TransactionUnspentOutputs.from_json(json);
export const txUnspentOuts_new = CSL.TransactionUnspentOutputs.new();
export const txUnspentOuts_len = self => self.len();
export const txUnspentOuts_get = self => index => self.get(index);
export const txUnspentOuts_add = self => elem => () => self.add(elem);

// TransactionWitnessSet
export const txWitnessSet_free = self => () => self.free();
export const txWitnessSet_toBytes = self => self.to_bytes();
export const txWitnessSet_fromBytes = bytes => CSL.TransactionWitnessSet.from_bytes(bytes);
export const txWitnessSet_toHex = self => self.to_hex();
export const txWitnessSet_fromHex = hex_str => CSL.TransactionWitnessSet.from_hex(hex_str);
export const txWitnessSet_toJson = self => self.to_json();
export const txWitnessSet_toJsValue = self => self.to_js_value();
export const txWitnessSet_fromJson = json => CSL.TransactionWitnessSet.from_json(json);
export const txWitnessSet_setVkeys = self => vkeys => () => self.set_vkeys(vkeys);
export const txWitnessSet_vkeys = self => self.vkeys();
export const txWitnessSet_setNativeScripts = self => native_scripts => () => self.set_native_scripts(native_scripts);
export const txWitnessSet_nativeScripts = self => self.native_scripts();
export const txWitnessSet_setBootstraps = self => bootstraps => () => self.set_bootstraps(bootstraps);
export const txWitnessSet_bootstraps = self => self.bootstraps();
export const txWitnessSet_setPlutusScripts = self => plutus_scripts => () => self.set_plutus_scripts(plutus_scripts);
export const txWitnessSet_plutusScripts = self => self.plutus_scripts();
export const txWitnessSet_setPlutusData = self => plutus_data => () => self.set_plutus_data(plutus_data);
export const txWitnessSet_plutusData = self => self.plutus_data();
export const txWitnessSet_setRedeemers = self => redeemers => () => self.set_redeemers(redeemers);
export const txWitnessSet_redeemers = self => self.redeemers();
export const txWitnessSet_new = CSL.TransactionWitnessSet.new();

// TransactionWitnessSets
export const txWitnessSets_free = self => () => self.free();
export const txWitnessSets_toBytes = self => self.to_bytes();
export const txWitnessSets_fromBytes = bytes => CSL.TransactionWitnessSets.from_bytes(bytes);
export const txWitnessSets_toHex = self => self.to_hex();
export const txWitnessSets_fromHex = hex_str => CSL.TransactionWitnessSets.from_hex(hex_str);
export const txWitnessSets_toJson = self => self.to_json();
export const txWitnessSets_toJsValue = self => self.to_js_value();
export const txWitnessSets_fromJson = json => CSL.TransactionWitnessSets.from_json(json);
export const txWitnessSets_new = CSL.TransactionWitnessSets.new();
export const txWitnessSets_len = self => self.len();
export const txWitnessSets_get = self => index => self.get(index);
export const txWitnessSets_add = self => elem => () => self.add(elem);

// TxBuilderConstants
export const txBuilderConstants_free = self => () => self.free();
export const txBuilderConstants_plutusDefaultCostModels = CSL.TxBuilderConstants.plutus_default_cost_models();
export const txBuilderConstants_plutusAlonzoCostModels = CSL.TxBuilderConstants.plutus_alonzo_cost_models();
export const txBuilderConstants_plutusVasilCostModels = CSL.TxBuilderConstants.plutus_vasil_cost_models();

// TxInputsBuilder
export const txInsBuilder_free = self => () => self.free();
export const txInsBuilder_new = () => CSL.TxInputsBuilder.new();
export const txInsBuilder_addKeyIn = self => hash => input => amount => () => self.add_key_input(hash, input, amount);
export const txInsBuilder_addScriptIn = self => hash => input => amount => () => self.add_script_input(hash, input, amount);
export const txInsBuilder_addNativeScriptIn = self => script => input => amount => () => self.add_native_script_input(script, input, amount);
export const txInsBuilder_addPlutusScriptIn = self => witness => input => amount => () => self.add_plutus_script_input(witness, input, amount);
export const txInsBuilder_addBootstrapIn = self => hash => input => amount => () => self.add_bootstrap_input(hash, input, amount);
export const txInsBuilder_addIn = self => address => input => amount => () => self.add_input(address, input, amount);
export const txInsBuilder_countMissingInScripts = self => self.count_missing_input_scripts();
export const txInsBuilder_addRequiredNativeInScripts = self => scripts => self.add_required_native_input_scripts(scripts);
export const txInsBuilder_addRequiredPlutusInScripts = self => scripts => self.add_required_plutus_input_scripts(scripts);
export const txInsBuilder_getRefIns = self => self.get_ref_inputs();
export const txInsBuilder_getNativeInScripts = self => self.get_native_input_scripts();
export const txInsBuilder_getPlutusInScripts = self => self.get_plutus_input_scripts();
export const txInsBuilder_len = self => self.len();
export const txInsBuilder_addRequiredSigner = self => key => () => self.add_required_signer(key);
export const txInsBuilder_addRequiredSigners = self => keys => () => self.add_required_signers(keys);
export const txInsBuilder_totalValue = self => self.total_value();
export const txInsBuilder_ins = self => self.inputs();
export const txInsBuilder_insOption = self => self.inputs_option();

// URL
export const uRL_free = self => () => self.free();
export const uRL_toBytes = self => self.to_bytes();
export const uRL_fromBytes = bytes => CSL.URL.from_bytes(bytes);
export const uRL_toHex = self => self.to_hex();
export const uRL_fromHex = hex_str => CSL.URL.from_hex(hex_str);
export const uRL_toJson = self => self.to_json();
export const uRL_toJsValue = self => self.to_js_value();
export const uRL_fromJson = json => CSL.URL.from_json(json);
export const uRL_new = url => CSL.URL.new(url);
export const uRL_url = self => self.url();

// UnitInterval
export const unitInterval_free = self => () => self.free();
export const unitInterval_toBytes = self => self.to_bytes();
export const unitInterval_fromBytes = bytes => CSL.UnitInterval.from_bytes(bytes);
export const unitInterval_toHex = self => self.to_hex();
export const unitInterval_fromHex = hex_str => CSL.UnitInterval.from_hex(hex_str);
export const unitInterval_toJson = self => self.to_json();
export const unitInterval_toJsValue = self => self.to_js_value();
export const unitInterval_fromJson = json => CSL.UnitInterval.from_json(json);
export const unitInterval_numerator = self => self.numerator();
export const unitInterval_denominator = self => self.denominator();
export const unitInterval_new = numerator => denominator => CSL.UnitInterval.new(numerator, denominator);

// Update
export const update_free = self => () => self.free();
export const update_toBytes = self => self.to_bytes();
export const update_fromBytes = bytes => CSL.Update.from_bytes(bytes);
export const update_toHex = self => self.to_hex();
export const update_fromHex = hex_str => CSL.Update.from_hex(hex_str);
export const update_toJson = self => self.to_json();
export const update_toJsValue = self => self.to_js_value();
export const update_fromJson = json => CSL.Update.from_json(json);
export const update_proposedProtocolParameterUpdates = self => self.proposed_protocol_parameter_updates();
export const update_epoch = self => self.epoch();
export const update_new = proposed_protocol_parameter_updates => epoch => CSL.Update.new(proposed_protocol_parameter_updates, epoch);

// VRFCert
export const vRFCert_free = self => () => self.free();
export const vRFCert_toBytes = self => self.to_bytes();
export const vRFCert_fromBytes = bytes => CSL.VRFCert.from_bytes(bytes);
export const vRFCert_toHex = self => self.to_hex();
export const vRFCert_fromHex = hex_str => CSL.VRFCert.from_hex(hex_str);
export const vRFCert_toJson = self => self.to_json();
export const vRFCert_toJsValue = self => self.to_js_value();
export const vRFCert_fromJson = json => CSL.VRFCert.from_json(json);
export const vRFCert_out = self => self.output();
export const vRFCert_proof = self => self.proof();
export const vRFCert_new = output => proof => CSL.VRFCert.new(output, proof);

// VRFKeyHash
export const vRFKeyHash_free = self => () => self.free();
export const vRFKeyHash_fromBytes = bytes => CSL.VRFKeyHash.from_bytes(bytes);
export const vRFKeyHash_toBytes = self => self.to_bytes();
export const vRFKeyHash_toBech32 = self => prefix => self.to_bech32(prefix);
export const vRFKeyHash_fromBech32 = bech_str => CSL.VRFKeyHash.from_bech32(bech_str);
export const vRFKeyHash_toHex = self => self.to_hex();
export const vRFKeyHash_fromHex = hex => CSL.VRFKeyHash.from_hex(hex);

// VRFVKey
export const vRFVKey_free = self => () => self.free();
export const vRFVKey_fromBytes = bytes => CSL.VRFVKey.from_bytes(bytes);
export const vRFVKey_toBytes = self => self.to_bytes();
export const vRFVKey_toBech32 = self => prefix => self.to_bech32(prefix);
export const vRFVKey_fromBech32 = bech_str => CSL.VRFVKey.from_bech32(bech_str);
export const vRFVKey_toHex = self => self.to_hex();
export const vRFVKey_fromHex = hex => CSL.VRFVKey.from_hex(hex);

// Value
export const value_free = self => () => self.free();
export const value_toBytes = self => self.to_bytes();
export const value_fromBytes = bytes => CSL.Value.from_bytes(bytes);
export const value_toHex = self => self.to_hex();
export const value_fromHex = hex_str => CSL.Value.from_hex(hex_str);
export const value_toJson = self => self.to_json();
export const value_toJsValue = self => self.to_js_value();
export const value_fromJson = json => CSL.Value.from_json(json);
export const value_new = coin => CSL.Value.new(coin);
export const value_newFromAssets = multiasset => CSL.Value.new_from_assets(multiasset);
export const value_newWithAssets = coin => multiasset => CSL.Value.new_with_assets(coin, multiasset);
export const value_zero = CSL.Value.zero();
export const value_isZero = self => self.is_zero();
export const value_coin = self => self.coin();
export const value_setCoin = self => coin => () => self.set_coin(coin);
export const value_multiasset = self => self.multiasset();
export const value_setMultiasset = self => multiasset => () => self.set_multiasset(multiasset);
export const value_checkedAdd = self => rhs => self.checked_add(rhs);
export const value_checkedSub = self => rhs_value => self.checked_sub(rhs_value);
export const value_clampedSub = self => rhs_value => self.clamped_sub(rhs_value);
export const value_compare = self => rhs_value => self.compare(rhs_value);

// Vkey
export const vkey_free = self => () => self.free();
export const vkey_toBytes = self => self.to_bytes();
export const vkey_fromBytes = bytes => CSL.Vkey.from_bytes(bytes);
export const vkey_toHex = self => self.to_hex();
export const vkey_fromHex = hex_str => CSL.Vkey.from_hex(hex_str);
export const vkey_toJson = self => self.to_json();
export const vkey_toJsValue = self => self.to_js_value();
export const vkey_fromJson = json => CSL.Vkey.from_json(json);
export const vkey_new = pk => CSL.Vkey.new(pk);
export const vkey_publicKey = self => self.public_key();

// Vkeys
export const vkeys_free = self => () => self.free();
export const vkeys_new = CSL.Vkeys.new();
export const vkeys_len = self => self.len();
export const vkeys_get = self => index => self.get(index);
export const vkeys_add = self => elem => () => self.add(elem);

// Vkeywitness
export const vkeywitness_free = self => () => self.free();
export const vkeywitness_toBytes = self => self.to_bytes();
export const vkeywitness_fromBytes = bytes => CSL.Vkeywitness.from_bytes(bytes);
export const vkeywitness_toHex = self => self.to_hex();
export const vkeywitness_fromHex = hex_str => CSL.Vkeywitness.from_hex(hex_str);
export const vkeywitness_toJson = self => self.to_json();
export const vkeywitness_toJsValue = self => self.to_js_value();
export const vkeywitness_fromJson = json => CSL.Vkeywitness.from_json(json);
export const vkeywitness_new = vkey => signature => CSL.Vkeywitness.new(vkey, signature);
export const vkeywitness_vkey = self => self.vkey();
export const vkeywitness_signature = self => self.signature();

// Vkeywitnesses
export const vkeywitnesses_free = self => () => self.free();
export const vkeywitnesses_new = CSL.Vkeywitnesses.new();
export const vkeywitnesses_len = self => self.len();
export const vkeywitnesses_get = self => index => self.get(index);
export const vkeywitnesses_add = self => elem => () => self.add(elem);

// Withdrawals
export const withdrawals_free = self => () => self.free();
export const withdrawals_toBytes = self => self.to_bytes();
export const withdrawals_fromBytes = bytes => CSL.Withdrawals.from_bytes(bytes);
export const withdrawals_toHex = self => self.to_hex();
export const withdrawals_fromHex = hex_str => CSL.Withdrawals.from_hex(hex_str);
export const withdrawals_toJson = self => self.to_json();
export const withdrawals_toJsValue = self => self.to_js_value();
export const withdrawals_fromJson = json => CSL.Withdrawals.from_json(json);
export const withdrawals_new = CSL.Withdrawals.new();
export const withdrawals_len = self => self.len();
export const withdrawals_insert = self => key => value => self.insert(key, value);
export const withdrawals_get = self => key => self.get(key);
export const withdrawals_keys = self => self.keys();


import { Network } from './networks';
import * as networks from './networks';
import * as payments from './payments';
import * as bscript from './script';
import * as types from './types';

const bech32 = require('bech32');
const bs58check = require('bs58check');
const typeforce = require('typeforce');

export interface Base58CheckResult {
  hash: Buffer;
  version: number;
}

export interface Bech32Result {
  version: number;
  prefix: string;
  data: Buffer;
}

export interface FindAddressTypeResult {
  version: number;
  confidential: boolean;
}

export function findAddressType(
  address: string,
  network: Network,
): FindAddressTypeResult {
  // TODO: native segwit
  if (address.startsWith('el') || address.startsWith('ert'))
    throw new TypeError('Native segwit is not supported yet');

  const payload = bs58check.decode(address);

  // Check if length matches uncofindetial or confidential address
  if (payload.length !== 21 && payload.length !== 55)
    throw new TypeError(address + ' is invalid');

  // For an unconfidential address the first byte defines its type.
  // For a confidential address, the first byte contains the blinding prefix,
  // while the second byte contains the address type
  const prefix = payload.readUInt8(0);
  if (prefix === network.confidentialPrefix)
    return { confidential: true, version: payload.readUInt8(1) };
  return { confidential: false, version: prefix };
}

export function blindingPubKeyFromConfidentialAddress(address: string): Buffer {
  if (address.startsWith('el') || address.startsWith('ert'))
    throw new TypeError('Native segwit is not support yet');

  const payload = bs58check.decode(address);

  // Confidential addresses have fixed length
  if (payload.length < 55) throw new TypeError(address + ' is too short');
  if (payload.length > 55) throw new TypeError(address + ' is too long');

  // Blinded decoded haddress has the form:
  // BLIND_PREFIX|ADDRESS_PREFIX|BLIND_KEY|SCRIPT_HASH
  // Prefixes are 1 byte long, thus blinding key always starts at 3rd byte
  return payload.slice(2, 35);
}

export function confidentialAddressFromAddress(
  address: string,
  blindkey: string,
  network: Network,
): string {
  if (address.startsWith(network.bech32))
    throw new TypeError('Native segwit is not supported yet');

  const payload = bs58check.decode(address);
  const prefix = payload.readUInt8(0);
  // Check if address has valid length and prefix
  if (
    payload.length !== 21 ||
    (prefix !== network.pubKeyHash && prefix !== network.scriptHash)
  )
    throw new TypeError(address + 'is not valid');

  // Check if blind key has valid length
  const rawBlindkey = Buffer.from(blindkey, 'hex');
  if (rawBlindkey.length < 33) throw new TypeError(blindkey + 'is too short');
  if (rawBlindkey.length > 33) throw new TypeError(blindkey + 'is too long');

  const prefixBuf = new Uint8Array(2);
  prefixBuf[0] = network.confidentialPrefix;
  prefixBuf[1] = prefix;
  const confidentialAddress = Buffer.concat([
    prefixBuf,
    rawBlindkey,
    Buffer.from(payload.slice(1)),
  ]);

  return bs58check.encode(confidentialAddress);
}

export function confidentialAddressToAddress(
  address: string,
  network: Network,
): string {
  const payload = bs58check.decode(address);
  const prefix = payload.readUInt8(1);
  // Check if address has valid length and prefix
  if (
    payload.length !== 55 ||
    (prefix !== network.pubKeyHash && prefix !== network.scriptHash)
  )
    throw new TypeError(address + 'is not valid');

  // Check if length matches confidential address
  if (payload.length < 55) throw new TypeError(address + ' is too short');
  if (payload.length > 55) throw new TypeError(address + ' is too long');

  const unconfidential = payload.slice(35, payload.length);

  // 0x39 is address version on Liquid v1 network for P2PKH address
  // 0xEB is address version on Liquid v1 regtest network for P2PKH address
  // ToDo: 0x27 is address version on Liquid v1 network for P2SH address
  // ToDo: 0x4B is address version on Liquid v1 regtest network for P2SH address
  const versionBuf = new Uint8Array(1);
  versionBuf[0] = prefix;
  const unconfidentialAddressBuffer = Buffer.concat([
    versionBuf,
    unconfidential,
  ]);
  const unconfidentialAddress = bs58check.encode(unconfidentialAddressBuffer);

  return unconfidentialAddress;
}

export function fromBase58Check(address: string): Base58CheckResult {
  const payload = bs58check.decode(address);

  // TODO: 4.0.0, move to "toOutputScript"
  if (payload.length < 21) throw new TypeError(address + ' is too short');
  if (payload.length > 21) throw new TypeError(address + ' is too long');

  const version = payload.readUInt8(0);
  const hash = payload.slice(1);

  return { version, hash };
}

export function fromBech32(address: string): Bech32Result {
  const result = bech32.decode(address);
  const data = bech32.fromWords(result.words.slice(1));

  return {
    version: result.words[0],
    prefix: result.prefix,
    data: Buffer.from(data),
  };
}

export function toBase58Check(hash: Buffer, version: number): string {
  typeforce(types.tuple(types.Hash160bit, types.UInt8), arguments);

  const payload = Buffer.allocUnsafe(21);
  payload.writeUInt8(version, 0);
  hash.copy(payload, 1);

  return bs58check.encode(payload);
}

export function toBech32(
  data: Buffer,
  version: number,
  prefix: string,
): string {
  const words = bech32.toWords(data);
  words.unshift(version);

  return bech32.encode(prefix, words);
}

export function fromOutputScript(output: Buffer, network?: Network): string {
  // TODO: Network
  network = network || networks.liquid;

  try {
    return payments.p2pkh({ output, network }).address as string;
  } catch (e) {}
  try {
    return payments.p2sh({ output, network }).address as string;
  } catch (e) {}
  try {
    return payments.p2wpkh({ output, network }).address as string;
  } catch (e) {}
  try {
    return payments.p2wsh({ output, network }).address as string;
  } catch (e) {}

  throw new Error(bscript.toASM(output) + ' has no matching Address');
}

export function toOutputScript(address: string, network?: Network): Buffer {
  network = network || networks.liquid;

  let decodeBase58: Base58CheckResult | undefined;
  let decodeBech32: Bech32Result | undefined;
  try {
    decodeBase58 = fromBase58Check(address);
  } catch (e) {}

  if (decodeBase58) {
    if (decodeBase58.version === network.pubKeyHash)
      return payments.p2pkh({ hash: decodeBase58.hash }).output as Buffer;
    if (decodeBase58.version === network.scriptHash)
      return payments.p2sh({ hash: decodeBase58.hash }).output as Buffer;
  } else {
    try {
      decodeBech32 = fromBech32(address);
    } catch (e) {}

    if (decodeBech32) {
      if (decodeBech32.prefix !== network.bech32)
        throw new Error(address + ' has an invalid prefix');
      if (decodeBech32.version === 0) {
        if (decodeBech32.data.length === 20)
          return payments.p2wpkh({ hash: decodeBech32.data }).output as Buffer;
        if (decodeBech32.data.length === 32)
          return payments.p2wsh({ hash: decodeBech32.data }).output as Buffer;
      }
    }
  }

  throw new Error(address + ' has no matching Script');
}

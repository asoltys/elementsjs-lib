import * as secp256k1 from 'secp256k1-zkp';

import * as crypto from './crypto';

function nonceHash(pubkey: Buffer, privkey: Buffer): Buffer {
  return crypto.sha256(secp256k1.ecdh.ecdh(pubkey, privkey));
}

export function valueBlindingFactor(
  values: string[],
  nInputs: number,
  generators: Buffer[],
  factors: Buffer[],
): Buffer {
  return secp256k1.pedersen.blindGeneratorBlindSum(
    values,
    nInputs,
    generators,
    factors,
  );
}

export function valueCommitment(
  value: string,
  generator: Buffer,
  factor: Buffer,
): Buffer {
  const gen = secp256k1.generator.parse(generator);
  const commit = secp256k1.pedersen.commit(factor, value, gen);
  return secp256k1.pedersen.commitSerialize(commit);
}

export function assetCommitment(asset: Buffer, factor: Buffer): Buffer {
  const generator = secp256k1.generator.generateBlinded(asset, factor);
  return secp256k1.generator.serialize(generator);
}

export interface UnblindOutputResult {
  value: string;
  valueBlindingFactor: Buffer;
  asset: Buffer;
  assetBlindingFactor: Buffer;
}

export function unblindOutput(
  ephemeralPubkey: Buffer,
  blindingPrivkey: Buffer,
  rangeproof: Buffer,
  valueCommit: Buffer,
  asset: Buffer,
  scriptPubkey: Buffer,
): UnblindOutputResult {
  const gen = secp256k1.generator.parse(asset);
  const nonce = nonceHash(ephemeralPubkey, blindingPrivkey);
  const { value, blindFactor, message } = secp256k1.rangeproof.rewind(
    valueCommit,
    rangeproof,
    nonce,
    gen,
    scriptPubkey,
  );

  return {
    value,
    asset: message.slice(0, 32),
    valueBlindingFactor: blindFactor,
    assetBlindingFactor: message.slice(32),
  };
}

export function rangeProof(
  value: string,
  blindingPubkey: Buffer,
  ephemeralPrivkey: Buffer,
  asset: Buffer,
  assetBlindingFactor: Buffer,
  valueBlindFactor: Buffer,
  valueCommit: Buffer,
  scriptPubkey: Buffer,
  minValue?: string,
  exp?: number,
  minBits?: number,
): Buffer {
  const nonce = nonceHash(blindingPubkey, ephemeralPrivkey);
  const gen = secp256k1.generator.generateBlinded(asset, assetBlindingFactor);
  const message = Buffer.concat([asset, assetBlindingFactor]);
  const commit = secp256k1.pedersen.commitParse(valueCommit);

  const mv = minValue ? minValue : '1';
  const e = exp ? exp : 0;
  const mb = minBits ? minBits : 36;

  return secp256k1.rangeproof.sign(
    commit,
    valueBlindFactor,
    nonce,
    value,
    gen,
    mv,
    e,
    mb,
    message,
    scriptPubkey,
  );
}

export function surjectionProof(
  outputAsset: Buffer,
  outputAssetBlindingFactor: Buffer,
  inputAssets: Buffer[],
  inputAssetBlindingFactors: Buffer[],
  seed: Buffer,
): Buffer {
  const outputGenerator = secp256k1.generator.generateBlinded(
    outputAsset,
    outputAssetBlindingFactor,
  );

  const inputGenerators = inputAssets.map((v, i) =>
    secp256k1.generator.generateBlinded(v, inputAssetBlindingFactors[i]),
  );
  const nInputsToUse = inputAssets.length > 3 ? 3 : inputAssets.length;
  const maxIterations = 100;

  const init = secp256k1.surjectionproof.initialize(
    inputAssets,
    nInputsToUse,
    outputAsset,
    maxIterations,
    seed,
  );

  const proof = secp256k1.surjectionproof.generate(
    init.proof,
    inputGenerators,
    outputGenerator,
    init.inputIndex,
    inputAssetBlindingFactors[init.inputIndex],
    outputAssetBlindingFactor,
  );

  return secp256k1.surjectionproof.serialize(proof);
}

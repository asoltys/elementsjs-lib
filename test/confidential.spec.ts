import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as confidential from '../src/confidential';
import * as preFixtures from './fixtures/confidential.json';

const initBuffers = (object: any): typeof preFixtures =>
  JSON.parse(JSON.stringify(object), (_, value) => {
    const regex = new RegExp(/^Buffer.from\(['"](.*)['"], ['"](.*)['"]\)$/);
    const result = regex.exec(value);
    if (!result) return value;

    const data = result[1];
    const encoding = result[2];

    return Buffer.from(data, encoding as BufferEncoding);
  });

const fixtures = initBuffers(preFixtures);

describe('confidential', () => {
  it('valueCommitment', () => {
    fixtures.valid.valueCommitment.forEach((f: any) => {
      assert.strictEqual(
        confidential
          .valueCommitment(f.value, f.generator, f.factor)
          .toString('hex'),
        f.expected,
      );
    });
  });

  it('valueBlindingFactor', () => {
    fixtures.valid.valueBlindingFactor.forEach((f: any) => {
      const generators = f.generators.map((v: any) => Buffer.from(v, 'hex'));
      const factors = f.factors.map((v: any) => Buffer.from(v, 'hex'));
      const vbf = confidential.valueBlindingFactor(
        f.values,
        f.nInputs,
        generators,
        factors,
      );
      assert.strictEqual(vbf.toString('hex'), f.expected);
    });
  });

  it('assetCommitment', () => {
    fixtures.valid.assetCommitment.forEach((f: any) => {
      assert.strictEqual(
        confidential.assetCommitment(f.asset, f.factor).toString('hex'),
        f.expected,
      );
    });
  });

  it('unblind', () => {
    fixtures.valid.unblind.forEach((f: any) => {
      const unblindProof = confidential.unblindOutput(
        f.ephemeralPubkey,
        f.blindingPrivkey,
        f.rangeproof,
        f.valueCommitment,
        f.assetGenerator,
        f.scriptPubkey,
      );
      assert.strictEqual(unblindProof.value, f.expected.value);
      assert.strictEqual(
        unblindProof.valueBlindingFactor.toString('hex'),
        f.expected.valueBlindingFactor,
      );
      assert.strictEqual(unblindProof.asset.toString('hex'), f.expected.asset);
      assert.strictEqual(
        unblindProof.assetBlindingFactor.toString('hex'),
        f.expected.assetBlindingFactor,
      );
    });
  });

  it('rangeProof', () => {
    fixtures.valid.rangeproof.forEach((f: any) => {
      const minValue = '1';
      const exp = 0;
      const minBits = 36;

      const proof = confidential.rangeProof(
        f.value,
        f.blindingPubkey,
        f.ephemeralPrivkey,
        f.asset,
        f.assetBlindingFactor,
        f.valueBlindingFactor,
        f.valueCommitment,
        f.scriptPubkey,
        minValue,
        exp,
        minBits,
      );
      assert.strictEqual(proof.toString('hex'), f.expected);
    });
  });

  it('surjectionProof', () => {
    fixtures.valid.surjectionproof.forEach((f: any) => {
      const inputAssets = f.inputAssets.map((v: any) => Buffer.from(v, 'hex'));
      const inputAssetBlindingFactors = f.inputAssetBlindingFactors.map(
        (v: any) => Buffer.from(v, 'hex'),
      );
      const proof = confidential.surjectionProof(
        f.outputAsset,
        f.outputAssetBlindingFactor,
        inputAssets,
        inputAssetBlindingFactors,
        f.seed,
      );
      assert.strictEqual(proof.toString('hex'), f.expected);
    });
  });
});

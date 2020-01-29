import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as liquid from '../..';
import { networks as NETWORKS } from '../..';
const { regtest } = NETWORKS;

// See bottom of file for some helper functions used to make the payment objects needed.

describe('liquidjs-lib (transactions with psbt)', () => {
  it('can create a 1-to-1 Transaction', () => {
    const alice = liquid.ECPair.fromWIF(
      'cPNMJD4VyFnQjGbGs3kcydRzAbDCXrLAbvH6wTCqs88qg1SkZT3J',
      regtest,
    );
    const psbt = new liquid.Psbt();
    psbt.setVersion(2); // These are defaults. This line is not needed.
    psbt.setLocktime(0); // These are defaults. This line is not needed.
    psbt.addInput({
      // if hash is string, txid, if hash is Buffer, is reversed compared to txid
      hash: '9d64f0343e264f9992aa024185319b349586ec4cbbfcedcda5a05678ab10e580',
      index: 0,
      script: Buffer.alloc(0),
      // non-segwit inputs now require passing the whole previous tx as Buffer
      nonWitnessUtxo: Buffer.from(
        '0200000000010caf381d44f094661f2da71a11946251a27d656d6c141577e27c483a6' +
          'd428f01010000006a47304402205ac99f5988d699d6d9f72004098c2e52c8f342838e' +
          '9009dde33d204108cc930d022077238cd40a4e4234f1e70ceab8fd6b51c5325954387' +
          '2e5d9f4bad544918b82ce012102b5214a4f0d6962fe547f0b9cbb241f9df1b61c3c40' +
          '1dbfb04cdd59efd552bea1ffffffff020125b251070e29ca19043cf33ccd7324e2dda' +
          'b03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5df70001976a914659bedb5d3d3' +
          'c7ab12d7f85323c3a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2dda' +
          'b03ecc4ae0b5e77c4fc0e5cf6c95a010000000000000190000000000000',
        'hex',
      ),

      // // If this input was segwit, instead of nonWitnessUtxo, you would add
      // // a witnessUtxo as follows. The scriptPubkey and the value only are needed.
      // witnessUtxo: {
      //   script: Buffer.from(
      //     '76a9148bbc95d2709c71607c60ee3f097c1217482f518d88ac',
      //     'hex',
      //   ),
      //   value: 90000,
      // },

      // Not featured here:
      //   redeemScript. A Buffer of the redeemScript for P2SH
      //   witnessScript. A Buffer of the witnessScript for P2WSH
    });
    psbt.addOutputs([
      {
        nonce: Buffer.from('00', 'hex'),
        value: liquid.satoshiToConfidentialValue(50000000),
        script: Buffer.from(
          '76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac',
          'hex',
        ),
        asset: Buffer.concat([
          Buffer.from('01', 'hex'),
          Buffer.from(
            '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
            'hex',
          ).reverse(),
        ]),
      },
      {
        nonce: Buffer.from('00', 'hex'),
        value: liquid.satoshiToConfidentialValue(49999100),
        script: Buffer.from(
          '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
          'hex',
        ),
        asset: Buffer.concat([
          Buffer.from('01', 'hex'),
          Buffer.from(
            '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
            'hex',
          ).reverse(),
        ]),
      },
      {
        nonce: Buffer.from('00', 'hex'),
        value: liquid.satoshiToConfidentialValue(500),
        script: Buffer.alloc(0),
        asset: Buffer.concat([
          Buffer.from('01', 'hex'),
          Buffer.from(
            '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
            'hex',
          ).reverse(),
        ]),
      },
    ]);
    psbt.signInput(0, alice);
    psbt.validateSignaturesOfInput(0);
    psbt.finalizeAllInputs();
    assert.strictEqual(
      psbt.extractTransaction().toHex(),
      '02000000000180e510ab7856a0a5cdedfcbb4cec8695349b31854102aa92994f263e34f' +
        '0649d000000006a47304402201e868b2bea22df05229746a27e7df2ca0f584880546f7f' +
        '6d55dad71cbd50d35302203a04a4cc49fca739c8974c97d3de924c99835e15ad1d85b96' +
        'ad24ea072d2e63e01210251464420fcc98a2e4cd347afe28a32d769287dacd861476ab8' +
        '58baa43bd308f3ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0' +
        'b5e77c4fc0e5cf6c95a010000000002faf080001976a91439397080b51ef22c59bd7469' +
        'afacffbeec0da12e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e7' +
        '7c4fc0e5cf6c95a010000000002faecfc001976a914659bedb5d3d3c7ab12d7f85323c3' +
        'a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4f' +
        'c0e5cf6c95a0100000000000001f4000000000000',
    );
  });
});

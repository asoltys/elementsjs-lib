import { describe, it } from 'mocha';
import { networks as NETWORKS } from '../..';
import * as liquid from '../..';
import * as regtestUtils from './_regtest';
const NETWORK = NETWORKS.regtest;
const DRY = process.env.DRY || true;
const keyPairs = !DRY
  ? [
      liquid.ECPair.makeRandom({ network: NETWORK }),
      liquid.ECPair.makeRandom({ network: NETWORK }),
    ]
  : [
      liquid.ECPair.fromWIF(
        'cPNMJD4VyFnQjGbGs3kcydRzAbDCXrLAbvH6wTCqs88qg1SkZT3J',
        NETWORK,
      ),
    ];

async function buildAndSign(sender: any): Promise<string> {
  const unspent = (await regtestUtils.faucet(sender.address))[0];
  const txHex = await regtestUtils.fetchTx(unspent.txid);

  const psbt = new liquid.Psbt({ network: NETWORK })
    .addInput({
      hash: unspent.txid,
      index: unspent.vout,
      script: Buffer.alloc(0),
      nonWitnessUtxo: Buffer.from(txHex, 'hex'),
    })
    .addOutputs([
      {
        value: liquid.satoshiToConfidentialValue(40000000),
        asset: Buffer.concat([
          Buffer.from('01', 'hex'),
          Buffer.from(unspent.asset, 'hex').reverse(),
        ]),
        script: Buffer.from(
          '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
          'hex',
        ),
        nonce: Buffer.from('00', 'hex'),
      },
      {
        value: liquid.satoshiToConfidentialValue(
          unspent.value - 40000000 - 400,
        ),
        asset: Buffer.concat([
          Buffer.from('01', 'hex'),
          Buffer.from(unspent.asset, 'hex').reverse(),
        ]),
        script: sender.output,
        nonce: Buffer.from('00', 'hex'),
      },
      {
        value: liquid.satoshiToConfidentialValue(400),
        asset: Buffer.concat([
          Buffer.from('01', 'hex'),
          Buffer.from(NETWORK.assetHash, 'hex').reverse(),
        ]),
        nonce: Buffer.from('00', 'hex'),
        script: Buffer.alloc(0),
      },
    ]);

  psbt.signInput(0, keyPairs[0]);

  return regtestUtils.broadcast(
    psbt
      .finalizeAllInputs()
      .extractTransaction()
      .toHex(),
  );
}

['p2pkh'].forEach(k => {
  const fixtures = require('../fixtures/' + k);
  const { depends } = fixtures.dynamic;
  const fn: any = (liquid.payments as any)[k];

  // const base: any = {};
  // if (depends.pubkey) base.pubkey = keyPairs[0].publicKey;
  // if (depends.pubkeys) base.pubkeys = keyPairs.map(x => x.publicKey);
  // if (depends.m) base.m = base.pubkeys.length;

  const sender = fn({ pubkey: keyPairs[0].publicKey, network: NETWORK }); // base);
  if (!sender.output && sender.address) throw new TypeError('Missing output');

  describe('liquidjs-lib (payments - ' + k + ')', () => {
    it('can broadcast as an output, and be spent as an input', async () => {
      Object.assign(depends, { prevOutScriptType: k });
      await buildAndSign(sender);
    });
  });
});

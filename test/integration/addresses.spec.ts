import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as bitcoin from '../..';
const liquidNetwork = bitcoin.networks.liquid;

describe('liquid-js (addresses)', () => {
  it(
    'can generate a random liquid address [and support the retrieval of ' +
      'transactions for that address (via 3PBP)]',
    async () => {
      const pubkeyHex =
        '026477115981fe981a6918a6297d9803c4dc04f328f22041bedff886bbc2962e01';
      const pubkey = Buffer.from(pubkeyHex, 'hex');
      const { address } = bitcoin.payments.p2pkh({
        pubkey,
        network: liquidNetwork,
      });

      assert.strictEqual(address, 'Q8EcsYKV8ntP6uWWpAeqS4e7J9V8jkzw7V');
    },
  );
});

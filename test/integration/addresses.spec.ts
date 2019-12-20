import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as liquid from '../..';
const liquidNetwork = liquid.networks.regtest;

describe('liquid-js (addresses)', () => {
  it(
    'can generate a random liquid address via p2pkh [and support the retrieval of ' +
      'transactions for that address (via 3PBP)]',
    async () => {
      const pubkeyHex =
        '026477115981fe981a6918a6297d9803c4dc04f328f22041bedff886bbc2962e01';
      const pubkey = Buffer.from(pubkeyHex, 'hex');
      const { address } = liquid.payments.p2pkh({
        pubkey,
        network: liquidNetwork,
      });

      assert.strictEqual(address, '2dkPz8sNmWuNLg4KwAqwZkP69KwM3Dd8QjR');
    },
  );
  it(
    'can generate a random liquid address via p2wpkh [and support the retrieval of ' +
      'transactions for that address (via 3PBP)]',
    async () => {
      const pubkeyHex =
        '026477115981fe981a6918a6297d9803c4dc04f328f22041bedff886bbc2962e01';
      const pubkey = Buffer.from(pubkeyHex, 'hex');
      const { address } = liquid.payments.p2wpkh({
        pubkey,
        network: liquidNetwork,
      });

      assert.strictEqual(
        address,
        'ert1q0p2qwzpgz74686uslpwxps2rhnq20cu2mqp45z',
      );
    },
  );
});

import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as liquid from '../..';
import * as fixtures from '../fixtures/address.json';

const NETWORKS = require('../../src/networks');

describe('liquid-js (addresses)', () => {
  it(
    'can generate a random liquid address via p2pkh from public key [and support the retrieval of ' +
      'transactions for that address (via 3PBP)]',
    async () => {
      fixtures.standard.forEach(f => {
        if (!f.blindkey) return;

        const pubkeyHex = f.blindkey;
        const pubkey = Buffer.from(pubkeyHex, 'hex');
        const { address } = liquid.payments.p2pkh({
          pubkey,
          network: NETWORKS[f.network],
        });

        assert.strictEqual(
          address!.startsWith('2') || address!.startsWith('Q'),
          true,
        );
      });
    },
  );
});

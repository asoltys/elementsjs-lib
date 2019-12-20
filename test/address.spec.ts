import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as baddress from '../src/address';
import * as fixtures from './fixtures/address.json';

const NETWORKS = require('../src/networks');

describe('address', () => {
  describe('findAddressType', () => {
    fixtures.standard.forEach(f => {
      if (!f.base58check) return;

      it('finds type for ' + f.base58check, () => {
        const t = baddress.findAddressType(f.base58check, NETWORKS[f.network]);

        assert.strictEqual(t.version, f.version);
        assert.strictEqual(t.confidential, f.confidential);
      });
    });
  });
  describe('blindingPubKeyFromConfidentialAddress', () => {
    fixtures.standard.forEach(f => {
      if (!f.base58check) return;
      if (!f.confidential) return;

      it('extracts blinding pubkey from ' + f.base58check, () => {
        const t = baddress.blindingPubKeyFromConfidentialAddress(f.base58check);
        assert.strictEqual(t.toString('hex'), f.blindkey);
      });
    });

    fixtures.standard.forEach(f => {
      if (!f.base58check) return;
      if (f.confidential) return;

      it('extract blinding pubkey fails for ' + f.base58check, () => {
        assert.throws(() => {
          baddress.blindingPubKeyFromConfidentialAddress(f.base58check);
        }, f.base58check + 'is too short');
      });
    });
  });
});

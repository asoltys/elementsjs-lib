import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as baddress from '../src/address';
import * as fixtures from './fixtures/address.json';

const NETWORKS = require('../src/networks');

describe('address', () => {
  describe('findAddressType', () => {
    fixtures.standard.forEach(f => {
      if (!f.unconfidentialAddress) return;

      it('finds type for ' + f.unconfidentialAddress, () => {
        const t = baddress.findAddressType(
          f.unconfidentialAddress,
          NETWORKS[f.network],
        );

        assert.strictEqual(t.version, f.version);
        assert.strictEqual(t.confidential, false);
      });
      it('finds type for ' + f.confidentialAddress, () => {
        const t = baddress.findAddressType(
          f.confidentialAddress,
          NETWORKS[f.network],
        );

        assert.strictEqual(t.version, f.version);
        assert.strictEqual(t.confidential, true);
      });
    });
  });
  describe('blindingPubKeyFromConfidentialAddress', () => {
    fixtures.standard.forEach(f => {
      if (!f.confidentialAddress) return;

      it('extracts blinding pubkey from ' + f.confidentialAddress, () => {
        const t = baddress.blindingPubKeyFromConfidentialAddress(
          f.confidentialAddress,
        );
        assert.strictEqual(t.toString('hex'), f.blindkey);
      });
    });

    fixtures.standard.forEach(f => {
      if (!f.unconfidentialAddress) return;

      it('extract blinding pubkey fails for ' + f.unconfidentialAddress, () => {
        assert.throws(() => {
          baddress.blindingPubKeyFromConfidentialAddress(
            f.unconfidentialAddress,
          );
        }, f.unconfidentialAddress + 'is too short');
      });
    });
  });
  describe('confidentialAddressFromAddress', () => {
    fixtures.standard.forEach(f => {
      if (!f.unconfidentialAddress) return;

      it(
        'create confidential address from ' +
          f.unconfidentialAddress +
          ' and ' +
          f.blindkey,
        () => {
          const t = baddress.confidentialAddressFromAddress(
            f.unconfidentialAddress,
            f.blindkey,
            NETWORKS[f.network],
          );
          assert.strictEqual(t, f.confidentialAddress);
        },
      );
    });
  });
  describe('confidentialAddressToAddress', () => {
    fixtures.standard.forEach(f => {
      if (!f.confidentialAddress) return;

      it(
        'extract address from a confidential address ' + f.confidentialAddress,
        () => {
          const unconfidential = baddress.confidentialAddressToAddress(
            f.confidentialAddress,
            NETWORKS[f.network],
          );

          assert.strictEqual(unconfidential, f.unconfidentialAddress);
        },
      );
    });
  });
});

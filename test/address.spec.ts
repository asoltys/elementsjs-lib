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
});

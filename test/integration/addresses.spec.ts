import * as assert from 'assert';
import Axios from 'axios';
import { describe, it } from 'mocha';
import * as liquid from '../..';
const REGTEST = liquid.networks.regtest;

describe('liquid-js (addresses)', () => {
  it(
    'can generate a random address [and support the retrieval of ' +
      'transactions for that address (via 3PBP)]',
    async () => {
      const keyPair = liquid.ECPair.makeRandom();
      const { address } = liquid.payments.p2pkh({ pubkey: keyPair.publicKey });
      // liquid P2PKH addresses start with a '2'
      assert.strictEqual(
        address!.startsWith('Q') || address!.startsWith('P'),
        true,
      );

      const result = await Axios.get(
        `https://blockstream.info/liquid/api/address/${address}/txs`,
      );

      // random private keys [probably!] have no transactions
      assert.strictEqual((result as any).data.length, 0);
    },
  );

  it('can import an address via WIF', () => {
    const keyPair = liquid.ECPair.fromWIF(
      'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn',
    );
    const { address } = liquid.payments.p2pkh({ pubkey: keyPair.publicKey });

    assert.strictEqual(address, 'Q7wegLt2qMGhm28vch6VTzvpzs8KXvs4X7');
  });

  it('can generate a P2SH, pay-to-multisig (2-of-3) address', () => {
    const pubkeys = [
      '026477115981fe981a6918a6297d9803c4dc04f328f22041bedff886bbc2962e01',
      '02c96db2302d19b43d4c69368babace7854cc84eb9e061cde51cfa77ca4a22b8b9',
      '03c6103b3b83e4a24a0e33a4df246ef11772f9992663db0c35759a5e2ebf68d8e9',
    ].map(hex => Buffer.from(hex, 'hex'));
    const { address } = liquid.payments.p2sh({
      redeem: liquid.payments.p2ms({ m: 2, pubkeys }),
    });

    assert.strictEqual(address, 'GmrzEaE3ecTq8uF8fmkTi2tCukeDCBmqxm');
  });

  it('can generate a SegWit address', () => {
    const keyPair = liquid.ECPair.fromWIF(
      'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn',
    );
    const { address } = liquid.payments.p2wpkh({ pubkey: keyPair.publicKey });

    assert.strictEqual(address, 'ex1qw508d6qejxtdg4y5r3zarvary0c5xw7kxw5fx4');
  });

  it('can generate a SegWit address (via P2SH)', () => {
    const keyPair = liquid.ECPair.fromWIF(
      'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn',
    );
    const { address } = liquid.payments.p2sh({
      redeem: liquid.payments.p2wpkh({ pubkey: keyPair.publicKey }),
    });

    assert.strictEqual(address, 'GzQqaEugGVFJWw7E2P8LxN363S8NWdL9ce');
  });

  it('can generate a P2WSH (SegWit), pay-to-multisig (3-of-4) address', () => {
    const pubkeys = [
      '026477115981fe981a6918a6297d9803c4dc04f328f22041bedff886bbc2962e01',
      '02c96db2302d19b43d4c69368babace7854cc84eb9e061cde51cfa77ca4a22b8b9',
      '023e4740d0ba639e28963f3476157b7cf2fb7c6fdf4254f97099cf8670b505ea59',
      '03c6103b3b83e4a24a0e33a4df246ef11772f9992663db0c35759a5e2ebf68d8e9',
    ].map(hex => Buffer.from(hex, 'hex'));
    const { address } = liquid.payments.p2wsh({
      redeem: liquid.payments.p2ms({ m: 3, pubkeys }),
    });

    assert.strictEqual(
      address,
      'ex1q75f6dv4q8ug7zhujrsp5t0hzf33lllnr3fe7e2pra3v24mzl8rrqhw64ue',
    );
  });

  it('can generate a P2SH(P2WSH(...)), pay-to-multisig (2-of-2) address', () => {
    const pubkeys = [
      '026477115981fe981a6918a6297d9803c4dc04f328f22041bedff886bbc2962e01',
      '02c96db2302d19b43d4c69368babace7854cc84eb9e061cde51cfa77ca4a22b8b9',
    ].map(hex => Buffer.from(hex, 'hex'));
    const { address } = liquid.payments.p2sh({
      redeem: liquid.payments.p2wsh({
        redeem: liquid.payments.p2ms({ m: 2, pubkeys }),
      }),
    });

    assert.strictEqual(address, 'H4ZHLeYTuNiTWhagB3jrexKFdaqJLfMqgQ');
  });

  // examples using other network information
  it('can generate a Testnet address', () => {
    const keyPair = liquid.ECPair.makeRandom({ network: REGTEST });
    const { address } = liquid.payments.p2pkh({
      pubkey: keyPair.publicKey,
      network: REGTEST,
    });

    // liquid testnet P2PKH addresses start with a 'm' or 'n'
    assert.strictEqual(address!.startsWith('2'), true);
  });
});

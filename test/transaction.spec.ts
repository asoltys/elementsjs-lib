import * as assert from 'assert';
const { describe, it } = require('mocha');
const bscript = require('../src/script');
const fixtures = require('./fixtures/transaction');
const {
  Transaction,
  satoshiToConfidentialValue,
  // confidentialValueToSatoshi
} = require('../src/transaction');
// const BufferUtils = require('../src/bufferutils')

const emptyNonce = Buffer.from('00', 'hex');

describe('Transaction', () => {
  function fromRaw(raw: any): any {
    const tx = new Transaction();
    tx.version = raw.version;
    tx.locktime = raw.locktime;

    if (raw.flag) tx.flag = raw.flag;

    raw.ins.forEach((txIn: any) => {
      const txHash = Buffer.from(txIn.hash, 'hex').reverse();
      let scriptSig;
      let issuance;

      if (txIn.script.length > 0) {
        scriptSig = bscript.fromASM(txIn.script);
      }

      if (txIn.issuance) {
        issuance = {
          assetBlindingNonce: Buffer.from(
            txIn.issuance.assetBlindingNonce,
            'hex',
          ),
          assetEntropy: Buffer.from(txIn.issuance.assetEntropy, 'hex'),
          assetAmount: satoshiToConfidentialValue(txIn.issuance.assetAmount),
          tokenAmount: satoshiToConfidentialValue(txIn.issuance.tokenAmount),
        };
      }

      tx.addInput(txHash, txIn.index, scriptSig, txIn.sequence, issuance);
    });

    raw.outs.forEach((txOut: any) => {
      const asset = Buffer.concat([
        Buffer.from('01', 'hex'),
        Buffer.from(txOut.asset, 'hex').reverse(),
      ]);
      let script = Buffer.allocUnsafe(0);
      if (txOut.script.length > 0) {
        script = bscript.fromASM(txOut.script);
      }
      let nonce = Buffer.from('00', 'hex');
      if (txOut.nonce.length > 0) {
        nonce = Buffer.from(txOut.nonce, 'hex');
      }

      let value;
      if (txOut.hasOwnProperty('amount')) {
        value = satoshiToConfidentialValue(txOut.amount);
      } else {
        value = Buffer.from(txOut.amountCommitment, 'hex');
      }
      tx.addOutput(script, value, asset, nonce);
    });

    const witnessIn = [];
    const witnessOut = [];

    if (raw.witnessIn) {
      for (const witIn of raw.witnessIn) {
        const scriptWitness = [];
        const peginWitness = [];
        for (const sWit of witIn.scriptWitness) {
          scriptWitness.push(Buffer.from(sWit, 'hex'));
        }
        for (const pWit of witIn.peginWitness) {
          peginWitness.push(Buffer.from(pWit, 'hex'));
        }
        witnessIn.push({
          issuanceRangeProof: Buffer.from(witIn.issuanceRangeProof, 'hex'),
          inflationRangeProof: Buffer.from(witIn.inflationRangeProof, 'hex'),
          scriptWitness,
          peginWitness,
        });
      }
    }

    if (raw.witnessOut) {
      for (const witOut of raw.witnessOut) {
        witnessOut.push({
          surjectionProof: Buffer.from(witOut.surjectionProof, 'hex'),
          rangeProof: Buffer.from(witOut.rangeProof, 'hex'),
        });
      }
    }

    tx.witnessIn = witnessIn;
    tx.witnessOut = witnessOut;
    return tx;
  }

  describe('fromBuffer/fromHex', () => {
    function importExport(f: any): void {
      const id = f.id || f.hash;
      const txHex = f.hex || f.txHex;

      it('imports ' + f.description + ' (' + id + ')', () => {
        const actual = Transaction.fromHex(txHex);
        assert.strictEqual(actual.toHex(), txHex);
      });
    }

    fixtures.valid.forEach(importExport);
    fixtures.hashForSignature.forEach(importExport);

    fixtures.invalid.fromBuffer.forEach((f: any) => {
      it('throws on ' + f.exception, () => {
        assert.throws(() => {
          Transaction.fromHex(f.hex);
        }, new RegExp(f.exception));
      });
    });

    it('.version should be interpreted as an int32le', () => {
      const txHex = 'ffffffff000000ffffffff';
      const tx = Transaction.fromHex(txHex);
      assert.strictEqual(-1, tx.version);
      assert.strictEqual(0xffffffff, tx.locktime);
    });
  });

  describe('toBuffer/toHex', () => {
    fixtures.valid.forEach((f: any) => {
      it('exports ' + f.description + ' (' + f.id + ')', () => {
        const actual = fromRaw(f.raw);
        assert.strictEqual(actual.toHex(), f.hex);
      });
    });

    it('accepts target Buffer and offset parameters', () => {
      const f = fixtures.valid[0];
      const actual = fromRaw(f.raw);
      const byteLength = actual.byteLength();

      const target = Buffer.alloc(byteLength * 2);
      const a = actual.toBuffer(target, 0);
      const b = actual.toBuffer(target, byteLength);

      assert.strictEqual(a.length, byteLength);
      assert.strictEqual(b.length, byteLength);
      assert.strictEqual(a.toString('hex'), f.hex);
      assert.strictEqual(b.toString('hex'), f.hex);
      assert.deepStrictEqual(a, b);
      assert.deepStrictEqual(a, target.slice(0, byteLength));
      assert.deepStrictEqual(b, target.slice(byteLength));
    });
  });

  describe('weight/virtualSize', () => {
    it('computes virtual size', () => {
      fixtures.valid.forEach((f: any) => {
        const transaction = Transaction.fromHex(f.hex);

        assert.strictEqual(transaction.virtualSize(), f.virtualSize);
      });
    });

    it('computes weight', () => {
      fixtures.valid.forEach((f: any) => {
        const transaction = Transaction.fromHex(f.hex);

        assert.strictEqual(transaction.weight(), f.weight);
      });
    });
  });

  describe('addInput', () => {
    let prevTxHash: Buffer;
    beforeEach(() => {
      prevTxHash = Buffer.from(
        'ffffffff00ffff000000000000000000000000000000000000000000101010ff',
        'hex',
      );
    });

    it('returns an index', () => {
      const tx = new Transaction();
      assert.strictEqual(tx.addInput(prevTxHash, 0, Buffer.alloc(0)), 0);
      assert.strictEqual(tx.addInput(prevTxHash, 0, Buffer.alloc(0)), 1);
    });

    it('defaults to empty script, 0xffffffff SEQUENCE number', () => {
      const tx = new Transaction();
      tx.addInput(prevTxHash, 0, Buffer.alloc(0));

      assert.strictEqual(tx.ins[0].script.length, 0);
      assert.strictEqual(tx.ins[0].sequence, 0xffffffff);
    });

    fixtures.invalid.addInput.forEach((f: any) => {
      it('throws on ' + f.exception, () => {
        const tx = new Transaction();
        const hash = Buffer.from(f.hash, 'hex');

        assert.throws(() => {
          tx.addInput(hash, f.index, Buffer.alloc(0));
        }, new RegExp(f.exception));
      });
    });
  });

  describe('addOutput', () => {
    it('returns an index', () => {
      const tx = new Transaction();
      assert.strictEqual(
        tx.addOutput(
          Buffer.alloc(0),
          Buffer.alloc(1),
          Buffer.from(
            '01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d',
            'hex',
          ),
          Buffer.alloc(1),
        ),
        0,
      );
      assert.strictEqual(
        tx.addOutput(
          Buffer.alloc(0),
          Buffer.alloc(1),
          Buffer.from(
            '01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d',
            'hex',
          ),
          Buffer.alloc(1),
        ),
        1,
      );
    });
  });

  describe('clone', () => {
    fixtures.valid.forEach((f: any) => {
      let actual: any;
      let expected: any;

      beforeEach(() => {
        expected = Transaction.fromHex(f.hex);
        actual = expected.clone();
      });

      it('should have value equality', () => {
        assert.deepStrictEqual(actual, expected);
      });

      it('should not have reference equality', () => {
        assert.notStrictEqual(actual, expected);
      });
    });
  });

  describe('getHash/getId', () => {
    function verify(f: any): void {
      it('should return the id for ' + f.id + '(' + f.description + ')', () => {
        const tx = Transaction.fromHex(f.hex);

        assert.strictEqual(tx.getHash().toString('hex'), f.hash);
        assert.strictEqual(tx.getId(), f.id);
      });
    }

    fixtures.valid.forEach(verify);
  });

  describe('isCoinbase', () => {
    function verify(f: any): void {
      it(
        'should return ' +
          f.coinbase +
          ' for ' +
          f.id +
          '(' +
          f.description +
          ')',
        () => {
          const tx = Transaction.fromHex(f.hex);

          assert.strictEqual(tx.isCoinbase(), f.coinbase);
        },
      );
    }

    fixtures.valid.forEach(verify);
  });

  describe('hashForSignature', () => {
    it('does not use Witness serialization', () => {
      const randScript = Buffer.from('6a', 'hex');

      const tx = new Transaction();
      tx.addInput(
        Buffer.from(
          '0000000000000000000000000000000000000000000000000000000000000000',
          'hex',
        ),
        0,
        Buffer.alloc(0),
      );
      tx.addOutput(
        randScript,
        Buffer.from('010000000050000000', 'hex'),
        Buffer.from(
          '01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d',
          'hex',
        ),
        emptyNonce,
      );

      const original = tx.__toBuffer;
      tx.__toBuffer = (a: any, b: any, c: any): any => {
        if (c !== false) throw new Error('hashForSignature MUST pass false');

        return original.call(a, b, c);
      };

      assert.throws(() => {
        tx.__toBuffer(undefined, undefined, true);
      }, /hashForSignature MUST pass false/);

      // assert hashForSignature does not pass false
      assert.doesNotThrow(() => {
        tx.hashForSignature(0, randScript, 1);
      });
    });

    fixtures.hashForSignature.forEach((f: any) => {
      it(
        'should return ' +
          f.hash +
          ' for ' +
          (f.description ? 'case "' + f.description + '"' : f.script),
        () => {
          const tx = Transaction.fromHex(f.txHex);
          const script = bscript.fromASM(f.script);
          assert.strictEqual(
            tx.hashForSignature(f.inIndex, script, f.type).toString('hex'),
            f.hash,
          );
        },
      );
    });
  });
});

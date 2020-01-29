import * as assert from 'assert';
import { describe, it } from 'mocha';
import {
  // bip32,
  ECPair,
  networks as NETWORKS,
  Psbt,
  satoshiToConfidentialValue,
} from '..';
const bscript = require('../src/script');
import * as preFixtures from './fixtures/psbt.json';

const initBuffers = (object: any): typeof preFixtures =>
  JSON.parse(JSON.stringify(object), (_, value) => {
    const regex = new RegExp(/^Buffer.from\(['"](.*)['"], ['"](.*)['"]\)$/);
    const result = regex.exec(value);
    if (!result) return value;

    const data = result[1];
    const encoding = result[2];

    return Buffer.from(data, encoding as BufferEncoding);
  });

const fixtures = initBuffers(preFixtures);

const upperCaseFirstLetter = (str: string): string =>
  str.replace(/^./, s => s.toUpperCase());

describe('Psbt', () => {
  describe('BIP174 Test Vectors', () => {
    fixtures.bip174.creator.forEach((f: any) => {
      it('Creates expected PSBT', () => {
        const psbt = new Psbt();
        for (const input of f.inputs) {
          const script =
            input.script.length > 0
              ? Buffer.from(input.script, 'hex')
              : Buffer.alloc(0);
          psbt.addInput({ ...input, script });
        }
        for (const output of f.outputs) {
          const asset = Buffer.concat([
            Buffer.from('01', 'hex'),
            Buffer.from(output.asset, 'hex').reverse(),
          ]);
          const value = satoshiToConfidentialValue(output.amount);
          const nonce = Buffer.from(
            output.nonce.length > 0 ? output.nonce : '00',
            'hex',
          );
          const script =
            output.script.length > 0
              ? bscript.fromASM(output.script)
              : Buffer.alloc(0);
          psbt.addOutput({ asset, value, nonce, script });
        }
        assert.strictEqual(psbt.toBase64(), f.result);
      });
    });

    fixtures.bip174.updater.forEach(f => {
      it('Updates PSBT to the expected result', () => {
        const psbt = Psbt.fromBase64(f.psbt);

        for (const inputOrOutput of ['input', 'output']) {
          const fixtureData = (f as any)[`${inputOrOutput}Data`];
          if (fixtureData) {
            for (const [i, data] of fixtureData.entries()) {
              const txt = upperCaseFirstLetter(inputOrOutput);
              if (
                typeof data === 'object' &&
                data.hasOwnProperty('redeemScript')
              ) {
                data.redeemScript = Buffer.from(data.redeemScript, 'hex');
              }
              (psbt as any)[`update${txt}`](i, data);
            }
          }
        }
        assert.strictEqual(psbt.toBase64(), f.result);
      });
    });

    fixtures.bip174.signer.forEach(f => {
      it('Signs PSBT to the expected result', () => {
        const psbt = Psbt.fromBase64(f.psbt);

        f.keys.forEach(({ inputToSign, WIF }) => {
          const keyPair = ECPair.fromWIF(WIF, NETWORKS.regtest);
          psbt.signInput(inputToSign, keyPair);
        });

        assert.strictEqual(psbt.toBase64(), f.result);
      });
    });

    fixtures.bip174.finalizer.forEach(f => {
      it('Finalizes PSBT to the expected result', () => {
        const psbt = Psbt.fromBase64(f.psbt);
        psbt.finalizeAllInputs();
        assert.strictEqual(psbt.toBase64(), f.result);
      });
    });

    fixtures.bip174.extractor.forEach(f => {
      it('Extracts PSBT to the expected result', () => {
        const psbt = Psbt.fromBase64(f.psbt);
        const tx = psbt.extractTransaction();
        assert.strictEqual(tx.toHex(), f.transaction);
      });
    });
  });

  // describe('signInputAsync', () => {
  //   fixtures.signInput.checks.forEach(f => {
  //     it(f.description, async () => {
  //       if (f.shouldSign) {
  //         const psbtThatShouldsign = Psbt.fromBase64(f.shouldSign.psbt);
  //         assert.doesNotReject(async () => {
  //           await psbtThatShouldsign.signInputAsync(
  //             f.shouldSign.inputToCheck,
  //             ECPair.fromWIF(f.shouldSign.WIF),
  //             f.shouldSign.sighashTypes || undefined,
  //           );
  //         });
  //       }

  //       if (f.shouldThrow) {
  //         const psbtThatShouldThrow = Psbt.fromBase64(f.shouldThrow.psbt);
  //         assert.rejects(async () => {
  //           await psbtThatShouldThrow.signInputAsync(
  //             f.shouldThrow.inputToCheck,
  //             ECPair.fromWIF(f.shouldThrow.WIF),
  //             (f.shouldThrow as any).sighashTypes || undefined,
  //           );
  //         }, new RegExp(f.shouldThrow.errorMessage));
  //         assert.rejects(async () => {
  //           await (psbtThatShouldThrow.signInputAsync as any)(
  //             f.shouldThrow.inputToCheck,
  //           );
  //         }, new RegExp('Need Signer to sign input'));
  //       }
  //     });
  //   });
  // });

  // describe('signInput', () => {
  //   fixtures.signInput.checks.forEach(f => {
  //     it(f.description, () => {
  //       if (f.shouldSign) {
  //         const psbtThatShouldsign = Psbt.fromBase64(f.shouldSign.psbt);
  //         assert.doesNotThrow(() => {
  //           psbtThatShouldsign.signInput(
  //             f.shouldSign.inputToCheck,
  //             ECPair.fromWIF(f.shouldSign.WIF),
  //             f.shouldSign.sighashTypes || undefined,
  //           );
  //         });
  //       }

  //       if (f.shouldThrow) {
  //         const psbtThatShouldThrow = Psbt.fromBase64(f.shouldThrow.psbt);
  //         assert.throws(() => {
  //           psbtThatShouldThrow.signInput(
  //             f.shouldThrow.inputToCheck,
  //             ECPair.fromWIF(f.shouldThrow.WIF),
  //             (f.shouldThrow as any).sighashTypes || undefined,
  //           );
  //         }, new RegExp(f.shouldThrow.errorMessage));
  //         assert.throws(() => {
  //           (psbtThatShouldThrow.signInput as any)(f.shouldThrow.inputToCheck);
  //         }, new RegExp('Need Signer to sign input'));
  //       }
  //     });
  //   });
  // });

  // describe('signAllInputsAsync', () => {
  //   fixtures.signInput.checks.forEach(f => {
  //     if (f.description === 'checks the input exists') return;
  //     it(f.description, async () => {
  //       if (f.shouldSign) {
  //         const psbtThatShouldsign = Psbt.fromBase64(f.shouldSign.psbt);
  //         assert.doesNotReject(async () => {
  //           await psbtThatShouldsign.signAllInputsAsync(
  //             ECPair.fromWIF(f.shouldSign.WIF),
  //             f.shouldSign.sighashTypes || undefined,
  //           );
  //         });
  //       }

  //       if (f.shouldThrow) {
  //         const psbtThatShouldThrow = Psbt.fromBase64(f.shouldThrow.psbt);
  //         assert.rejects(async () => {
  //           await psbtThatShouldThrow.signAllInputsAsync(
  //             ECPair.fromWIF(f.shouldThrow.WIF),
  //             (f.shouldThrow as any).sighashTypes || undefined,
  //           );
  //         }, new RegExp('No inputs were signed'));
  //         assert.rejects(async () => {
  //           await (psbtThatShouldThrow.signAllInputsAsync as any)();
  //         }, new RegExp('Need Signer to sign input'));
  //       }
  //     });
  //   });
  // });

  // describe('signAllInputs', () => {
  //   fixtures.signInput.checks.forEach(f => {
  //     if (f.description === 'checks the input exists') return;
  //     it(f.description, () => {
  //       if (f.shouldSign) {
  //         const psbtThatShouldsign = Psbt.fromBase64(f.shouldSign.psbt);
  //         assert.doesNotThrow(() => {
  //           psbtThatShouldsign.signAllInputs(
  //             ECPair.fromWIF(f.shouldSign.WIF),
  //             f.shouldSign.sighashTypes || undefined,
  //           );
  //         });
  //       }

  //       if (f.shouldThrow) {
  //         const psbtThatShouldThrow = Psbt.fromBase64(f.shouldThrow.psbt);
  //         assert.throws(() => {
  //           psbtThatShouldThrow.signAllInputs(
  //             ECPair.fromWIF(f.shouldThrow.WIF),
  //             (f.shouldThrow as any).sighashTypes || undefined,
  //           );
  //         }, new RegExp('No inputs were signed'));
  //         assert.throws(() => {
  //           (psbtThatShouldThrow.signAllInputs as any)();
  //         }, new RegExp('Need Signer to sign input'));
  //       }
  //     });
  //   });
  // });

  // describe('signInputHDAsync', () => {
  //   fixtures.signInputHD.checks.forEach(f => {
  //     it(f.description, async () => {
  //       if (f.shouldSign) {
  //         const psbtThatShouldsign = Psbt.fromBase64(f.shouldSign.psbt);
  //         assert.doesNotReject(async () => {
  //           await psbtThatShouldsign.signInputHDAsync(
  //             f.shouldSign.inputToCheck,
  //             bip32.fromBase58(f.shouldSign.xprv),
  //             (f.shouldSign as any).sighashTypes || undefined,
  //           );
  //         });
  //       }

  //       if (f.shouldThrow) {
  //         const psbtThatShouldThrow = Psbt.fromBase64(f.shouldThrow.psbt);
  //         assert.rejects(async () => {
  //           await psbtThatShouldThrow.signInputHDAsync(
  //             f.shouldThrow.inputToCheck,
  //             bip32.fromBase58(f.shouldThrow.xprv),
  //             (f.shouldThrow as any).sighashTypes || undefined,
  //           );
  //         }, new RegExp(f.shouldThrow.errorMessage));
  //         assert.rejects(async () => {
  //           await (psbtThatShouldThrow.signInputHDAsync as any)(
  //             f.shouldThrow.inputToCheck,
  //           );
  //         }, new RegExp('Need HDSigner to sign input'));
  //       }
  //     });
  //   });
  // });

  // describe('signInputHD', () => {
  //   fixtures.signInputHD.checks.forEach(f => {
  //     it(f.description, () => {
  //       if (f.shouldSign) {
  //         const psbtThatShouldsign = Psbt.fromBase64(f.shouldSign.psbt);
  //         assert.doesNotThrow(() => {
  //           psbtThatShouldsign.signInputHD(
  //             f.shouldSign.inputToCheck,
  //             bip32.fromBase58(f.shouldSign.xprv),
  //             (f.shouldSign as any).sighashTypes || undefined,
  //           );
  //         });
  //       }

  //       if (f.shouldThrow) {
  //         const psbtThatShouldThrow = Psbt.fromBase64(f.shouldThrow.psbt);
  //         assert.throws(() => {
  //           psbtThatShouldThrow.signInputHD(
  //             f.shouldThrow.inputToCheck,
  //             bip32.fromBase58(f.shouldThrow.xprv),
  //             (f.shouldThrow as any).sighashTypes || undefined,
  //           );
  //         }, new RegExp(f.shouldThrow.errorMessage));
  //         assert.throws(() => {
  //           (psbtThatShouldThrow.signInputHD as any)(
  //             f.shouldThrow.inputToCheck,
  //           );
  //         }, new RegExp('Need HDSigner to sign input'));
  //       }
  //     });
  //   });
  // });

  // describe('signAllInputsHDAsync', () => {
  //   fixtures.signInputHD.checks.forEach(f => {
  //     it(f.description, async () => {
  //       if (f.shouldSign) {
  //         const psbtThatShouldsign = Psbt.fromBase64(f.shouldSign.psbt);
  //         assert.doesNotReject(async () => {
  //           await psbtThatShouldsign.signAllInputsHDAsync(
  //             bip32.fromBase58(f.shouldSign.xprv),
  //             (f.shouldSign as any).sighashTypes || undefined,
  //           );
  //         });
  //       }

  //       if (f.shouldThrow) {
  //         const psbtThatShouldThrow = Psbt.fromBase64(f.shouldThrow.psbt);
  //         assert.rejects(async () => {
  //           await psbtThatShouldThrow.signAllInputsHDAsync(
  //             bip32.fromBase58(f.shouldThrow.xprv),
  //             (f.shouldThrow as any).sighashTypes || undefined,
  //           );
  //         }, new RegExp('No inputs were signed'));
  //         assert.rejects(async () => {
  //           await (psbtThatShouldThrow.signAllInputsHDAsync as any)();
  //         }, new RegExp('Need HDSigner to sign input'));
  //       }
  //     });
  //   });
  // });

  // describe('signAllInputsHD', () => {
  //   fixtures.signInputHD.checks.forEach(f => {
  //     it(f.description, () => {
  //       if (f.shouldSign) {
  //         const psbtThatShouldsign = Psbt.fromBase64(f.shouldSign.psbt);
  //         assert.doesNotThrow(() => {
  //           psbtThatShouldsign.signAllInputsHD(
  //             bip32.fromBase58(f.shouldSign.xprv),
  //             (f.shouldSign as any).sighashTypes || undefined,
  //           );
  //         });
  //       }

  //       if (f.shouldThrow) {
  //         const psbtThatShouldThrow = Psbt.fromBase64(f.shouldThrow.psbt);
  //         assert.throws(() => {
  //           psbtThatShouldThrow.signAllInputsHD(
  //             bip32.fromBase58(f.shouldThrow.xprv),
  //             (f.shouldThrow as any).sighashTypes || undefined,
  //           );
  //         }, new RegExp('No inputs were signed'));
  //         assert.throws(() => {
  //           (psbtThatShouldThrow.signAllInputsHD as any)();
  //         }, new RegExp('Need HDSigner to sign input'));
  //       }
  //     });
  //   });
  // });

  describe('finalizeAllInputs', () => {
    // fixtures.finalizeAllInputs.forEach(f => {
    //   it(`Finalizes inputs of type "${f.type}"`, () => {
    //     const psbt = Psbt.fromBase64(f.psbt);

    //     psbt.finalizeAllInputs();

    //     assert.strictEqual(psbt.toBase64(), f.result);
    //   });
    // });
    it('fails if no script found', () => {
      const psbt = new Psbt();
      psbt.addInput({
        hash:
          '0000000000000000000000000000000000000000000000000000000000000000',
        index: 0,
        script: Buffer.alloc(0),
      });
      assert.throws(() => {
        psbt.finalizeAllInputs();
      }, new RegExp('No script found for input #0'));
      psbt.updateInput(0, {
        witnessUtxo: {
          script: Buffer.from(
            '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
            'hex',
          ),
          value: 2e5,
        },
      });
      assert.throws(() => {
        psbt.finalizeAllInputs();
      }, new RegExp('Can not finalize input #0'));
    });
  });

  describe('addInput', () => {
    fixtures.addInput.checks.forEach(f => {
      it(f.description, () => {
        const psbt = new Psbt();

        if (f.exception) {
          assert.throws(() => {
            psbt.addInput(f.inputData as any);
          }, new RegExp(f.exception));
          assert.throws(() => {
            psbt.addInputs([f.inputData as any]);
          }, new RegExp(f.exception));
        } else {
          assert.doesNotThrow(() => {
            psbt.addInputs([f.inputData as any]);
            if (f.equals) {
              assert.strictEqual(psbt.toBase64(), f.equals);
            }
          });
          assert.throws(() => {
            psbt.addInput(f.inputData as any);
          }, new RegExp('Duplicate input detected.'));
        }
      });
    });
  });

  describe('addOutput', () => {
    fixtures.addOutput.checks.forEach(f => {
      it(f.description, () => {
        const psbt = new Psbt();
        const out = {
          script: Buffer.from(f.outputData.script),
          value:
            typeof f.outputData.value === 'number'
              ? satoshiToConfidentialValue(f.outputData.value)
              : f.outputData.value,
          asset: Buffer.concat([
            Buffer.from('01', 'hex'),
            Buffer.from(f.outputData.asset, 'hex').reverse(),
          ]),
          nonce: Buffer.from('00', 'hex'),
        };
        if (f.exception) {
          assert.throws(() => {
            psbt.addOutput(out as any);
          }, new RegExp(f.exception));
          assert.throws(() => {
            psbt.addOutputs([out as any]);
          }, new RegExp(f.exception));
        } else {
          assert.doesNotThrow(() => {
            psbt.addOutput(out as any);
          });
          assert.doesNotThrow(() => {
            psbt.addOutputs([out as any]);
          });
        }
      });
    });
  });

  describe('setVersion', () => {
    it('Sets the version value of the unsigned transaction', () => {
      const psbt = new Psbt();

      assert.strictEqual(psbt.extractTransaction().version, 2);
      psbt.setVersion(1);
      assert.strictEqual(psbt.extractTransaction(true).version, 1);
    });
  });

  describe('setLocktime', () => {
    it('Sets the nLockTime value of the unsigned transaction', () => {
      const psbt = new Psbt();

      assert.strictEqual(psbt.extractTransaction().locktime, 0);
      psbt.setLocktime(1);
      assert.strictEqual(psbt.extractTransaction(true).locktime, 1);
    });
  });

  describe('setInputSequence', () => {
    it('Sets the sequence number for a given input', () => {
      const psbt = new Psbt();
      psbt.addInput({
        hash:
          '0000000000000000000000000000000000000000000000000000000000000000',
        index: 0,
        script: Buffer.alloc(0),
      });

      assert.strictEqual(psbt.inputCount, 1);
      assert.strictEqual(
        (psbt as any).__CACHE.__TX.ins[0].sequence,
        0xffffffff,
      );
      psbt.setInputSequence(0, 0);
      assert.strictEqual((psbt as any).__CACHE.__TX.ins[0].sequence, 0);
    });

    it('throws if input index is too high', () => {
      const psbt = new Psbt();
      psbt.addInput({
        hash:
          '0000000000000000000000000000000000000000000000000000000000000000',
        index: 0,
        script: Buffer.alloc(0),
      });

      assert.throws(() => {
        psbt.setInputSequence(1, 0);
      }, new RegExp('Input index too high'));
    });
  });

  describe('clone', () => {
    it('Should clone a psbt exactly with no reference', () => {
      const f = fixtures.clone;
      const psbt = Psbt.fromBase64(f.psbt);
      const notAClone = Object.assign(new Psbt(), psbt); // references still active
      const clone = psbt.clone();

      assert.strictEqual(psbt.validateSignaturesOfAllInputs(), true);

      assert.strictEqual(clone.toBase64(), psbt.toBase64());
      assert.strictEqual(clone.toBase64(), notAClone.toBase64());
      assert.strictEqual(psbt.toBase64(), notAClone.toBase64());
      (psbt as any).__CACHE.__TX.version |= 0xff0000;
      assert.notStrictEqual(clone.toBase64(), psbt.toBase64());
      assert.notStrictEqual(clone.toBase64(), notAClone.toBase64());
      assert.strictEqual(psbt.toBase64(), notAClone.toBase64());
    });
  });

  // describe('setMaximumFeeRate', () => {
  //   it('Sets the maximumFeeRate value', () => {
  //     const psbt = new Psbt();

  //     assert.strictEqual((psbt as any).opts.maximumFeeRate, 5000);
  //     psbt.setMaximumFeeRate(6000);
  //     assert.strictEqual((psbt as any).opts.maximumFeeRate, 6000);
  //   });
  // });

  describe('validateSignaturesOfInput', () => {
    const f = fixtures.validateSignaturesOfInput;
    it('Correctly validates a signature', () => {
      const psbt = Psbt.fromBase64(f.psbt);

      assert.strictEqual(psbt.validateSignaturesOfInput(f.index), true);
      assert.throws(() => {
        psbt.validateSignaturesOfInput(f.nonExistantIndex);
      }, new RegExp('No signatures to validate'));
    });

    it('Correctly validates a signature against a pubkey', () => {
      const psbt = Psbt.fromBase64(f.psbt);
      assert.strictEqual(
        psbt.validateSignaturesOfInput(f.index, f.pubkey as any),
        true,
      );
      assert.throws(() => {
        psbt.validateSignaturesOfInput(f.index, f.incorrectPubkey as any);
      }, new RegExp('No signatures for this pubkey'));
    });
  });

  // describe('getFeeRate', () => {
  //   it('Throws error if called before inputs are finalized', () => {
  //     const f = fixtures.getFeeRate;
  //     const psbt = Psbt.fromBase64(f.psbt);

  //     assert.throws(() => {
  //       psbt.getFeeRate();
  //     }, new RegExp('PSBT must be finalized to calculate fee rate'));

  //     psbt.finalizeAllInputs();

  //     assert.strictEqual(psbt.getFeeRate(), f.fee);
  //     (psbt as any).__CACHE.__FEE_RATE = undefined;
  //     assert.strictEqual(psbt.getFeeRate(), f.fee);
  //   });
  // });

  describe('create 1-to-1 transaction', () => {
    const alice = ECPair.fromWIF(
      'cPNMJD4VyFnQjGbGs3kcydRzAbDCXrLAbvH6wTCqs88qg1SkZT3J',
      NETWORKS.regtest,
    );
    const psbt = new Psbt();
    psbt.addInput({
      hash: '9d64f0343e264f9992aa024185319b349586ec4cbbfcedcda5a05678ab10e580',
      index: 0,
      script: Buffer.alloc(0),
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
      sighashType: 1,
    });
    psbt.addOutput({
      asset: Buffer.concat([
        Buffer.from('01', 'hex'),
        Buffer.from(
          '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
          'hex',
        ).reverse(),
      ]),
      nonce: Buffer.from('00', 'hex'),
      script: Buffer.from(
        '76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac',
        'hex',
      ),
      value: satoshiToConfidentialValue(80000),
    });
    psbt.signInput(0, alice);
    assert.throws(() => {
      psbt.setVersion(3);
    }, new RegExp('Can not modify transaction, signatures exist.'));
    psbt.validateSignaturesOfInput(0);
    psbt.finalizeAllInputs();
    assert.throws(() => {
      psbt.setVersion(3);
    }, new RegExp('Can not modify transaction, signatures exist.'));
    assert.strictEqual(
      psbt.extractTransaction().toHex(),
      '02000000000180e510ab7856a0a5cdedfcbb4cec8695349b31854102aa92994f263e34f' +
        '0649d000000006b483045022100f91ae1cb73b3afae669ceb8768a564176effa9ccce4d' +
        '791eabd2b47078bdebd50220154c08cf3e42f3678f5bf7cf461dc4656538dc7c1cd9fc4' +
        '31ae08cd754f3cd4401210251464420fcc98a2e4cd347afe28a32d769287dacd861476a' +
        'b858baa43bd308f3ffffffff010125b251070e29ca19043cf33ccd7324e2ddab03ecc4a' +
        'e0b5e77c4fc0e5cf6c95a010000000000013880001976a91439397080b51ef22c59bd74' +
        '69afacffbeec0da12e88ac00000000',
    );
  });

  // describe('Method return types', () => {
  //   it('fromBuffer returns Psbt type (not base class)', () => {
  //     const psbt = Psbt.fromBuffer(
  //       Buffer.from(
  //         '70736274ff01000a01000000000000000000000000',
  //         'hex', // cHNidP8BAAoBAAAAAAAAAAAAAAAA
  //       ),
  //     );
  //     assert.strictEqual(psbt instanceof Psbt, true);
  //     assert.ok((psbt as any).__CACHE.__TX);
  //   });
  //   it('fromBase64 returns Psbt type (not base class)', () => {
  //     const psbt = Psbt.fromBase64('cHNidP8BAAoBAAAAAAAAAAAAAAAA');
  //     assert.strictEqual(psbt instanceof Psbt, true);
  //     assert.ok((psbt as any).__CACHE.__TX);
  //   });
  //   it('fromHex returns Psbt type (not base class)', () => {
  //     const psbt = Psbt.fromHex('70736274ff01000a01000000000000000000000000');
  //     assert.strictEqual(psbt instanceof Psbt, true);
  //     assert.ok((psbt as any).__CACHE.__TX);
  //   });
  // });

  // describe('Cache', () => {
  //   it('non-witness UTXOs are cached', () => {
  //     const f = fixtures.cache.nonWitnessUtxo;
  //     const psbt = Psbt.fromBase64(f.psbt);
  //     const index = f.inputIndex;

  //     // Cache is empty
  //     assert.strictEqual(
  //       (psbt as any).__CACHE.__NON_WITNESS_UTXO_BUF_CACHE[index],
  //       undefined,
  //     );

  //     // Cache is populated
  //     psbt.updateInput(index, { nonWitnessUtxo: f.nonWitnessUtxo as any });
  //     const value = psbt.data.inputs[index].nonWitnessUtxo;
  //     assert.ok(
  //       (psbt as any).__CACHE.__NON_WITNESS_UTXO_BUF_CACHE[index].equals(value),
  //     );
  //     assert.ok(
  //       (psbt as any).__CACHE.__NON_WITNESS_UTXO_BUF_CACHE[index].equals(
  //         f.nonWitnessUtxo,
  //       ),
  //     );

  //     // Cache is rebuilt from internal transaction object when cleared
  //     psbt.data.inputs[index].nonWitnessUtxo = Buffer.from([1, 2, 3]);
  //     (psbt as any).__CACHE.__NON_WITNESS_UTXO_BUF_CACHE[index] = undefined;
  //     assert.ok((psbt as any).data.inputs[index].nonWitnessUtxo.equals(value));
  //   });
  // });
});

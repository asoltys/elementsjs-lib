import * as bufferutils from './bufferutils';
import { BufferReader, BufferWriter, reverseBuffer } from './bufferutils';
import * as bcrypto from './crypto';
import * as bscript from './script';
import { OPS as opcodes } from './script';
import * as types from './types';

const typeforce = require('typeforce');
const varuint = require('varuint-bitcoin');

function varSliceSize(someScript: Buffer): number {
  const length = someScript.length;

  return varuint.encodingLength(length) + length;
}

const EMPTY_SCRIPT: Buffer = Buffer.allocUnsafe(0);
const EMPTY_WITNESS: Buffer[] = [];
const ZERO: Buffer = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex',
);
const ONE: Buffer = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000001',
  'hex',
);
const WITNESS_SCALE_FACTOR = 4;
const OUTPOINT_ISSUANCE_FLAG = (1 << 31) >>> 0;
const OUTPOINT_PEGIN_FLAG = (1 << 30) >>> 0;
const OUTPOINT_INDEX_MASK = 0x3fffffff;
const MINUS_1 = 4294967295;
// const CONFIDENTIAL_COMMITMENT = 33; // default size of confidential commitments (i.e. asset, value, nonce)
const CONFIDENTIAL_VALUE = 9; // explicit size of confidential values
const VALUE_UINT64_MAX: Buffer = Buffer.from('ffffffffffffffff', 'hex');
const BLANK_OUTPUT = {
  script: EMPTY_SCRIPT,
  asset: ZERO,
  nonce: ZERO,
  value: VALUE_UINT64_MAX,
};

export interface Output {
  script: Buffer;
  value: Buffer;
  asset: Buffer;
  nonce: Buffer;
  amount?: number;
  amountCommitment?: string;
}

export interface Issuance {
  assetBlindingNonce: Buffer;
  assetEntropy: Buffer;
  assetAmount: Buffer;
  tokenAmount: Buffer;
}

export interface Input {
  hash: Buffer;
  index: number;
  script: Buffer;
  sequence: number;
  witness: Buffer[];
  isPegin?: boolean;
  issuance?: Issuance;
}

export class Transaction {
  static readonly DEFAULT_SEQUENCE = 0xffffffff;
  static readonly SIGHASH_ALL = 0x01;
  static readonly SIGHASH_NONE = 0x02;
  static readonly SIGHASH_SINGLE = 0x03;
  static readonly SIGHASH_ANYONECANPAY = 0x80;
  static readonly ADVANCED_TRANSACTION_MARKER = 0x00;
  static readonly ADVANCED_TRANSACTION_FLAG = 0x01;

  static fromBuffer(buffer: Buffer, _NO_STRICT?: boolean): Transaction {
    const bufferReader = new BufferReader(buffer);
    const tx = new Transaction();
    tx.version = bufferReader.readInt32();
    tx.flag = bufferReader.readUInt8();

    // const hasWitnesses = tx.flag === Transaction.ADVANCED_TRANSACTION_FLAG;

    const vinLen = bufferReader.readVarInt();
    for (let i = 0; i < vinLen; ++i) {
      const inHash = bufferReader.readSlice(32);
      let inIndex = bufferReader.readUInt32();
      const inScript = bufferReader.readVarSlice();
      const inSequence = bufferReader.readUInt32();
      let inIsPegin = false;

      let inIssuance: Issuance | undefined;
      if (inIndex !== MINUS_1) {
        if (inIndex & OUTPOINT_ISSUANCE_FLAG) {
          inIssuance = bufferReader.readIssuance();
        }
        if (inIndex & OUTPOINT_PEGIN_FLAG) {
          inIsPegin = true;
        }
        inIndex &= OUTPOINT_INDEX_MASK;
      }

      tx.ins.push({
        hash: inHash,
        index: inIndex,
        script: inScript,
        sequence: inSequence,
        witness: EMPTY_WITNESS,
        isPegin: inIsPegin,
        issuance: inIssuance,
      });
    }
    const voutLen = bufferReader.readVarInt();
    for (let i = 0; i < voutLen; ++i) {
      const assetBuffer = bufferReader.readConfidentialAsset();
      const outValueBuffer = bufferReader.readConfidentialValue();

      let outAmountCommitment: string | undefined;
      let outAmount: number | undefined;

      if (isUncofnidentialValue(outValueBuffer)) {
        outAmount = confidentialValueToSatoshi(outValueBuffer);
      } else outAmountCommitment = outValueBuffer.toString('hex');

      tx.outs.push({
        asset: assetBuffer,
        value: outValueBuffer,
        nonce: bufferReader.readConfidentialNonce(),
        script: bufferReader.readVarSlice(),
        amount: outAmount,
        amountCommitment: outAmountCommitment,
      });
    }
    tx.locktime = bufferReader.readUInt32();
    if (tx.flag === 1) {
      for (let i = 0; i < vinLen; ++i) {
        tx.ins[i].witness = bufferReader.readVector();
      }

      // was this pointless?
      if (!tx.hasWitnesses())
        throw new Error('Transaction has superfluous witness data');
    }

    if (_NO_STRICT) return tx;
    if (bufferReader.offset !== buffer.length)
      throw new Error('Transaction has unexpected data');

    return tx;
  }

  static fromHex(hex: string): Transaction {
    return Transaction.fromBuffer(Buffer.from(hex, 'hex'), false);
  }

  static isCoinbaseHash(buffer: Buffer): boolean {
    typeforce(types.Hash256bit, buffer);
    for (let i = 0; i < 32; ++i) {
      if (buffer[i] !== 0) return false;
    }
    return true;
  }

  version: number = 1;
  locktime: number = 0;
  flag: number = 0;
  ins: Input[] = [];
  outs: Output[] = [];

  isCoinbase(): boolean {
    return (
      this.ins.length === 1 && Transaction.isCoinbaseHash(this.ins[0].hash)
    );
  }

  // A quick and reliable way to validate that all the buffers are of correct type and length
  validateIssuance(
    assetBlindingNonce: Buffer,
    assetEntropy: Buffer,
    assetAmount: Buffer,
    tokenAmount: Buffer,
  ): boolean {
    typeforce(types.Hash256bit, assetBlindingNonce);
    typeforce(types.Hash256bit, assetEntropy);
    typeforce(
      types.oneOf(
        types.ConfidentialValue,
        types.ConfidentialCommitment,
        types.BufferOne,
      ),
      assetAmount,
    );
    typeforce(
      types.oneOf(
        types.ConfidentialValue,
        types.ConfidentialCommitment,
        types.BufferOne,
      ),
      tokenAmount,
    );
    return true;
  }

  addInput(
    hash: Buffer,
    index: number,
    scriptSig: Buffer,
    sequence?: number,
    inIssuance?: Issuance,
  ): number {
    typeforce(
      types.tuple(
        types.Hash256bit,
        types.UInt32,
        types.Buffer,
        types.maybe(types.UInt32),
        types.maybe(types.Object),
      ),
      arguments,
    );

    if (types.Null(sequence)) {
      sequence = Transaction.DEFAULT_SEQUENCE;
    }

    let inIsPegin = false;

    if (index !== MINUS_1) {
      if (index & OUTPOINT_ISSUANCE_FLAG) {
        if (!inIssuance) {
          throw new Error(
            'Issuance flag has been set but the Issuance object is not defined or invalid',
          );
        } else
          this.validateIssuance(
            inIssuance.assetBlindingNonce,
            inIssuance.assetEntropy,
            inIssuance.assetAmount,
            inIssuance.tokenAmount,
          );
      }
      if (index & OUTPOINT_PEGIN_FLAG) {
        inIsPegin = true;
      }
      index &= OUTPOINT_INDEX_MASK;
    }

    // Add the input and return the input's index
    return (
      this.ins.push({
        hash,
        index,
        script: scriptSig || EMPTY_SCRIPT,
        sequence: sequence as number,
        witness: EMPTY_WITNESS,
        isPegin: inIsPegin as boolean,
        issuance: inIssuance,
      }) - 1
    );
  }

  addOutput(
    scriptPubKey: Buffer,
    value: Buffer,
    asset: Buffer,
    nonce: Buffer,
  ): number {
    typeforce(
      types.tuple(
        types.Buffer,
        types.oneOf(
          types.ConfidentialValue,
          types.ConfidentialCommitment,
          types.BufferOne,
        ),
        types.oneOf(types.ConfidentialCommitment, types.BufferOne),
        types.oneOf(types.ConfidentialCommitment, types.BufferOne),
      ),
      arguments,
    );

    // Add the output and return the output's index
    return (
      this.outs.push({
        script: scriptPubKey,
        value,
        asset,
        nonce,
      }) - 1
    );
  }

  hasWitnesses(): boolean {
    return (
      this.flag === 1 &&
      this.ins.some(x => {
        return x.witness.length !== 0;
      })
    );
  }

  weight(): number {
    const base = this.__byteLength(false);
    const total = this.__byteLength(true);
    return base * (WITNESS_SCALE_FACTOR - 1) + total;
  }

  virtualSize(): number {
    const vsize =
      (this.weight() + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
    return Math.floor(vsize);
  }

  byteLength(_ALLOW_WITNESS?: boolean): number {
    return this.__byteLength(_ALLOW_WITNESS || true);
  }

  clone(): Transaction {
    const newTx = new Transaction();
    newTx.version = this.version;
    newTx.locktime = this.locktime;
    newTx.flag = this.flag;

    newTx.ins = this.ins.map(txIn => {
      return {
        hash: txIn.hash,
        index: txIn.index,
        script: txIn.script,
        sequence: txIn.sequence,
        witness: txIn.witness,
        isPegin: txIn.isPegin,
        issuance: txIn.issuance,
      };
    });

    newTx.outs = this.outs.map(txOut => {
      return {
        script: txOut.script,
        value: txOut.value,
        asset: txOut.asset,
        nonce: txOut.nonce,
        amount: (txOut as Output).amount,
        amountCommitment: (txOut as Output).amountCommitment,
      };
    });

    return newTx;
  }

  /**
   * Hash transaction for signing a specific input.
   *
   * Bitcoin uses a different hash for each signed transaction input.
   * This method copies the transaction, makes the necessary changes based on the
   * hashType, and then hashes the result.
   * This hash can then be used to sign the provided transaction input.
   */
  hashForSignature(
    inIndex: number,
    prevOutScript: Buffer,
    hashType: number,
  ): Buffer {
    typeforce(
      types.tuple(types.UInt32, types.Buffer, /* types.UInt8 */ types.Number),
      arguments,
    );

    // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L29
    if (inIndex >= this.ins.length) return ONE;

    // ignore OP_CODESEPARATOR
    const ourScript = bscript.compile(
      bscript.decompile(prevOutScript)!.filter(x => {
        return x !== opcodes.OP_CODESEPARATOR;
      }),
    );

    const txTmp = this.clone();

    // SIGHASH_NONE: ignore all outputs? (wildcard payee)
    if ((hashType & 0x1f) === Transaction.SIGHASH_NONE) {
      txTmp.outs = [];

      // ignore sequence numbers (except at inIndex)
      txTmp.ins.forEach((input, i) => {
        if (i === inIndex) return;

        input.sequence = 0;
      });

      // SIGHASH_SINGLE: ignore all outputs, except at the same index?
    } else if ((hashType & 0x1f) === Transaction.SIGHASH_SINGLE) {
      // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L60
      if (inIndex >= this.outs.length) return ONE;

      // truncate outputs after
      txTmp.outs.length = inIndex + 1;

      // "blank" outputs before
      for (let i = 0; i < inIndex; i++) {
        (txTmp.outs as any)[i] = BLANK_OUTPUT;
      }

      // ignore sequence numbers (except at inIndex)
      txTmp.ins.forEach((input, y) => {
        if (y === inIndex) return;

        input.sequence = 0;
      });
    }

    // SIGHASH_ANYONECANPAY: ignore inputs entirely?
    if (hashType & Transaction.SIGHASH_ANYONECANPAY) {
      txTmp.ins = [txTmp.ins[inIndex]];
      txTmp.ins[0].script = ourScript;

      // SIGHASH_ALL: only ignore input scripts
    } else {
      // "blank" others input scripts
      txTmp.ins.forEach(input => {
        input.script = EMPTY_SCRIPT;
      });
      txTmp.ins[inIndex].script = ourScript;
    }

    // serialize and hash
    const buffer: Buffer = Buffer.allocUnsafe(
      txTmp.__byteLength(false, true) + 4,
    );
    buffer.writeInt32LE(hashType, buffer.length - 4);
    txTmp.__toBuffer(buffer, 0, false, true, true);

    return bcrypto.hash256(buffer);
  }

  hashForWitnessV0(
    inIndex: number,
    prevOutScript: Buffer,
    value: number,
    hashType: number,
  ): Buffer {
    typeforce(
      types.tuple(types.UInt32, types.Buffer, types.Satoshi, types.UInt32),
      arguments,
    );

    let tbuffer: Buffer = Buffer.from([]);
    let toffset: number = 0;

    function writeSlice(slice: Buffer): void {
      toffset += slice.copy(tbuffer, toffset);
    }

    function writeUInt32(i: number): void {
      toffset = tbuffer.writeUInt32LE(i, toffset);
    }

    function writeUInt64(i: number): void {
      toffset = bufferutils.writeUInt64LE(tbuffer, i, toffset);
    }

    function writeVarInt(i: number): void {
      varuint.encode(i, tbuffer, toffset);
      toffset += varuint.encode.bytes;
    }

    function writeVarSlice(slice: Buffer): void {
      writeVarInt(slice.length);
      writeSlice(slice);
    }

    let hashOutputs = ZERO;
    let hashPrevouts = ZERO;
    let hashSequence = ZERO;

    if (!(hashType & Transaction.SIGHASH_ANYONECANPAY)) {
      tbuffer = Buffer.allocUnsafe(36 * this.ins.length);
      toffset = 0;

      this.ins.forEach(txIn => {
        writeSlice(txIn.hash);
        writeUInt32(txIn.index);
      });

      hashPrevouts = bcrypto.hash256(tbuffer);
    }

    if (
      !(hashType & Transaction.SIGHASH_ANYONECANPAY) &&
      (hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
      (hashType & 0x1f) !== Transaction.SIGHASH_NONE
    ) {
      tbuffer = Buffer.allocUnsafe(4 * this.ins.length);
      toffset = 0;

      this.ins.forEach(txIn => {
        writeUInt32(txIn.sequence);
      });

      hashSequence = bcrypto.hash256(tbuffer);
    }

    if (
      (hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
      (hashType & 0x1f) !== Transaction.SIGHASH_NONE
    ) {
      const txOutsSize = this.outs.reduce((sum, output) => {
        return sum + 8 + varSliceSize(output.script);
      }, 0);

      tbuffer = Buffer.allocUnsafe(txOutsSize);
      toffset = 0;

      this.outs.forEach(out => {
        writeUInt64(out.amount!);
        writeVarSlice(out.script);
      });

      hashOutputs = bcrypto.hash256(tbuffer);
    } else if (
      (hashType & 0x1f) === Transaction.SIGHASH_SINGLE &&
      inIndex < this.outs.length
    ) {
      const output = this.outs[inIndex];

      tbuffer = Buffer.allocUnsafe(8 + varSliceSize(output.script));
      toffset = 0;
      writeUInt64(output.amount!);
      writeVarSlice(output.script);

      hashOutputs = bcrypto.hash256(tbuffer);
    }

    tbuffer = Buffer.allocUnsafe(156 + varSliceSize(prevOutScript));
    toffset = 0;

    const input = this.ins[inIndex];
    writeUInt32(this.version);
    writeSlice(hashPrevouts);
    writeSlice(hashSequence);
    writeSlice(input.hash);
    writeUInt32(input.index);
    writeVarSlice(prevOutScript);
    writeUInt64(value);
    writeUInt32(input.sequence);
    writeSlice(hashOutputs);
    writeUInt32(this.locktime);
    writeUInt32(hashType);
    return bcrypto.hash256(tbuffer);
  }

  getHash(forWitness?: boolean): Buffer {
    // wtxid for coinbase is always 32 bytes of 0x00
    if (forWitness && this.isCoinbase()) return Buffer.alloc(32, 0);
    return bcrypto.hash256(
      this.__toBuffer(undefined, undefined, forWitness, true),
    );
  }

  getId(): string {
    // transaction hash's are displayed in reverse order
    return reverseBuffer(this.getHash(false)).toString('hex');
  }

  toBuffer(buffer?: Buffer, initialOffset?: number): Buffer {
    return this.__toBuffer(buffer, initialOffset, true);
  }

  toHex(): string {
    return this.toBuffer(undefined, undefined).toString('hex');
  }

  setInputScript(index: number, scriptSig: Buffer): void {
    typeforce(types.tuple(types.Number, types.Buffer), arguments);

    this.ins[index].script = scriptSig;
  }

  setWitness(index: number, witness: Buffer[]): void {
    typeforce(types.tuple(types.Number, [types.Buffer]), arguments);

    this.ins[index].witness = witness;
  }

  private __byteLength(
    _ALLOW_WITNESS: boolean,
    forSignature?: boolean,
  ): number {
    // const hasWitnesses = _ALLOW_WITNESS && this.hasWitnesses();
    return (
      8 +
      (forSignature ? 0 : 1) +
      varuint.encodingLength(this.ins.length) +
      varuint.encodingLength(this.outs.length) +
      this.ins.reduce((sum, input) => {
        return (
          sum +
          40 +
          varSliceSize(input.script) +
          (input.issuance
            ? 64 +
              input.issuance.assetAmount.length +
              input.issuance.tokenAmount.length
            : 0)
        );
      }, 0) +
      this.outs.reduce((sum, output) => {
        return (
          sum +
          output.asset.length +
          output.value.length +
          output.nonce.length +
          varSliceSize(output.script)
        );
      }, 0)
    );
  }

  private __toBuffer(
    buffer?: Buffer,
    initialOffset?: number,
    _ALLOW_WITNESS?: boolean,
    forceZeroFlag?: boolean,
    forSignature?: boolean,
  ): Buffer {
    if (!buffer)
      buffer = Buffer.allocUnsafe(
        this.__byteLength(_ALLOW_WITNESS!, forSignature),
      ) as Buffer;

    const bufferWriter = new BufferWriter(buffer, initialOffset || 0);

    bufferWriter.writeInt32(this.version);

    const hasWitnesses = _ALLOW_WITNESS && this.hasWitnesses();
    if (!forSignature) {
      bufferWriter.writeUInt8(this.flag);
    }
    // if (hasWitnesses) {
    //   writeUInt8(Transaction.ADVANCED_TRANSACTION_FLAG);
    // } else  {
    //   writeUInt8(Transaction.ADVANCED_TRANSACTION_MARKER)
    // }

    bufferWriter.writeVarInt(this.ins.length);

    this.ins.forEach(txIn => {
      bufferWriter.writeSlice(txIn.hash);
      let prevIndex = txIn.index;
      if (forceZeroFlag === false || forceZeroFlag === undefined) {
        if (txIn.issuance) {
          prevIndex = (prevIndex | OUTPOINT_ISSUANCE_FLAG) >>> 0;
        }
        if (txIn.isPegin) {
          prevIndex = (prevIndex | OUTPOINT_PEGIN_FLAG) >>> 0;
        }
      }
      bufferWriter.writeUInt32(prevIndex);
      bufferWriter.writeVarSlice(txIn.script);
      bufferWriter.writeUInt32(txIn.sequence);

      if (txIn.issuance) {
        bufferWriter.writeSlice(txIn.issuance.assetBlindingNonce);
        bufferWriter.writeSlice(txIn.issuance.assetEntropy);

        bufferWriter.writeSlice(txIn.issuance.assetAmount);
        bufferWriter.writeSlice(txIn.issuance.tokenAmount);
      }
    });

    bufferWriter.writeVarInt(this.outs.length);
    this.outs.forEach(txOut => {
      bufferWriter.writeSlice(txOut.asset);
      bufferWriter.writeSlice(txOut.value);
      bufferWriter.writeSlice(txOut.nonce);
      bufferWriter.writeVarSlice(txOut.script);
    });

    bufferWriter.writeUInt32(this.locktime);

    if (hasWitnesses) {
      this.ins.forEach(input => {
        bufferWriter.writeVector(input.witness);
      });
    }

    // avoid slicing unless necessary
    if (initialOffset !== undefined)
      return buffer.slice(initialOffset, bufferWriter.offset);
    return buffer;
  }
}

export function confidentialValueToSatoshi(value: Buffer): number {
  if (value.length !== CONFIDENTIAL_VALUE && value.readUInt8(0) !== 1) {
    throw new Error(
      'Value must be unconfidential, length or the prefix are not valid',
    );
  }
  const reverseValueBuffer: Buffer = Buffer.allocUnsafe(CONFIDENTIAL_VALUE - 1);
  value.slice(1, CONFIDENTIAL_VALUE).copy(reverseValueBuffer, 0);
  reverseBuffer(reverseValueBuffer);
  return bufferutils.readUInt64LE(reverseValueBuffer, 0);
}

export function satoshiToConfidentialValue(amount: number): Buffer {
  const unconfPrefix: Buffer = Buffer.allocUnsafe(1);
  const valueBuffer: Buffer = Buffer.allocUnsafe(CONFIDENTIAL_VALUE - 1);
  unconfPrefix.writeUInt8(1, 0);
  bufferutils.writeUInt64LE(valueBuffer, amount, 0);
  return Buffer.concat([unconfPrefix, reverseBuffer(valueBuffer)]);
}

function isUncofnidentialValue(value: Buffer): boolean {
  return value.length === CONFIDENTIAL_VALUE && value.readUIntLE(0, 1) === 1;
}

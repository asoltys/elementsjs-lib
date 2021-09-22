import { describe } from 'mocha';
import * as fixtures from './fixtures/block_deserialize.json';
import * as block from '../ts_src/block';

describe('block deserialization ', () => {
  fixtures.test.forEach(f => {
    block.Block.fromBuffer(Buffer.from(f.hex, 'hex'));
  });
});

import Axios from 'axios';

const APIURL = process.env.APIURL || 'http://localhost:3001';
const DRY = process.env.DRY || true;

export async function faucet(address: string): Promise<any> {
  if (DRY === true) {
    return new Promise(
      (res: any): any =>
        res([
          {
            vout: 1,
            value: 100000000,
            txid:
              '7151ad91d42584f71d8ac23e785c347aa81828f2f7d08435b330e52db02a799e',
            asset:
              '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
          },
        ]),
    );
  }
  let resp = await Axios.post(`${APIURL}/faucet`, { address });
  if (resp.status !== 200) {
    throw new Error('Invalid address');
  }
  sleep(1000);
  while (!resp.data.length) {
    sleep(1000);
    resp = await Axios.get(`${APIURL}/address/${address}/utxo`);
  }
  return resp.data;
}

export async function fetchTx(txId: string): Promise<string> {
  if (DRY === true) {
    return new Promise(
      (res: any): any =>
        res(
          '0200000000019bb9df0a0c1bd4764e4aa201a357f43fec0d268359b3a5b3bdab41643' +
            'e1da5120000000000fdffffff030125b251070e29ca19043cf33ccd7324e2ddab03ec' +
            'c4ae0b5e77c4fc0e5cf6c95a01000775f054114ce00017a9140e13bb04880564672ba' +
            '2d15dfd1ae8ec2343e4e2870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae' +
            '0b5e77c4fc0e5cf6c95a010000000005f5e100001976a914659bedb5d3d3c7ab12d7f' +
            '85323c3a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae' +
            '0b5e77c4fc0e5cf6c95a010000000000001220000065000000',
        ),
    );
  }
  const resp = await Axios.get(`${APIURL}/tx/${txId}/hex`);
  return resp.data;
}

export async function broadcast(txHex: string): Promise<string> {
  if (DRY === true) {
    return new Promise(
      (res: any): any =>
        res('d0416622fce79b549a4d9465c1c3012bfb7a2513fe695ac38771790eaad53456'),
    );
  }
  const resp = await Axios.get(`${APIURL}/broadcast?tx=${txHex}`);
  return resp.data;
}

function sleep(ms: number): Promise<any> {
  return new Promise((res: any): any => setTimeout(res, ms));
}

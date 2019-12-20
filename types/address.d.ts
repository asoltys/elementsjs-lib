import { Network } from './networks';
export interface Base58CheckResult {
    hash: Buffer;
    version: number;
}
export interface Bech32Result {
    version: number;
    prefix: string;
    data: Buffer;
}
export interface FindAddressTypeResult {
    version: number;
    confidential: boolean;
}
export declare function findAddressType(address: string, network: Network): FindAddressTypeResult;
export declare function blindingPubKeyFromConfidentialAddress(address: string): Buffer;
export declare function confidentialAddressFromAddress(address: string, blindkey: string, network: Network): string;
export declare function confidentialAddressToAddress(address: string, network: Network): string;
export declare function fromBase58Check(address: string): Base58CheckResult;
export declare function fromBech32(address: string): Bech32Result;
export declare function toBase58Check(hash: Buffer, version: number): string;
export declare function toBech32(data: Buffer, version: number, prefix: string): string;
export declare function fromOutputScript(output: Buffer, network?: Network): string;
export declare function toOutputScript(address: string, network?: Network): Buffer;

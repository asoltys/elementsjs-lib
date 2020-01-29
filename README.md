# LiquidJS

[![Build Status](https://travis-ci.org/vulpemventures/liquidjs-lib.svg?branch=master)](https://travis-ci.org/vulpemventures/liquidjs-lib)

[![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)

The following library forks `bitcoinjs/bitcoinjs-lib` and contains modifications that are necessary for support of elements-based blockchains such as [Blockstream Liquid](https://blockstream.com/liquid)

Released under the terms of the [MIT LICENSE](LICENSE).

## Examples

The below examples are implemented as integration tests (as in [bitcoinjs-lib](https://github.com/bitcoinjs/bitcoinjs-lib#examples)).

- [Generate a random Liquid address](./test/integration/addresses.spec.ts)
- [Create a 1-to-1 Transaction](./test/integration/transaction.spec.ts)

# blake2b-solidity

![tests and coverage](https://github.com/dhl/blake2b-solidity/actions/workflows/test.yml/badge.svg)
[![codecov](https://codecov.io/github/dhl/blake2b-solidity/graph/badge.svg?token=4WOC5GEC7H)](https://codecov.io/github/dhl/blake2b-solidity)

`blake2b-solidity` is a high-performance Solidity implementation of the [BLAKE2b](https://www.blake2.net/) hash
function.

## Table of Contents

- [Motivation](#motivation)
- [Features](#features)
- [Gas Usage](#gas-usage)
- [Testing](#testing)
- [Acknowledgements](#acknowledgements)
- [References](#references)
- [License](#license)

## Motivation

The primary goal of this project is to provide the most efficient and feature-complete BLAKE2b implementation for the
Ethereum Virtual Machine (EVM) to support interoperability with other cryptographic applications and Proof-of-Work (PoW)
algorithms.

BLAKE2b is renowned for its speed, security, and simplicity. Notable applications of BLAKE2b in blockchain include:

* [Zcash](https://z.cash): A privacy-focused blockchain that uses BLAKE2b for its Equihash proof-of-work algorithm.
* [IPFS](https://ipfs.tech): A decentralized file storage system that uses BLAKE2b for content addressing.

The lack of full native support for BLAKE2b in the Ethereum Virtual Machine (EVM) poses challenges for application
developers to validate and interoperate with these applications within Solidity smart contracts. Consequently,
developers are often forced to either adopt another hashing algorithm such as keccak-256 or sha256, both of which enjoy
native support in EVM, or trust validation performed by some trusted operator.

Efforts such as [EIP-152](https://eips.ethereum.org/EIPS/eip-152)
and [Project Alchemy](https://github.com/Consensys/Project-Alchemy/tree/master/contracts/BLAKE2b) by Consensys have
attempted to provide a BLAKE2/BLAKE2b implementation. However, EIP-152 only provides a precompiled F compress function
instead of the full hash function, and Project Alchemy, which started before EIP-152, could not take advantage of the
precompile compress function, did not pass all reference implementation test vectors, and is no longer unmaintained.

`blake2b-solidity` aims to address these limitations by providing a high-performance, gas-efficient, and
feature-complete BLAKE2b implementation in Solidity, enabling developers to leverage the benefits of BLAKE2b directly
within Ethereum smart contracts.

## Features

1. Gas-efficient ⛽️ (See [Gas Usage](#gas-usage)).
2. Full support for variable input (tested to accept ~750KB of data given block gas limit of 30 million).
3. Full support for variable digest output size (1 up to 64 bytes).
4. Supports salting.
5. Supports personalized hashes.
6. Zero external dependency.

## Gas Usage

The `blake2b-solidity` implementation is gas efficient.

We benchmarked our implementation against other available hash functions by hashing the test vectors in the test suite
and returning the result in `bytes`. Test vectors that involve optional extensions (keying, salting, personalization)
were excluded in our benchmark.

| Hash Function          | Implementation        | Average Gas Cost | Digest Size (bits) | Relative Gas Cost (%) |
|------------------------|-----------------------|------------------|--------------------|-----------------------|
| Blake2b (Consensys)    | Solidity              | 255,427          | 512                | 1047%                 |
| Blake2b (this project) | Solidity + Precompile | 28,618           | 512                | 117%                  |
| ripemd160              | Native                | 25,719           | 160                | 105%                  |
| sha256                 | Native                | 24,834           | 256                | 102%                  |
| keccak256              | Native                | 24,400           | 256                | 100%                  |

## Testing

This project includes a comprehensive test suite to ensure strict conformance to the BLAKE2b specification.

Core test vectors are taken from the
BLAKE2b [reference implementation](https://github.com/BLAKE2/BLAKE2/blob/5cbb39c9ef8007f0b63723e3aea06cd0887e36ad/testvectors/blake2-kat.json).

Additional test vectors are taken from official [libsodium](https://github.com/jedisct1/libsodium) tests.

## Acknowledgements

We are grateful
to [Tjaden Hess](https://github.com/tjade273), [Matt Luongo](https://github.com/mhluongo), [Piotr Dyraga](https://github.com/pdyraga),
and [James Hancock](https://github.com/MadeOfTin) for their contributions to EIP-152 and the initial reference
implementation of the BLAKE2b F compression function in [go-ethereum](https://github.com/ethereum/go-ethereum).

We would also like to thank [Emil Bay](https://github.com/emilbayes) for making his work on BLAKE2b test vectors
available.

## References

1. [RFC-7693: The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)](https://datatracker.ietf.org/doc/html/rfc7693)
2. [BLAKE2: Simpler, Smaller, Fast as MD5](https://www.blake2.net/blake2.pdf)
3. [EIP-152: Add BLAKE2 compression function `F` precompile](https://eips.ethereum.org/EIPS/eip-152)

## License

`blake2b-solidity` is released under the [MIT License](LICENSE).
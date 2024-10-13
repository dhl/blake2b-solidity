// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright 2024 David Leung

pragma solidity 0.8.27;

error OutputLengthCannotBeZero();
error OutputLengthExceeded();
error KeyLengthExceeded();

library BLAKE2b {
    struct Context {
        uint128 t; // processed bytes counter
        uint128 c; // message block buffer counter
    }

    // Initial state vectors
    //
    // IV 0-3 as numerical values
    //    0x6A09E667F3BCC908 0xbb67ae8584caa73b 0x3c6ef372fe94f82b 0xa54ff53a5f1d36f1
    // IV 0-3 in little-endian encoding
    //      08c9bcf367e6096a   3ba7ca8485ae67bb   2bf894fe72f36e3c   f1361d5f3af54fa5
    // IV 0-3 XOR with parameter block set to sequential mode:
    //      0000010100000000   0000000000000000   0000000000000000   0000000000000000
    // XOR Result:
    //      08c9bdf267e6096a   3ba7ca8485ae67bb   2bf894fe72f36e3c   f1361d5f3af54fa5
    //
    // IV 4-7 as numerical values
    //     0x510e527fade682d1 0x9b05688c2b3e6c1f 0x1f83d9abfb41bd6b 0x5be0cd19137e2179
    // IV 4-7 as little-endian encoded bytes
    //       d182e6ad7f520e51   1f6c3e2b8c68059b   6bbd41fbabd9831f   79217e1319cde05b
    bytes32 private constant IS0 = bytes32(hex"08c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5");
    bytes32 private constant IS1 = bytes32(hex"d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b");

    function hash(
        bytes memory input,
        bytes memory key,
        bytes memory salt,
        bytes memory personalization,
        uint256 outlen
    ) internal view returns (bytes memory out) {
        if (outlen == 0) {
            revert OutputLengthCannotBeZero();
        }

        if (outlen > 64) {
            revert OutputLengthExceeded();
        }

        if (key.length > 64) {
            revert KeyLengthExceeded();
        }

        Context memory ctx;
        out = new bytes(outlen);

        bytes memory state = init(ctx, outlen, key, salt, personalization);
        update(ctx, state, input);

        finalize(ctx, state, out, outlen);
    }

    function init(
        Context memory ctx,
        uint256 outlen,
        bytes memory key,
        bytes memory salt,
        bytes memory person
    ) internal view returns (bytes memory state) {
        // Initialize state by XORing initial state vectors with parameter block.
        // Note the parameter block is broken up into different if statements to save gas.
        bytes32[2] memory h = [IS0 ^ bytes32(outlen << 248), IS1];

        if (key.length > 0) {
            h[0] ^= bytes32(key.length << 240);
        }

        if (salt.length > 0) {
            h[1] ^= bytes32(salt);
        }

        if (person.length > 0) {
            h[1] ^= bytes32(person) >> 128;
        }

        // Copy state into the state buffer, encoded to the specification of EIP-152
        state = new bytes(213);
        assembly {
            mstore8(add(state, 35), 12)
            mcopy(add(state, 36), h, 64)
        }

        if (key.length > 0) {
            update(ctx, state, key);
            ctx.c = 128;
        }
    }

    function update(Context memory ctx, bytes memory state, bytes memory input) internal view {
        uint128 t = ctx.t;
        uint128 c = ctx.c;
        uint256 inputOffset = 0;
        uint256 inputLength = input.length;

        // Read input in 128-byte chunks
        while (inputOffset + 128 <= inputLength) {
            // If the buffer is full, process it
            if (c == 128) {
                unchecked {
                    t += 128;
                }

                bytes8[2] memory tt = [bytes8(reverseByteOrder(uint64(t))), bytes8(reverseByteOrder(uint64(t >> 64)))];

                assembly {
                    mcopy(add(state, 228), tt, 16)
                    if iszero(staticcall(not(0), 0x09, add(state, 32), 0xd5, add(state, 36), 0x40)) {
                        revert(0, 0)
                    }
                }

                c = 0;
            }

            assembly {
                mcopy(add(add(state, 100), c), add(input, add(32, inputOffset)), 128)
            }

            unchecked {
                c = 128;
                inputOffset += 128;
            }
        }

        // Handle sub-128-byte chunk
        if (inputOffset < inputLength) {
            // If the buffer is full, process it
            if (c == 128) {
                unchecked {
                    t += 128;
                }

                bytes8[2] memory tt = [bytes8(reverseByteOrder(uint64(t))), bytes8(reverseByteOrder(uint64(t >> 64)))];

                assembly {
                    mcopy(add(state, 228), tt, 16)
                    if iszero(staticcall(not(0), 0x09, add(state, 32), 0xd5, add(state, 36), 0x40)) {
                        revert(0, 0)
                    }
                }

                c = 0;
                assembly {
                    mstore(add(state, 100), 0)
                    mstore(add(state, 132), 0)
                    mstore(add(state, 164), 0)
                    mstore(add(state, 196), 0)
                }
            }

            // Safe casting, because left is always less than 128
            uint128 left = uint128(inputLength - inputOffset);

            assembly {
                mcopy(add(add(state, 100), c), add(input, add(32, inputOffset)), left)
            }

            unchecked {
                c += left;
            }
        }

        ctx.t = t;
        ctx.c = c;
    }

    function finalize(Context memory ctx, bytes memory state, bytes memory out, uint256 outlen) internal view {
        uint128 t = ctx.t;
        unchecked {
            t += ctx.c;
        }

        assembly {
            mstore8(add(state, 244), true)
        }

        bytes8[2] memory tt = [bytes8(reverseByteOrder(uint64(t))), bytes8(reverseByteOrder(uint64(t >> 64)))];

        assembly {
            mcopy(add(state, 228), tt, 16)
            if iszero(staticcall(not(0), 0x09, add(state, 32), 0xd5, add(state, 36), 0x40)) {
                revert(0, 0)
            }
            mcopy(add(out, 32), add(state, 36), outlen)
        }
    }

    function reverseByteOrder(uint64 input) internal pure returns (uint64 v) {
        v = input;
        v = ((v & 0xFF00FF00FF00FF00) >> 8) | ((v & 0x00FF00FF00FF00FF) << 8);
        v = ((v & 0xFFFF0000FFFF0000) >> 16) | ((v & 0x0000FFFF0000FFFF) << 16);
        v = (v >> 32) | (v << 32);
    }
}

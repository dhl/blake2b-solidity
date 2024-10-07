// SPDX-License-Identifier: MIT
// Copyright (c) 2024 David Leung

pragma solidity 0.8.27;

error OutputLengthCannotBeZero();
error OutputLengthExceeded();
error KeyLengthExceeded();

library BLAKE2b {
    struct Context {
        bytes32[4] m; // input buffer
        bytes32[2] h; // state
        uint128 t; // processed bytes counter
        uint64 c; // input buffer counter
        uint256 outlen; // digest output size
    }

    function hash(
        bytes memory input,
        bytes memory key,
        bytes memory salt,
        bytes memory personalization,
        uint64 outlen
    ) internal view returns (bytes memory) {
        Context memory ctx;

        init(ctx, outlen, key, salt, personalization);
        update(ctx, input);
        return finalize(ctx);
    }

    function init(
        Context memory ctx,
        uint64 outlen,
        bytes memory key,
        bytes memory salt,
        bytes memory person
    ) internal view {
        if (outlen == 0) {
            revert OutputLengthCannotBeZero();
        }

        if (outlen > 64) {
            revert OutputLengthExceeded();
        }

        if (key.length > 64) {
            revert KeyLengthExceeded();
        }

        // Initialize state by XORing IV with parameter block. Note the IV is in little-endian encoding.
        ctx.h[0] =
            bytes32(hex"08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5") ^
            bytes32(uint256(reverseByteOrder(0x01010000 ^ (uint64(key.length) << 8) ^ outlen)) << 192);
        ctx.h[1] =
            bytes32(hex"d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b") ^
            (bytes32(salt) | (bytes32(person) >> 128));

        ctx.outlen = outlen;

        if (key.length > 0) {
            update(ctx, key);
            ctx.c = 128;
        }
    }

    function update(Context memory ctx, bytes memory input) internal view {
        uint64 c = ctx.c;
        bytes32[4] memory m = ctx.m;
        uint256 inputLength = input.length;
        uint256 inputOffset = 0;

        // Read input in 32-byte chunks
        while (inputOffset + 32 <= inputLength) {
            if (c == 128) {
                unchecked {
                    ctx.t += c;
                }

                compress(ctx, false);

                c = 0;
                assembly {
                    mstore(m, 0)
                    mstore(add(m, 32), 0)
                    mstore(add(m, 64), 0)
                    mstore(add(m, 96), 0)
                }
            }

            assembly {
                mstore(add(m, c), mload(add(input, add(32, inputOffset))))
            }

            unchecked {
                c += 32;
                inputOffset += 32;
            }
        }

        // Handle remaining bytes one at a time
        while (inputOffset < inputLength) {
            if (c == 128) {
                unchecked {
                    ctx.t += c;
                }

                compress(ctx, false);

                c = 0;
                assembly {
                    mstore(m, 0)
                    mstore(add(m, 32), 0)
                    mstore(add(m, 64), 0)
                    mstore(add(m, 96), 0)
                }
            }

            assembly {
                mstore8(add(m, c), byte(0, mload(add(input, add(32, inputOffset)))))
            }

            unchecked {
                ++c;
                ++inputOffset;
            }
        }

        ctx.c = c;
    }

    function finalize(Context memory ctx) internal view returns (bytes memory out) {
        bytes32[2] memory h = ctx.h;
        unchecked {
            ctx.t += ctx.c;
        }

        // Compress with finalization flag.
        // The compress function is not called to save gas
        bytes memory args = abi.encodePacked(
            uint32(12),
            h[0],
            h[1],
            ctx.m[0],
            ctx.m[1],
            ctx.m[2],
            ctx.m[3],
            bytes8(reverseByteOrder(uint64(ctx.t))),
            bytes8(reverseByteOrder(uint64(ctx.t >> 64))),
            true
        );

        assembly {
            if iszero(staticcall(not(0), 0x09, add(args, 32), 0xd5, h, 0x40)) {
                revert(0, 0)
            }
        }

        if (ctx.outlen == 64) {
            out = abi.encodePacked(h[0], h[1]);
        } else {
            uint256 i = 0;

            out = new bytes(ctx.outlen);

            // Write 32 bytes at a time
            while (i + 32 <= ctx.outlen) {
                assembly {
                    mstore(add(out, add(32, i)), mload(add(h, i)))
                    i := add(i, 32)
                }
            }

            // Write remaining bytes one at a time
            for (; i < ctx.outlen; ++i) {
                out[i] = h[i / 32][i % 32];
            }
        }
    }

    function compress(Context memory ctx, bool finalFlag) internal view {
        bytes32[2] memory h = ctx.h;
        bytes memory args = abi.encodePacked(
            uint32(12),
            h[0],
            h[1],
            ctx.m[0],
            ctx.m[1],
            ctx.m[2],
            ctx.m[3],
            bytes8(reverseByteOrder(uint64(ctx.t))),
            bytes8(reverseByteOrder(uint64(ctx.t >> 64))),
            finalFlag
        );

        assembly {
            if iszero(staticcall(not(0), 0x09, add(args, 32), 0xd5, h, 0x40)) {
                revert(0, 0)
            }
        }
    }

    function reverseByteOrder(uint64 input) internal pure returns (uint64 v) {
        v = input;
        v = ((v & 0xFF00FF00FF00FF00) >> 8) | ((v & 0x00FF00FF00FF00FF) << 8);
        v = ((v & 0xFFFF0000FFFF0000) >> 16) | ((v & 0x0000FFFF0000FFFF) << 16);
        v = (v >> 32) | (v << 32);
    }
}

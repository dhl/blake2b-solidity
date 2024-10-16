// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright 2024 David Leung

pragma solidity 0.8.27;

error OutputLengthCannotBeZero();
error OutputLengthExceeded();
error KeyLengthExceeded();
error InputLengthExceeded();

library BLAKE2b {
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

    uint256 private constant BLOCK_SIZE_BYTES = 128;

    function hash(
        bytes memory input,
        bytes memory key,
        bytes memory salt,
        bytes memory personalization,
        uint256 digestLen
    ) internal view returns (bytes memory digest) {
        if (digestLen == 0) {
            revert OutputLengthCannotBeZero();
        }

        if (digestLen > 64) {
            revert OutputLengthExceeded();
        }

        if (key.length > 64) {
            revert KeyLengthExceeded();
        }

        ////////////////////////////////////////////
        // INITIALIZATION
        ////////////////////////////////////////////

        // See https://eips.ethereum.org/EIPS/eip-152#specification
        // We refer to the collective inputs to the F function as the context.
        bytes memory context = new bytes(213);

        bytes32[2] memory h = [IS0 ^ bytes32(digestLen << 248), IS1];

        if (key.length > 0) {
            h[0] ^= bytes32(key.length << 240);
        }

        if (salt.length > 0) {
            h[1] ^= bytes32(salt);
        }

        if (personalization.length > 0) {
            h[1] ^= bytes32(personalization) >> 128;
        }

        assembly {
            // Set the round count (12 for BLAKE2b) in the context
            mstore8(add(context, 35), 12)
            // Copy the initial hash state to the context
            mcopy(add(context, 36), h, 64)
        }

        uint256 bytesProcessed = 0;
        uint256 bufferUsed = 0;

        // If key is present, copy it to the context, and compress it as a full block
        if (key.length > 0) {
            assembly {
                // key length := mload(key)
                // pointer to key := add(key, 32)
                // pointer to state := add(context, 100)
                mcopy(add(context, 100), add(key, 32), mload(key))
            }

            bufferUsed = BLOCK_SIZE_BYTES;
        }

        ////////////////////////////////////////////
        // INPUT PROCESSING
        ////////////////////////////////////////////

        uint256 readInputOffset = 0;

        // Read full block chunks
        while (readInputOffset + BLOCK_SIZE_BYTES <= input.length) {
            if (bufferUsed == BLOCK_SIZE_BYTES) {
                unchecked {
                    bytesProcessed += BLOCK_SIZE_BYTES;
                }

                bytes8[1] memory tt = [bytes8(reverseByteOrder(uint64(bytesProcessed)))];

                assembly {
                    mcopy(add(context, 228), tt, 8)
                    if iszero(staticcall(not(0), 0x09, add(context, 32), 0xd5, add(context, 36), 0x40)) {
                        revert(0, 0)
                    }
                }

                bufferUsed = 0;
            }

            assembly {
                mcopy(add(add(context, 100), bufferUsed), add(input, add(32, readInputOffset)), BLOCK_SIZE_BYTES)
            }

            unchecked {
                bufferUsed = BLOCK_SIZE_BYTES;
                readInputOffset += BLOCK_SIZE_BYTES;
            }
        }

        // Handle partial block
        if (readInputOffset < input.length) {
            if (bufferUsed == BLOCK_SIZE_BYTES) {
                unchecked {
                    bytesProcessed += BLOCK_SIZE_BYTES;
                }

                bytes8[1] memory tt = [bytes8(reverseByteOrder(uint64(bytesProcessed)))];

                assembly {
                    mcopy(add(context, 228), tt, 8)
                    if iszero(staticcall(not(0), 0x09, add(context, 32), 0xd5, add(context, 36), 0x40)) {
                        revert(0, 0)
                    }
                }

                bufferUsed = 0;

                // Reset the message buffer, as we are going to process a partial block
                assembly {
                    mstore(add(context, 100), 0)
                    mstore(add(context, 132), 0)
                    mstore(add(context, 164), 0)
                    mstore(add(context, 196), 0)
                }
            }

            assembly {
                // left = input.length - inputOffset. Safe casting, because left is always less than 128
                let left := sub(mload(input), readInputOffset)
                mcopy(add(add(context, 100), bufferUsed), add(input, add(32, readInputOffset)), left)
                bufferUsed := add(bufferUsed, left)
            }
        }

        ////////////////////////////////////////////
        // FINAL
        ////////////////////////////////////////////

        unchecked {
            bytesProcessed += bufferUsed;
        }

        bytes8[1] memory tt = [bytes8(reverseByteOrder(uint64(bytesProcessed)))];

        assembly {
            // Set final block flag
            mstore8(add(context, 244), 1)
            mcopy(add(context, 228), tt, 8)
            if iszero(staticcall(not(0), 0x09, add(context, 32), 0xd5, add(context, 36), 0x40)) {
                revert(0, 0)
            }

            // digest = new bytes(digestLen)
            digest := mload(0x40)
            mstore(0x40, add(digest, add(digestLen, 0x20)))
            mstore(digest, digestLen)

            // copy final hash state to digest
            mcopy(add(digest, 32), add(context, 36), digestLen)
        }
    }

    function reverseByteOrder(uint64 input) internal pure returns (uint64 v) {
        v = input;
        v = ((v & 0xFF00FF00FF00FF00) >> 8) | ((v & 0x00FF00FF00FF00FF) << 8);
        v = ((v & 0xFFFF0000FFFF0000) >> 16) | ((v & 0x0000FFFF0000FFFF) << 16);
        v = (v >> 32) | (v << 32);
    }
}

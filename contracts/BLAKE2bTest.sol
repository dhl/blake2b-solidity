// SPDX-License-Identifier: MIT
// Copyright (c) 2024 David Leung

pragma solidity 0.8.27;

import {BLAKE2b} from "./BLAKE2b.sol";

contract BLAKE2bTest {
    function hash(
        bytes memory input,
        bytes memory key,
        bytes memory salt,
        bytes memory personalization,
        uint64 outlen
    ) public view returns (bytes memory) {
        return BLAKE2b.hash(input, key, salt, personalization, outlen);
    }

    // solc-disable-next-line
    function callHash(
        bytes memory input,
        bytes memory key,
        bytes memory salt,
        bytes memory personalization,
        uint64 outlen
    ) public returns (bytes memory) {
        return BLAKE2b.hash(input, key, salt, personalization, outlen);
    }

    // solc-disable-next-line
    function callRipemd160(bytes memory input) public returns (bytes memory) {
        return abi.encodePacked(ripemd160(input));
    }

    // solc-disable-next-line
    function callSha256(bytes memory input) public returns (bytes memory) {
        return abi.encodePacked(sha256(input));
    }

    // solc-disable-next-line
    function callKeccak256(bytes memory input) public returns (bytes memory) {
        return abi.encodePacked(keccak256(input));
    }
}

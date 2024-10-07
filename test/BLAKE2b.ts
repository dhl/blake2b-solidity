import crypto from "node:crypto";

import { expect } from "chai";
import hre from "hardhat";
import TEST_VECTORS from "./fixtures/test-vectors.json";
import { BLAKE2bTest } from "../typechain-types";

describe("BLAKE2b", function () {
  let blake2b: BLAKE2bTest;

  before(async function () {
    const BLAKE2b = await hre.ethers.getContractFactory("BLAKE2bTest");
    blake2b = await BLAKE2b.deploy();
  });

  describe("Input length validations", function () {
    it("should revert if outlen is 0", async function () {
      const outlen = 0;
      const key = crypto.randomBytes(32);
      const salt = crypto.randomBytes(16);
      const personalization = crypto.randomBytes(16);
      const input = crypto.randomBytes(64);

      await expect(blake2b.hash(input, key, salt, personalization, outlen)).to.be.revertedWithCustomError(
        blake2b,
        "OutputLengthCannotBeZero",
      );
    });

    it("should revert if outlen is greater than 64", async function () {
      const outlen = 65;
      const key = crypto.randomBytes(32);
      const salt = crypto.randomBytes(16);
      const personalization = crypto.randomBytes(16);
      const input = crypto.randomBytes(64);

      await expect(blake2b.hash(input, key, salt, personalization, outlen)).to.be.revertedWithCustomError(
        blake2b,
        "OutputLengthExceeded",
      );
    });

    it("should revert if key length is greater than 64", async function () {
      const outlen = 32;
      const key = crypto.randomBytes(65);
      const salt = crypto.randomBytes(16);
      const personalization = crypto.randomBytes(16);
      const input = crypto.randomBytes(64);

      await expect(blake2b.hash(input, key, salt, personalization, outlen)).to.be.revertedWithCustomError(
        blake2b,
        "KeyLengthExceeded",
      );
    });
  });

  describe("Test Vectors - Reference", function () {
    for (const vector of TEST_VECTORS) {
      const { input, key, salt, personal, out, outlen } = vector;

      it(`input=${input} key=${key}`, async function () {
        const result = await blake2b.hash(`0x${input}`, `0x${key}`, `0x${salt}`, `0x${personal}`, outlen);

        // For gas benchmarking. We only want to test with basic vectors.
        if (key === "") {
          await blake2b.callHash(`0x${input}`, `0x${key}`, `0x${salt}`, `0x${personal}`, outlen);
          await blake2b.callRipemd160(`0x${input}`);
          await blake2b.callSha256(`0x${input}`);
          await blake2b.callKeccak256(`0x${input}`);
        }

        expect(result).to.equal(`0x${out}`);
      });
    }
  });
});

const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

describe("CredentialRevocationRegistry", function () {
  let RevocationRegistry, revocationRegistry, issuer1, issuer2;
  const vcID = "550e8400-e29b-41d4-a716-446655440000";
  const ttl = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now

  beforeEach(async function () {
    [issuer1, issuer2] = await ethers.getSigners();
    RevocationRegistry = await ethers.getContractFactory(
      "CredentialRevocationRegistry"
    );
    revocationRegistry = await RevocationRegistry.deploy();
    await revocationRegistry.waitForDeployment();
  });

  it("Should allow an issuer to issue a credential with TTL", async function () {
    await expect(
      revocationRegistry.connect(issuer1).issueCredential(vcID, ttl)
    ).to.emit(revocationRegistry, "CredentialIssued");

    expect(await revocationRegistry.getIssuer(vcID)).to.equal(issuer1.address);
    expect(await revocationRegistry.getTTL(vcID)).to.equal(ttl);
  });

  it("Should allow the issuer to revoke a credential before expiry", async function () {
    await revocationRegistry.connect(issuer1).issueCredential(vcID, ttl);
    await expect(
      revocationRegistry.connect(issuer1).revokeCredential(vcID)
    ).to.emit(revocationRegistry, "CredentialRevoked");

    expect(await revocationRegistry.isRevoked(vcID)).to.be.true;
  });

  it("Should prevent revocation by non-issuers", async function () {
    await revocationRegistry.connect(issuer1).issueCredential(vcID, ttl);
    await expect(
      revocationRegistry.connect(issuer2).revokeCredential(vcID)
    ).to.be.revertedWith("Not the credential issuer");
  });

  it("should not allow issuing a credential with an empty vcID", async function () {
    await expect(
      revocationRegistry.connect(issuer1).issueCredential("", ttl)
    ).to.be.revertedWith("vcID cannot be empty");
  });

  it("should not allow issuing a credential with a TTL in the past", async function () {
    const pastTTL = Math.floor(Date.now() / 1000) - 3600; // 1 hour in the past
    await expect(
      revocationRegistry.connect(issuer1).issueCredential(vcID, pastTTL)
    ).to.be.revertedWith("TTL must be in the future");
  });

  it("Should return true for expired credentials", async function () {
    const shortTTL = (await time.latest()) + 5; // 5 seconds in the future

    await revocationRegistry.connect(issuer1).issueCredential(vcID, shortTTL);

    // Increase time by 6 seconds
    await time.increase(6);

    // Now, the credential should be expired
    expect(await revocationRegistry.isRevoked(vcID)).to.be.true;
  });

  it("Should return false for non-expired, non-revoked credentials", async function () {
    await revocationRegistry.connect(issuer1).issueCredential(vcID, ttl);
    expect(await revocationRegistry.isRevoked(vcID)).to.be.false;
  });
});

const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

describe("CredentialRevocationRegistry", function () {
  let RevocationRegistry, revocationRegistry, issuer1, issuer2;
  const holder = "0x1234567890123456789012345678901234567890";
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
      revocationRegistry.connect(issuer1).issueCredential(holder, vcID, ttl)
    ).to.emit(revocationRegistry, "CredentialIssued");
  });

  it("Should allow the issuer to revoke a credential before expiry", async function () {
    await revocationRegistry
      .connect(issuer1)
      .issueCredential(holder, vcID, ttl);
    await expect(
      revocationRegistry.connect(issuer1).revokeCredential(holder, vcID)
    ).to.emit(revocationRegistry, "CredentialRevoked");

    expect(await revocationRegistry.isRevoked(vcID)).to.be.true;
  });

  it("Should prevent revocation by non-issuers", async function () {
    await revocationRegistry
      .connect(issuer1)
      .issueCredential(holder, vcID, ttl);
    await expect(
      revocationRegistry.connect(issuer2).revokeCredential(holder, vcID)
    ).to.be.revertedWith("Not the credential issuer");
  });

  it("Should prevent revocation of non-existent credentials", async function () {
    await expect(
      revocationRegistry.connect(issuer1).revokeCredential(holder, vcID)
    ).to.be.revertedWith("Credential not issued");
  });

  it("should not allow issuing a credential with an empty vcID", async function () {
    await expect(
      revocationRegistry.connect(issuer1).issueCredential(holder, "", ttl)
    ).to.be.revertedWith("vcID cannot be empty");
  });

  it("should not allow issuing a credential with an empty holder address", async function () {
    await expect(
      revocationRegistry
        .connect(issuer1)
        .issueCredential(ethers.ZeroAddress, vcID, ttl)
    ).to.be.revertedWith("Holder address cannot be zero");
  });

  it("should not allow issuing a credential with a TTL in the past", async function () {
    const pastTTL = Math.floor(Date.now() / 1000) - 3600; // 1 hour in the past
    await expect(
      revocationRegistry.connect(issuer1).issueCredential(holder, vcID, pastTTL)
    ).to.be.revertedWith("TTL must be in the future");
  });

  it("Should return true for expired credentials", async function () {
    const shortTTL = (await time.latest()) + 5; // 5 seconds in the future

    await revocationRegistry
      .connect(issuer1)
      .issueCredential(holder, vcID, shortTTL);

    // Increase time by 6 seconds
    await time.increase(6);

    // Now, the credential should be expired
    expect(await revocationRegistry.isRevoked(vcID)).to.be.true;
  });

  it("Should return false for non-expired, non-revoked credentials", async function () {
    await revocationRegistry
      .connect(issuer1)
      .issueCredential(holder, vcID, ttl);
    expect(await revocationRegistry.isRevoked(vcID)).to.be.false;
  });

  it("Should prevent issuing a credential with the same vcID twice", async function () {
    await revocationRegistry
      .connect(issuer1)
      .issueCredential(holder, vcID, ttl);
    await expect(
      revocationRegistry.connect(issuer1).issueCredential(holder, vcID, ttl)
    ).to.be.revertedWith("Credential already issued");
  });

  it("Should return the correct credentials for a holder", async function () {
    const vcID2 = "550e8400-e29b-41d4-a716-446655440050";
    await revocationRegistry
      .connect(issuer1)
      .issueCredential(holder, vcID, ttl);
    await revocationRegistry
      .connect(issuer1)
      .issueCredential(holder, vcID2, ttl);

    holderProvider = await ethers.getSigner(holder);
    const credentials = await revocationRegistry
      .connect(holderProvider)
      .getCredentialsForHolder(holder);

    expect(credentials.length).to.equal(2);
    expect(credentials[0].vcIDHash).to.equal(
      ethers.keccak256(ethers.toUtf8Bytes(vcID))
    );
    expect(credentials[1].vcIDHash).to.equal(
      ethers.keccak256(ethers.toUtf8Bytes(vcID2))
    );
  });

  it("Should prevent non-holders or non-issuers from viewing credentials", async function () {
    await revocationRegistry
      .connect(issuer1)
      .issueCredential(holder, vcID, ttl);
    await expect(
      revocationRegistry.connect(issuer2).getCredentialsForHolder(holder)
    ).to.be.revertedWith(
      "Access denied: Only holder or issuer can view credentials"
    );
  });

  it("should prevent trying to view non-existent credentials", async function () {
    const holderProvider = await ethers.getSigner(holder);
    await expect(
      revocationRegistry.connect(holderProvider).getCredentialsForHolder(holder)
    ).to.be.revertedWith("No credentials found");
  });
});

const { expect } = require('chai');
const { ethers } = require('hardhat');
const { time } = require('@nomicfoundation/hardhat-network-helpers');

describe('CredentialRevocationRegistry', function () {
	let RevocationRegistry, revocationRegistry, issuer1, issuer2, holderSigner;
	const vcID = '550e8400-e29b-41d4-a716-446655440000';
	const ttl = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now

	beforeEach(async function () {
		[issuer1, issuer2, holderSigner] = await ethers.getSigners();
		RevocationRegistry = await ethers.getContractFactory(
			'CredentialRevocationRegistry'
		);
		revocationRegistry = await RevocationRegistry.deploy();
		await revocationRegistry.waitForDeployment();
	});

	it('Should allow an issuer to issue a credential with TTL', async function () {
		await expect(
			revocationRegistry
				.connect(issuer1)
				.issueCredential(holderSigner.address, vcID, ttl)
		).to.emit(revocationRegistry, 'CredentialIssued');
	});

	it('Should allow the issuer to revoke a credential before expiry', async function () {
		await revocationRegistry
			.connect(issuer1)
			.issueCredential(holderSigner.address, vcID, ttl);
		await expect(
			revocationRegistry
				.connect(issuer1)
				.revokeCredential(holderSigner.address, vcID)
		).to.emit(revocationRegistry, 'CredentialRevoked');

		expect(await revocationRegistry.isRevoked(vcID)).to.be.true;
	});

	it('Should prevent revocation by non-issuers', async function () {
		await revocationRegistry
			.connect(issuer1)
			.issueCredential(holderSigner.address, vcID, ttl);
		await expect(
			revocationRegistry
				.connect(issuer2)
				.revokeCredential(holderSigner.address, vcID)
		).to.be.revertedWith('Unauthorized');
	});

	it('Should prevent revocation of non-existent credentials', async function () {
		await expect(
			revocationRegistry
				.connect(issuer1)
				.revokeCredential(holderSigner.address, vcID)
		).to.be.revertedWith('Credential not issued');
	});

	it('should not allow issuing a credential with an empty vcID', async function () {
		await expect(
			revocationRegistry
				.connect(issuer1)
				.issueCredential(holderSigner.address, '', ttl)
		).to.be.revertedWith('vcID cannot be empty');
	});

	it('should not allow issuing a credential with an empty holder address', async function () {
		await expect(
			revocationRegistry
				.connect(issuer1)
				.issueCredential(ethers.ZeroAddress, vcID, ttl)
		).to.be.revertedWith('Holder address cannot be zero');
	});

	it('should not allow issuing a credential with a TTL in the past', async function () {
		const pastTTL = Math.floor(Date.now() / 1000) - 3600; // 1 hour in the past
		await expect(
			revocationRegistry
				.connect(issuer1)
				.issueCredential(holderSigner.address, vcID, pastTTL)
		).to.be.revertedWith('TTL must be in the future');
	});

	it('Should return true for expired credentials', async function () {
		const shortTTL = (await time.latest()) + 5; // 5 seconds in the future

		await revocationRegistry
			.connect(issuer1)
			.issueCredential(holderSigner.address, vcID, shortTTL);

		// Increase time by 6 seconds
		await time.increase(6);

		// Now, the credential should be expired
		expect(await revocationRegistry.isRevoked(vcID)).to.be.true;
	});

	it('Should return false for non-expired, non-revoked credentials', async function () {
		await revocationRegistry
			.connect(issuer1)
			.issueCredential(holderSigner.address, vcID, ttl);
		expect(await revocationRegistry.isRevoked(vcID)).to.be.false;
	});

	it('Should prevent issuing a credential with the same vcID twice', async function () {
		await revocationRegistry
			.connect(issuer1)
			.issueCredential(holderSigner.address, vcID, ttl);
		await expect(
			revocationRegistry
				.connect(issuer1)
				.issueCredential(holderSigner.address, vcID, ttl)
		).to.be.revertedWith('Credential already issued');
	});

	it('should prevent trying to view non-existent credentials', async function () {
		const messageHash = ethers.keccak256(
			ethers.toUtf8Bytes('Authentication Request')
		);
		const signedMessage = await holderSigner.signMessage(
			ethers.getBytes(messageHash)
		);
		const signature = ethers.Signature.from(signedMessage);

		await expect(
			revocationRegistry.getCredentialsForHolder(
				holderSigner.address,
				signature.v,
				signature.r,
				signature.s,
				messageHash
			)
		).to.be.revertedWith('No credentials found');
	});

	it('Should allow the holder to retrieve their credentials with a valid signature', async function () {
		await revocationRegistry
			.connect(issuer1)
			.issueCredential(holderSigner.address, vcID, ttl);

		const messageHash = ethers.keccak256(
			ethers.toUtf8Bytes('Authentication Request')
		);
		const signedMessage = await holderSigner.signMessage(
			ethers.getBytes(messageHash)
		);
		const signature = ethers.Signature.from(signedMessage);

		const credentials = await revocationRegistry.getCredentialsForHolder(
			holderSigner.address,
			signature.v,
			signature.r,
			signature.s,
			messageHash
		);

		expect(credentials.length).to.equal(1);
		expect(credentials[0].issuer).to.equal(issuer1.address);
		expect(credentials[0].ttl).to.equal(ttl);
		expect(credentials[0].revoked).to.equal(false);
	});

	it('Should allow an issuer to retrieve credentials for a holder with a valid signature', async function () {
		await revocationRegistry
			.connect(issuer1)
			.issueCredential(holderSigner.address, vcID, ttl);

		const messageHash = ethers.keccak256(
			ethers.toUtf8Bytes('Authentication Request')
		);
		const signedMessage = await issuer1.signMessage(
			ethers.getBytes(messageHash)
		);
		const signature = ethers.Signature.from(signedMessage);

		const credentials = await revocationRegistry.getCredentialsForHolder(
			holderSigner.address,
			signature.v,
			signature.r,
			signature.s,
			messageHash
		);

		expect(credentials.length).to.equal(1);
		expect(credentials[0].issuer).to.equal(issuer1.address);
		expect(credentials[0].ttl).to.equal(ttl);
		expect(credentials[0].revoked).to.equal(false);
	});

	it('Should prevent unauthorized access to credentials with an invalid signature', async function () {
		await revocationRegistry
			.connect(issuer1)
			.issueCredential(holderSigner.address, vcID, ttl);

		const messageHash = ethers.keccak256(
			ethers.toUtf8Bytes('Authentication Request')
		);
		const signedMessage = await issuer2.signMessage(
			ethers.getBytes(messageHash)
		);
		const signature = ethers.Signature.from(signedMessage);

		// Attempt to retrieve credentials using an invalid signature
		await expect(
			revocationRegistry.getCredentialsForHolder(
				holderSigner.address,
				signature.v,
				signature.r,
				signature.s,
				messageHash
			)
		).to.be.revertedWith('Invalid signature');
	});

	it('Should remove revoked credentials using cleanupRevokedCredentials', async function () {
		await revocationRegistry
			.connect(issuer1)
			.issueCredential(holderSigner.address, vcID, ttl);

		await revocationRegistry
			.connect(issuer1)
			.revokeCredential(holderSigner.address, vcID);

		expect(await revocationRegistry.isRevoked(vcID)).to.be.true;

		const messageHash = ethers.keccak256(ethers.toUtf8Bytes('Cleanup Request'));
		const signedMessage = await holderSigner.signMessage(
			ethers.getBytes(messageHash)
		);
		const signature = ethers.Signature.from(signedMessage);

		// Perform cleanup
		await revocationRegistry.cleanupRevokedCredentials(
			holderSigner.address,
			signature.v,
			signature.r,
			signature.s,
			messageHash
		);

		// Verify credential has been removed
		await expect(
			revocationRegistry.getCredentialsForHolder(
				holderSigner.address,
				signature.v,
				signature.r,
				signature.s,
				messageHash
			)
		).to.be.revertedWith('No credentials found');
	});

	it('Should revoke and remove expired credentials using cleanupRevokedCredentials', async function () {
		const shortTTL = (await time.latest()) + 5; // TTL 5 seconds in the future

		await revocationRegistry
			.connect(issuer1)
			.issueCredential(holderSigner.address, vcID, shortTTL);

		// Wait for expiration
		await time.increase(6);

		// Call cleanup
		const messageHash = ethers.keccak256(ethers.toUtf8Bytes('Cleanup Request'));
		const signedMessage = await holderSigner.signMessage(
			ethers.getBytes(messageHash)
		);
		const signature = ethers.Signature.from(signedMessage);

		await revocationRegistry.cleanupRevokedCredentials(
			holderSigner.address,
			signature.v,
			signature.r,
			signature.s,
			messageHash
		);

		// Confirm the credential was deleted
		await expect(
			revocationRegistry.getCredentialsForHolder(
				holderSigner.address,
				signature.v,
				signature.r,
				signature.s,
				messageHash
			)
		).to.be.revertedWith('No credentials found');
	});
});

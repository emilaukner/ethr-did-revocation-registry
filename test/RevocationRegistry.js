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

	it('Should issue a credential using a valid signature and nonce', async function () {
		// Step 1: Get current nonce for the issuer
		const nonce = await revocationRegistry.getNonce(issuer1.address);

		// Step 2: Build message hash
		const messageHash = ethers.keccak256(
			ethers.solidityPacked(
				['address', 'uint256', 'address', 'string', 'uint256', 'string'],
				[
					revocationRegistry.target,
					nonce,
					holderSigner.address,
					vcID,
					ttl,
					'ISSUE',
				]
			)
		);

		// Step 3: Sign it off-chain
		const signedMessage = await issuer1.signMessage(
			ethers.getBytes(messageHash)
		);
		const signature = ethers.Signature.from(signedMessage);

		// Step 4: Submit on-chain using a relayer
		await expect(
			revocationRegistry.issueCredentialWithSignature(
				holderSigner.address,
				vcID,
				ttl,
				nonce,
				signature.v,
				signature.r,
				signature.s
			)
		).to.emit(revocationRegistry, 'CredentialIssued');

		// Step 5: Confirm it's now in the registry
		const messageHashAuth = ethers.keccak256(
			ethers.toUtf8Bytes('Authentication Request')
		);
		const authSignature = ethers.Signature.from(
			await holderSigner.signMessage(ethers.getBytes(messageHashAuth))
		);

		const credentials = await revocationRegistry.getCredentialsForHolder(
			holderSigner.address,
			authSignature.v,
			authSignature.r,
			authSignature.s,
			messageHashAuth
		);

		expect(credentials.length).to.equal(1);
		expect(credentials[0].issuer).to.equal(issuer1.address);
		expect(credentials[0].vcID).to.equal(vcID);
		expect(credentials[0].ttl).to.equal(ttl);
		expect(credentials[0].revoked).to.equal(false);
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

	it('should return an empty list when holder has no credentials', async function () {
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

		expect(credentials).to.be.an('array').that.is.empty;
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

	it('Should return only issuer-specific credentials when queried by an issuer', async function () {
		const vcID1 = 'cred-issuer1';
		const vcID2 = 'cred-issuer2';

		// Both issuers issue different credentials to the same holder
		await revocationRegistry
			.connect(issuer1)
			.issueCredential(holderSigner.address, vcID1, ttl);
		await revocationRegistry
			.connect(issuer2)
			.issueCredential(holderSigner.address, vcID2, ttl);

		// issuer1 signs an access message
		const messageHash = ethers.keccak256(ethers.toUtf8Bytes('Issuer Access'));
		const signedMessage = await issuer1.signMessage(
			ethers.getBytes(messageHash)
		);
		const signature = ethers.Signature.from(signedMessage);

		// issuer1 tries to fetch credentials for the holder
		const creds = await revocationRegistry.getCredentialsForHolder(
			holderSigner.address,
			signature.v,
			signature.r,
			signature.s,
			messageHash
		);

		expect(creds.length).to.equal(1);
		expect(creds[0].issuer).to.equal(issuer1.address);
		expect(creds[0].vcID).to.equal(vcID1);
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
		).to.be.revertedWith('Unauthorized');
	});

	it('Should revoke a credential using a valid signature and nonce', async function () {
		await revocationRegistry
			.connect(issuer1)
			.issueCredential(holderSigner.address, vcID, ttl);

		const nonce = await revocationRegistry.nonces(holderSigner.address);
		const messageHash = ethers.keccak256(
			ethers.solidityPacked(
				['address', 'uint256', 'address', 'string', 'string'],
				[revocationRegistry.target, nonce, holderSigner.address, vcID, 'REVOKE']
			)
		);
		const signedMessage = await holderSigner.signMessage(
			ethers.getBytes(messageHash)
		);
		const signature = ethers.Signature.from(signedMessage);

		await expect(
			revocationRegistry.revokeCredentialWithSignature(
				holderSigner.address,
				vcID,
				nonce,
				signature.v,
				signature.r,
				signature.s
			)
		).to.emit(revocationRegistry, 'CredentialRevoked');

		expect(await revocationRegistry.isRevoked(vcID)).to.be.true;
	});

	it('Should return the correct nonce for an account', async function () {
		const nonceBefore = await revocationRegistry.nonces(holderSigner.address);
		expect(nonceBefore).to.equal(0);

		await revocationRegistry
			.connect(issuer1)
			.issueCredential(holderSigner.address, vcID, ttl);

		const nonce = await revocationRegistry.nonces(holderSigner.address);
		expect(nonce).to.equal(0); // nonce should still be 0 (not incremented until sig-based op)

		const messageHash = ethers.keccak256(
			ethers.solidityPacked(
				['address', 'uint256', 'address', 'string', 'string'],
				[revocationRegistry.target, nonce, holderSigner.address, vcID, 'REVOKE']
			)
		);
		const signedMessage = await holderSigner.signMessage(
			ethers.getBytes(messageHash)
		);
		const signature = ethers.Signature.from(signedMessage);

		await revocationRegistry.revokeCredentialWithSignature(
			holderSigner.address,
			vcID,
			nonce,
			signature.v,
			signature.r,
			signature.s
		);

		const nonceAfter = await revocationRegistry.nonces(holderSigner.address);
		expect(nonceAfter).to.equal(1);
	});
});

const { buildModule } = require('@nomicfoundation/hardhat-ignition/modules');

const RevocationRegistryModule = buildModule(
	'CredentialRevocationRegistry',
	(m) => {
		const registry = m.contract('CredentialRevocationRegistry');
		return { registry };
	}
);

module.exports = RevocationRegistryModule;

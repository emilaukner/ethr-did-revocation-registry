const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

const RevocationRegistryModule = buildModule(
  "RevocationRegistryModule",
  (m) => {
    const registry = m.contract("CredentialRevocationRegistry");
    return { registry };
  }
);

module.exports = RevocationRegistryModule;

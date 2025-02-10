// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract CredentialRevocationRegistry {
    struct Credential {
        address issuer;
        uint256 ttl;  // Expiration timestamp
        bool revoked;
    }

    mapping(bytes32 => Credential) private credentials;

    event CredentialIssued(bytes32 indexed credentialHash, address issuer, uint256 ttl);
    event CredentialRevoked(bytes32 indexed credentialHash, address issuer, uint256 timestamp);

    function _hashVcID(string memory vcID) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(vcID));
    }

    function issueCredential(string memory vcID, uint256 ttl) external {
        require(bytes(vcID).length > 0, "vcID cannot be empty");
        require(ttl > block.timestamp, "TTL must be in the future");
        
        bytes32 hashedVcID = _hashVcID(vcID);
        require(credentials[hashedVcID].issuer == address(0), "Credential already issued");

        credentials[hashedVcID] = Credential({
            issuer: msg.sender,
            ttl: ttl,
            revoked: false
        });
    

        emit CredentialIssued(hashedVcID, msg.sender, ttl);
    }

    function revokeCredential(string memory vcID) external {
        require(bytes(vcID).length > 0, "vcID cannot be empty");
        bytes32 hashedVcID = _hashVcID(vcID);

        Credential storage cred = credentials[hashedVcID];

        require(cred.issuer == msg.sender, "Not the credential issuer");
        require(!cred.revoked, "Credential already revoked");

        cred.revoked = true;
        emit CredentialRevoked(hashedVcID, msg.sender, block.timestamp);
    }

    function isRevoked(string memory vcID) external view returns (bool) {
        bytes32 hashedVcID = _hashVcID(vcID);
        Credential storage cred = credentials[hashedVcID];

        return cred.revoked || (block.timestamp > cred.ttl);
    }

    function getIssuer(string memory vcID) external view returns (address) {
        return credentials[_hashVcID(vcID)].issuer;
    }

    function getTTL(string memory vcID) external view returns (uint256) {
        return credentials[_hashVcID(vcID)].ttl;
    }
}

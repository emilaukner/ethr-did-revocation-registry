// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract CredentialRevocationRegistry {
    struct Credential {
        address issuer;
        bytes32 vcIDHash;
        uint256 ttl;
        bool revoked;
    }
    
    mapping(address => bytes32[]) private holderCredentials; // holder => credentialHashes
    mapping(bytes32 => Credential) private credentials; // vcIDHash => Credential

    event CredentialIssued(bytes32 indexed credentialHash, address indexed issuer, address indexed holder, uint256 ttl);
    event CredentialRevoked(bytes32 indexed credentialHash, address indexed issuer, address indexed holder, uint256 timestamp);

    /**
     * internal function to hash the vcID
     * @param vcID The unique identifier of the credential
     */
    function _hashVcID(string memory vcID) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(vcID));
    }

    /**
     * Function to publish a issued credential for a holder
     * @param holder address of the credential holder 
     * @param vcID  The unique identifier of the credential
     * @param ttl  The time-to-live of the credential
     */
    function issueCredential(address holder, string memory vcID, uint256 ttl) external {
        require(holder != address(0), "Holder address cannot be zero");
        require(bytes(vcID).length > 0, "vcID cannot be empty");
        require(ttl > block.timestamp, "TTL must be in the future");

        bytes32 hashedVcID = _hashVcID(vcID);
        require(credentials[hashedVcID].issuer == address(0), "Credential already issued");

        credentials[hashedVcID] = Credential({
            issuer: msg.sender,
            vcIDHash: hashedVcID,
            ttl: ttl,
            revoked: false
        });

        holderCredentials[holder].push(hashedVcID);

        emit CredentialIssued(hashedVcID, msg.sender, holder, ttl);
    }

    /**
     * Function to revoke a issued credential for a holder
     * @param holder address of the credential holder 
     * @param vcID  The unique identifier of the credential
     */
    function revokeCredential(address holder, string memory vcID) external {
        require(holder != address(0), "Holder address cannot be zero");
        require(bytes(vcID).length > 0, "vcID cannot be empty");

        bytes32 hashedVcID = _hashVcID(vcID);
        Credential storage cred = credentials[hashedVcID];
        require(cred.issuer != address(0), "Credential not issued");
        require(cred.issuer == msg.sender, "Not the credential issuer");
        require(!cred.revoked, "Credential already revoked");

        cred.revoked = true;

        emit CredentialRevoked(hashedVcID, msg.sender, holder, block.timestamp);
    }

    /**
     * Function to check if a credential is revoked
     * @param vcID  The unique identifier of the credential
     */
    function isRevoked(string memory vcID) external view returns (bool) {
        bytes32 hashedVcID = _hashVcID(vcID);
        Credential storage cred = credentials[hashedVcID];

        return cred.revoked || (block.timestamp > cred.ttl);
    }

    /**
     * Function to get all credentials issued to a holder
     * @param holder address of the credential holder 
     */
    function getCredentialsForHolder(address holder) external view returns (Credential[] memory) {
        require(
            msg.sender == holder || _isIssuerForHolder(msg.sender, holder),
            "Access denied: Only holder or issuer can view credentials"
        );

        bytes32[] memory credentialHashes = holderCredentials[holder];
        Credential[] memory creds = new Credential[](credentialHashes.length);

        uint256 count = 0;

        for (uint256 i = 0; i < credentialHashes.length; i++) {
            Credential memory cred = credentials[credentialHashes[i]];

            if (msg.sender == holder || cred.issuer == msg.sender) {
                creds[count] = cred;
                count++;
            }
        }

        Credential[] memory filteredCreds = new Credential[](count);
        for (uint256 i = 0; i < count; i++) {
            filteredCreds[i] = creds[i];
        }

        return filteredCreds;
    }

    /**
     * Function to check if an issuer has issued a credential to a holder
     * @param issuer address of the credential issuer
     * @param holder address of the credential holder 
     */
    function _isIssuerForHolder(address issuer, address holder) private view returns (bool) {
        bytes32[] memory credentialHashes = holderCredentials[holder];

        for (uint256 i = 0; i < credentialHashes.length; i++) {
            if (credentials[credentialHashes[i]].issuer == issuer) {
                return true;
            }
        }
        return false;
    }
}

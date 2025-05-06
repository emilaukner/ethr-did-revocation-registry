// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract CredentialRevocationRegistry {
    struct Credential {
        string vcID; // Id of the credential
        address issuer; // address of the credential issuer
        address holder; // address of the credential holder
        uint256 ttl; // seconds until the credential expires
        bool revoked; // flag to indicate if the credential is revoked
    }

    mapping(address => bytes32[]) private holderCredentials; // holderAddress => vcIDHash[]
    mapping(bytes32 => Credential) private credentials; // vcIDHash => Credential
    mapping(address => mapping(address => bool)) private isIssuerOfHolder; // issuerAddress => holderAddress => bool

    event CredentialIssued(
        bytes32 indexed credentialHash,
        address indexed issuer
    );
    event CredentialRevoked(
        bytes32 indexed credentialHash,
        address indexed issuer,
        uint256 timestamp
    );

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
     * @param ttl  The time-to-live of the credential in seconds
     */
    function issueCredential(
        address holder,
        string memory vcID,
        uint256 ttl
    ) external {
        require(holder != address(0), "Holder address cannot be zero");
        require(bytes(vcID).length > 0, "vcID cannot be empty");
        require(ttl > block.timestamp, "TTL must be in the future");

        bytes32 hashedVcID = _hashVcID(vcID);
        require(
            credentials[hashedVcID].issuer == address(0),
            "Credential already issued"
        );

        credentials[hashedVcID] = Credential({
            vcID: vcID,
            issuer: msg.sender,
            holder: holder,
            ttl: ttl,
            revoked: false
        });

        holderCredentials[holder].push(hashedVcID);
        isIssuerOfHolder[holder][msg.sender] = true;

        emit CredentialIssued(hashedVcID, msg.sender);
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
        require(
            msg.sender == cred.holder || msg.sender == cred.issuer,
            "Unauthorized"
        );
        require(!cred.revoked, "Credential already revoked");

        cred.revoked = true;

        // Remove from holderCredentials list
        bytes32[] storage credList = holderCredentials[holder];
        for (uint256 i = 0; i < credList.length; i++) {
            if (credList[i] == hashedVcID) {
                credList[i] = credList[credList.length - 1];
                credList.pop();
                break;
            }
        }

        // Remove the credential from the holder's storage
        _deleteCredential(hashedVcID);

        emit CredentialRevoked(hashedVcID, msg.sender, block.timestamp);
    }

    /**
     * @dev Internal function to permanently delete a credential from storage
     * @param credentialHash The hash of the credential to delete
     */
    function _deleteCredential(bytes32 credentialHash) internal {
        require(
            credentials[credentialHash].issuer != address(0),
            "Credential does not exist"
        );
        require(
            credentials[credentialHash].revoked,
            "Credential must be revoked first"
        );

        delete credentials[credentialHash]; // Remove from storage
    }

    /**
     * Function to check if a credential is revoked
     * @param vcID  The unique identifier of the credential
     * @return bool  True if the credential is revoked or does not exist
     */
    function isRevoked(string memory vcID) external view returns (bool) {
        bytes32 hashedVcID = _hashVcID(vcID);
        Credential storage cred = credentials[hashedVcID];
        if (cred.issuer == address(0)) {
            return true;
        }
        return cred.revoked || (block.timestamp > cred.ttl);
    }

    /**
     * WARNING: This function is for testing purposes only and should not be used in production due to risk of replay of signatures
     * Function to get credentials for a holder
     * @param holder address of the credential holder
     * @param sigV  The recovery id of the signature
     * @param sigR  The r value of the signature
     * @param sigS  The s value of the signature
     * @param hash  The hash of the message
     * @return Credential[]  List of credentials for the holder
     */
    function getCredentialsForHolder(
        address holder,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS,
        bytes32 hash
    ) external view returns (Credential[] memory) {
        require(holder != address(0), "Holder address cannot be zero");

        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );
        address signer = ecrecover(prefixedHash, sigV, sigR, sigS);
        require(
            signer == holder || _isIssuerForHolder(signer, holder),
            "Invalid signature"
        );

        bytes32[] storage credentialHashes = holderCredentials[holder];
        require(credentialHashes.length > 0, "No credentials found");

        // If signer is holder, return all credentials
        if (signer == holder) {
            Credential[] memory allCreds = new Credential[](
                credentialHashes.length
            );
            for (uint256 i = 0; i < credentialHashes.length; i++) {
                allCreds[i] = credentials[credentialHashes[i]];
            }
            return allCreds;
        }

        // Else, signer is issuer → filter only their credentials
        uint256 count = 0;

        // First pass: count matching credentials
        for (uint256 i = 0; i < credentialHashes.length; i++) {
            if (credentials[credentialHashes[i]].issuer == signer) {
                count++;
            }
        }

        Credential[] memory filteredCreds = new Credential[](count);
        uint256 j = 0;
        for (uint256 i = 0; i < credentialHashes.length; i++) {
            Credential memory cred = credentials[credentialHashes[i]];
            if (cred.issuer == signer) {
                filteredCreds[j] = cred;
                j++;
            }
        }

        return filteredCreds;
    }

    /**
     * Function to check if an issuer has issued a credential for a holder
     * @param issuer address to be checked
     * @param holder credential owner to be checked against
     */
    function _isIssuerForHolder(
        address issuer,
        address holder
    ) private view returns (bool) {
        return isIssuerOfHolder[holder][issuer];
    }
}

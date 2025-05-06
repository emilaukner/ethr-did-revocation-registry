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

    mapping(address => bytes32[]) private holderCredentials;
    mapping(bytes32 => Credential) private credentials;
    mapping(address => mapping(address => bool)) private isIssuerOfHolder;
    mapping(address => uint256) public nonces;

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

    function getNonce(address account) external view returns (uint256) {
        return nonces[account];
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

    function issueCredentialWithSignature(
        address holder,
        string memory vcID,
        uint256 ttl,
        uint256 expectedNonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(holder != address(0), "Holder address cannot be zero");
        require(bytes(vcID).length > 0, "vcID cannot be empty");
        require(ttl > block.timestamp, "TTL must be in the future");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(
                    abi.encodePacked(
                        address(this),
                        expectedNonce,
                        holder,
                        vcID,
                        ttl,
                        "ISSUE"
                    )
                )
            )
        );

        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "Invalid signature");
        require(nonces[signer] == expectedNonce, "Bad nonce");
        nonces[signer]++;

        // Use signer as the issuer
        bytes32 hashedVcID = _hashVcID(vcID);
        require(
            credentials[hashedVcID].issuer == address(0),
            "Credential already issued"
        );

        credentials[hashedVcID] = Credential({
            vcID: vcID,
            issuer: signer,
            holder: holder,
            ttl: ttl,
            revoked: false
        });

        holderCredentials[holder].push(hashedVcID);
        isIssuerOfHolder[holder][signer] = true;

        emit CredentialIssued(hashedVcID, signer);
    }

    /**
     * Function to revoke a issued credential for a holder
     * @param holder address of the credential holder
     * @param vcID  The unique identifier of the credential
     */
    function revokeCredential(address holder, string memory vcID) public {
        require(holder != address(0), "Holder address cannot be zero");
        require(bytes(vcID).length > 0, "vcID cannot be empty");

        bytes32 hashedVcID = _hashVcID(vcID);
        Credential storage cred = credentials[hashedVcID];

        require(cred.issuer != address(0), "Credential not issued");
        require(
            msg.sender == cred.holder || msg.sender == cred.issuer,
            "Unauthorized"
        );
        require(!cred.revoked, "Already revoked");

        cred.revoked = true;

        emit CredentialRevoked(hashedVcID, msg.sender, block.timestamp);

        // Remove from holder's list
        bytes32[] storage credList = holderCredentials[holder];
        for (uint256 i = 0; i < credList.length; i++) {
            if (credList[i] == hashedVcID) {
                credList[i] = credList[credList.length - 1];
                credList.pop();
                break;
            }
        }

        delete credentials[hashedVcID];
    }

    function revokeCredentialWithSignature(
        address holder,
        string memory vcID,
        uint256 expectedNonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(holder != address(0), "Holder address cannot be zero");
        require(bytes(vcID).length > 0, "vcID cannot be empty");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(
                    abi.encodePacked(
                        address(this),
                        expectedNonce,
                        holder,
                        vcID,
                        "REVOKE"
                    )
                )
            )
        );

        address signer = ecrecover(digest, v, r, s);
        require(
            signer == holder || _isIssuerForHolder(signer, holder),
            "Invalid signature"
        );
        require(nonces[signer] == expectedNonce, "Bad nonce");
        nonces[signer]++;

        revokeCredential(holder, vcID);
    }

    /**
     * Function to check if a credential is revoked
     * @param vcID  The unique identifier of the credential
     * @return bool  True if the credential is revoked or does not exist
     */
    function isRevoked(string memory vcID) external view returns (bool) {
        bytes32 hashedVcID = _hashVcID(vcID);
        Credential storage cred = credentials[hashedVcID];
        if (cred.issuer == address(0)) return true;
        return cred.revoked || block.timestamp > cred.ttl;
    }

    /**
     * Function to get credentials for a holder
     * @param holder address of the credential holder
     * @param v  The recovery id of the signature
     * @param r  The r value of the signature
     * @param s The s value of the signature
     * @param hash  The hash of the message
     * @return Credential[]  List of credentials for the holder
     */
    function getCredentialsForHolder(
        address holder,
        uint8 v,
        bytes32 r,
        bytes32 s,
        bytes32 hash
    ) external view returns (Credential[] memory) {
        require(holder != address(0), "Holder cannot be zero");

        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );
        address signer = ecrecover(prefixedHash, v, r, s);
        require(
            signer == holder || _isIssuerForHolder(signer, holder),
            "Unauthorized"
        );

        bytes32[] storage hashes = holderCredentials[holder];
        uint256 count = 0;

        for (uint256 i = 0; i < hashes.length; i++) {
            if (signer == holder || credentials[hashes[i]].issuer == signer) {
                count++;
            }
        }

        Credential[] memory results = new Credential[](count);
        uint256 j = 0;
        for (uint256 i = 0; i < hashes.length; i++) {
            Credential storage cred = credentials[hashes[i]];
            if (signer == holder || cred.issuer == signer) {
                results[j] = cred;
                j++;
            }
        }

        return results;
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

// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.6.0 <0.9.0;

import "@openzeppelin/contracts/access/AccessControl.sol";

import { ByteHasher } from "./helpers/ByteHasher.sol";
import { IWorldID } from "./interfaces/IWorldID.sol";

contract Roam is AccessControl {
    using ByteHasher for bytes;

    event Uploaded(string ipfsHash);
    event TagAdded(string tag);
    event Indexed(string tag, string ipfsHash);

    bytes32 public constant OWNER_ROLE = keccak256("OWNER_ROLE");
    bytes32 public constant TAGGER_ROLE = keccak256("TAGGER_ROLE");
    bytes32 public constant INDEXER_ROLE = keccak256("INDEXER_ROLE");

    string[] private _ipfsHashes;
    string[] private _tags;
    mapping(string => string[]) private _groups; // tag => ipfsHashes

    ///////////////////////////////////////////////////////////////////////////////
    ///                                  ERRORS                                ///
    //////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when attempting to reuse a nullifier
    error InvalidNullifier();

    /// @dev The World ID instance that will be used for verifying proofs
    IWorldID internal immutable worldId;

    /// @dev The contract's external nullifier hash
    uint256 internal immutable externalNullifier;

    /// @dev The World ID group ID (always 1)
    uint256 internal immutable groupId = 1;

    /// @dev Whether a nullifier hash has been used already. Used to guarantee an action is only performed once by a single person
    mapping(uint256 => bool) internal nullifierHashes;

    constructor(
        IWorldID _worldId,
        string memory _appId,
        string memory _actionId
    ) {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(OWNER_ROLE, msg.sender);

        worldId = _worldId;
        externalNullifier = abi
            .encodePacked(abi.encodePacked(_appId).hashToField(), _actionId)
            .hashToField();
    }

    function _verifyAndExecute(
        address signal,
        uint256 root,
        uint256 nullifierHash,
        uint256[8] calldata proof
    ) public {
        // First, we make sure this person hasn't done this before
        if (nullifierHashes[nullifierHash]) revert InvalidNullifier();

        // We now verify the provided proof is valid and the user is verified by World ID
        worldId.verifyProof(
            root,
            groupId,
            abi.encodePacked(signal).hashToField(),
            nullifierHash,
            externalNullifier,
            proof
        );

        // We now record the user has done this, so they can't do it again (proof of uniqueness)
        nullifierHashes[nullifierHash] = true;

        // Finally, execute your logic here, for example issue a token, NFT, etc...
        // Make sure to emit some kind of event afterwards!
    }

    function upload(
        string calldata ipfsHash,
        address signal,
        uint256 root,
        uint256 nullifierHash,
        uint256[8] calldata proof
    ) external {
        require(bytes(ipfsHash).length > 0, "IPFS hash cannot be empty");

        _verifyAndExecute(
            signal,
            root,
            nullifierHash,
            proof
        );

        _ipfsHashes.push(ipfsHash);
        emit Uploaded(ipfsHash);
    }

    function createTag(string calldata tag) external onlyRole(TAGGER_ROLE) {
        require(bytes(tag).length > 0, "Tag cannot be empty");

        _tags.push(tag);
        emit TagAdded(tag);
    }

    function index(
        string[] calldata hashes,
        string calldata tag,
        address signal,
        uint256 root,
        uint256 nullifierHash,
        uint256[8] calldata proof
    ) external onlyRole(INDEXER_ROLE) {
        require(bytes(tag).length > 0, "Tag cannot be empty");

        _verifyAndExecute(
            signal,
            root,
            nullifierHash,
            proof
        );

        string[] storage group = _groups[tag];

        for (uint256 i = 0; i < hashes.length; i++) {
            require(bytes(hashes[i]).length > 0, "IPFS hash cannot be empty");

            group.push(hashes[i]);
            emit Indexed(tag, hashes[i]);
        }
    }

    function ipfsHash(uint256 index) external view returns (string memory) {
        return _ipfsHashes[index];
    }

    function ipfsHashes() external view returns (string[] memory) {
        return _ipfsHashes;
    }

    function tags() external view returns (string[] memory) {
        return _tags;
    }

    function group(string calldata tag) external view returns (string[] memory) {
        return _groups[tag];
    }
}

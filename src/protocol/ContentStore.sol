// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { SSTORE2 } from "../utils/SSTORE2.sol";

/**
 * @title ContentStore
 * @notice Permanent, immutable, content-addressed on-chain store for Console cartridges & assets.
 * @dev Deduplicates storage by indexing chunks on `digest = keccak256(data)`.
 *      Uses deterministic CREATE2 SSTORE2 deployments with domain-separated salt:
 *      salt = keccak256(abi.encode(CONTENT_POINTER_DOMAIN, digest)).
 *      Predicted pointer matches the actual deployed address bit-for-bit.
 *      If a contract already exists at the predicted pointer, validates that its bytecode
 *      strictly matches the expected SSTORE2 representation (0x00 STOP prefix + exact data)
 *      to prevent registering unrelated pre-existing contracts.
 */
contract ContentStore {
    /// @dev Maximum single chunk size permitted by Spurious Dragon EIP-170 code size limit (24576 - 1 byte STOP = 24575)
    uint256 public constant MAX_CHUNK_SIZE = 24575;

    /// @notice Domain separator for deterministic storage pointer salts
    bytes32 public constant CONTENT_POINTER_DOMAIN = keccak256("CONSOLE_CONTENT_STORE_V1");

    /// @notice Mapping from keccak256 content digest to SSTORE2 pointer contract address
    mapping(bytes32 => address) public chunkAddresses;

    /// @notice Mapping from keccak256 content digest to byte length
    mapping(bytes32 => uint32) public chunkSizes;

    /// @notice Emitted when a new unique chunk is persisted
    event ContentStored(bytes32 indexed digest, address indexed chunk, uint256 size, address indexed sender);

    /// @notice Emitted when an existing chunk is referenced without redeployment (deduplicated)
    event ContentDeduplicated(bytes32 indexed digest, address indexed chunk, address indexed sender);

    error ChunkTooLarge(uint256 size, uint256 maxAllowed);
    error ChunkEmpty();
    error ChunkNotFound(bytes32 digest);
    error InvalidExistingPointer(address pointer, bytes32 digest);
    error PointerMismatch(address predicted, address actual);

    /**
     * @notice Computes domain-separated salt for deterministic CREATE2 deployment.
     */
    function computeSalt(bytes32 digest) public pure returns (bytes32) {
        return keccak256(abi.encode(CONTENT_POINTER_DOMAIN, digest));
    }

    /**
     * @notice Predicts the exact CREATE2 address for deterministic SSTORE2 deployment.
     * @dev predicted pointer == actual deployed pointer returned by store(data).
     */
    function predictPointer(bytes calldata data) external view returns (address) {
        bytes32 digest = keccak256(data);
        bytes32 salt = computeSalt(digest);
        return SSTORE2.predictCounterfactualAddress(data, salt, address(this));
    }

    /**
     * @notice Stores a chunk of data if not already present.
     * @param data Raw content bytes to store (must be between 1 and 24,575 bytes).
     * @return digest The keccak256 hash of the content.
     * @return pointer The address of the SSTORE2 contract holding the bytecode.
     */
    function store(bytes calldata data) external returns (bytes32 digest, address pointer) {
        return _store(data);
    }

    /**
     * @notice Stores multiple chunks in a single call, preserving original caller provenance without self-calls.
     */
    function storeBatch(bytes[] calldata chunks)
        external
        returns (bytes32[] memory digests, address[] memory pointers)
    {
        uint256 count = chunks.length;
        digests = new bytes32[](count);
        pointers = new address[](count);

        for (uint256 i = 0; i < count; i++) {
            (digests[i], pointers[i]) = _store(chunks[i]);
        }
    }

    /**
     * @dev Internal chunk storage and deduplication logic using deterministic CREATE2.
     */
    function _store(bytes memory data) internal returns (bytes32 digest, address pointer) {
        if (data.length == 0) revert ChunkEmpty();
        if (data.length > MAX_CHUNK_SIZE) revert ChunkTooLarge(data.length, MAX_CHUNK_SIZE);

        digest = keccak256(data);
        pointer = chunkAddresses[digest];

        if (pointer != address(0)) {
            emit ContentDeduplicated(digest, pointer, msg.sender);
            return (digest, pointer);
        }

        bytes32 salt = computeSalt(digest);
        address predicted = SSTORE2.predictCounterfactualAddress(data, salt, address(this));

        // If code already exists at predicted address, validate it strictly
        if (predicted.code.length > 0) {
            // Must have exactly data.length + 1 bytes (0x00 STOP prefix + data)
            if (predicted.code.length != data.length + 1) {
                revert InvalidExistingPointer(predicted, digest);
            }
            // Read stored bytes (skips 0x00 prefix) and verify exact content match
            bytes memory deployedContent = SSTORE2.read(predicted);
            if (keccak256(deployedContent) != digest) {
                revert InvalidExistingPointer(predicted, digest);
            }
            pointer = predicted;
        } else {
            // Deploy counterfactual contract with domain-separated salt
            pointer = SSTORE2.writeCounterfactual(data, salt);
            if (pointer != predicted) {
                revert PointerMismatch(predicted, pointer);
            }
        }

        chunkAddresses[digest] = pointer;
        chunkSizes[digest] = uint32(data.length);

        emit ContentStored(digest, pointer, data.length, msg.sender);
    }

    /**
     * @notice Reads a stored chunk by its keccak256 digest.
     */
    function read(bytes32 digest) external view returns (bytes memory) {
        address pointer = chunkAddresses[digest];
        if (pointer == address(0)) revert ChunkNotFound(digest);
        return SSTORE2.read(pointer);
    }

    /**
     * @notice Reads a slice of a stored chunk.
     */
    function readSlice(bytes32 digest, uint256 start, uint256 end) external view returns (bytes memory) {
        address pointer = chunkAddresses[digest];
        if (pointer == address(0)) revert ChunkNotFound(digest);
        return SSTORE2.read(pointer, start, end);
    }

    /**
     * @notice Reads and concatenates multiple chunks in order.
     */
    function readChunks(bytes32[] calldata digests) external view returns (bytes memory) {
        uint256 totalSize = 0;
        uint256 count = digests.length;
        address[] memory pointers = new address[](count);

        for (uint256 i = 0; i < count; i++) {
            address p = chunkAddresses[digests[i]];
            if (p == address(0)) revert ChunkNotFound(digests[i]);
            pointers[i] = p;
            totalSize += chunkSizes[digests[i]];
        }

        bytes memory combined = new bytes(totalSize);
        uint256 offset = 0;

        for (uint256 i = 0; i < count; i++) {
            bytes memory chunkData = SSTORE2.read(pointers[i]);
            for (uint256 j = 0; j < chunkData.length; j++) {
                combined[offset + j] = chunkData[j];
            }
            offset += chunkData.length;
        }

        return combined;
    }

    /**
     * @notice Checks whether a given digest is stored.
     */
    function has(bytes32 digest) external view returns (bool) {
        return chunkAddresses[digest] != address(0);
    }
}

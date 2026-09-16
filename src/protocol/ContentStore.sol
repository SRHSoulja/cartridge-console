// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { SSTORE2 } from "../utils/SSTORE2.sol";

/**
 * @title ContentStore
 * @notice Permanent, immutable, content-addressed on-chain store for Console cartridges & assets.
 * @dev Deduplicates storage by indexing chunks on `digest = keccak256(data)`.
 *      Uses SSTORE2 runtime code deployment for optimal read gas and on-chain persistence.
 *      Batch operations use internal storage to preserve original msg.sender provenance in events.
 */
contract ContentStore {
    /// @dev Maximum single chunk size permitted by Spurious Dragon EIP-170 code size limit (24576 - 1 byte STOP = 24575)
    uint256 public constant MAX_CHUNK_SIZE = 24575;

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
     * @dev Internal chunk storage and deduplication logic.
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

        pointer = SSTORE2.write(data);
        chunkAddresses[digest] = pointer;
        chunkSizes[digest] = uint32(data.length);

        emit ContentStored(digest, pointer, data.length, msg.sender);
    }

    /**
     * @notice Predicts the CREATE2 address for counterfactual SSTORE2 deployment.
     */
    function predictPointer(bytes calldata data) external view returns (address) {
        bytes32 salt = keccak256(data);
        return SSTORE2.predictCounterfactualAddress(data, salt, address(this));
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

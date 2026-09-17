// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title CartridgeRegistry
 * @notice On-chain registry tracking cartridge identities, immutable releases, and mutable channels.
 * @dev Enforces strict separation between immutable releases (manifest digests) and mutable channels (e.g. stable, latest).
 *      Features full 256-bit domain-separated cartridge IDs, publisher provenance on releases, and 2-step ownership transfers.
 */
contract CartridgeRegistry {
    struct Release {
        bytes32 manifestDigest;
        address publisher;
        uint64 publishedAt;
        uint64 publishedBlock;
        string version;
    }

    struct CartridgeMeta {
        address owner;
        address pendingOwner;
        string name;
        uint256 releaseCount;
    }

    /// @notice Domain separator for canonical 256-bit cartridge identifiers
    bytes32 public constant CARTRIDGE_ID_DOMAIN = keccak256("CARTRIDGE_PROTOCOL_V1_ID");

    /// @notice Standard channel keys
    bytes32 public constant CHANNEL_STABLE = keccak256("stable");
    bytes32 public constant CHANNEL_LATEST = keccak256("latest");
    bytes32 public constant CHANNEL_BETA = keccak256("beta");

    /// @notice Cartridge metadata keyed by unique cartridgeId
    mapping(bytes32 => CartridgeMeta) public cartridges;

    /// @notice Releases list keyed by cartridgeId
    mapping(bytes32 => Release[]) internal _releases;

    /// @notice Current release index pointed to by a channel: cartridgeId => channelKey => releaseIndex
    mapping(bytes32 => mapping(bytes32 => uint256)) public channelReleaseIndex;

    /// @notice Whether a channel has been explicitly assigned: cartridgeId => channelKey => isConfigured
    mapping(bytes32 => mapping(bytes32 => bool)) public channelConfigured;

    /// @notice Tracks published semantic version labels per cartridge: cartridgeId => keccak256(bytes(version)) => bool
    mapping(bytes32 => mapping(bytes32 => bool)) public isVersionPublished;

    // Events
    event CartridgeRegistered(bytes32 indexed cartridgeId, address indexed initialPublisher, bytes32 salt, string name);
    event ReleasePublished(
        bytes32 indexed cartridgeId,
        uint256 indexed releaseIndex,
        address indexed publisher,
        string version,
        bytes32 manifestDigest
    );
    event ChannelUpdated(bytes32 indexed cartridgeId, bytes32 indexed channelKey, uint256 releaseIndex, bytes32 manifestDigest);
    event OwnershipTransferProposed(bytes32 indexed cartridgeId, address indexed currentOwner, address indexed proposedNewOwner);
    event CartridgeOwnershipTransferred(bytes32 indexed cartridgeId, address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferCancelled(bytes32 indexed cartridgeId, address indexed owner);

    // Errors
    error CartridgeAlreadyExists(bytes32 cartridgeId);
    error CartridgeNotFound(bytes32 cartridgeId);
    error Unauthorized(bytes32 cartridgeId, address caller);
    error InvalidOwner();
    error InvalidManifestDigest();
    error InvalidVersion();
    error VersionAlreadyPublished(bytes32 cartridgeId, string version);
    error ReleaseNotFound(bytes32 cartridgeId, uint256 releaseIndex);
    error ChannelNotSet(bytes32 cartridgeId, bytes32 channelKey);

    modifier onlyOwner(bytes32 cartridgeId) {
        address owner = cartridges[cartridgeId].owner;
        if (owner == address(0)) revert CartridgeNotFound(cartridgeId);
        if (owner != msg.sender) revert Unauthorized(cartridgeId, msg.sender);
        _;
    }

    /**
     * @notice Derives a canonical, domain-separated cartridge identifier.
     * @param initialPublisher The address creating the cartridge.
     * @param salt An arbitrary 32-byte salt chosen by the publisher.
     */
    function computeCartridgeId(address initialPublisher, bytes32 salt) public pure returns (bytes32) {
        return keccak256(abi.encode(CARTRIDGE_ID_DOMAIN, initialPublisher, salt));
    }

    /**
     * @notice Registers a new canonical cartridge namespace.
     * @param salt An arbitrary 32-byte salt chosen by the caller.
     * @param name Human-readable identifier/metadata name.
     * @return cartridgeId Unique 256-bit identifier.
     */
    function registerCartridge(bytes32 salt, string calldata name) external returns (bytes32 cartridgeId) {
        cartridgeId = computeCartridgeId(msg.sender, salt);
        if (cartridges[cartridgeId].owner != address(0)) {
            revert CartridgeAlreadyExists(cartridgeId);
        }

        cartridges[cartridgeId] = CartridgeMeta({
            owner: msg.sender,
            pendingOwner: address(0),
            name: name,
            releaseCount: 0
        });

        emit CartridgeRegistered(cartridgeId, msg.sender, salt, name);
    }

    /**
     * @notice Publishes an immutable release for a cartridge.
     * @dev Boundary Architecture Decision:
     *      The registry records an immutable publisher commitment to a manifestDigest.
     *      It is deliberately storage-backend-agnostic; it does not verify immediate
     *      content retrievability at publish time. Content availability is verified
     *      at resolution time by the host resolver.
     *      Semantic version labels are immutable: duplicate versions for the same cartridge are rejected.
     * @param cartridgeId The ID of the cartridge.
     * @param version Semantic version string (e.g. "1.0.0").
     * @param manifestDigest The keccak256 digest of the canonical manifest stored in ContentStore.
     * @return releaseIndex Index of the published release.
     */
    function publishRelease(
        bytes32 cartridgeId,
        string calldata version,
        bytes32 manifestDigest
    ) external onlyOwner(cartridgeId) returns (uint256 releaseIndex) {
        if (manifestDigest == bytes32(0)) revert InvalidManifestDigest();
        if (bytes(version).length == 0) revert InvalidVersion();

        bytes32 vHash = keccak256(bytes(version));
        if (isVersionPublished[cartridgeId][vHash]) {
            revert VersionAlreadyPublished(cartridgeId, version);
        }
        isVersionPublished[cartridgeId][vHash] = true;

        releaseIndex = _releases[cartridgeId].length;

        _releases[cartridgeId].push(Release({
            manifestDigest: manifestDigest,
            publisher: msg.sender,
            publishedAt: uint64(block.timestamp),
            publishedBlock: uint64(block.number),
            version: version
        }));

        cartridges[cartridgeId].releaseCount = releaseIndex + 1;

        emit ReleasePublished(cartridgeId, releaseIndex, msg.sender, version, manifestDigest);

        // Always update CHANNEL_LATEST to newest release
        channelReleaseIndex[cartridgeId][CHANNEL_LATEST] = releaseIndex;
        channelConfigured[cartridgeId][CHANNEL_LATEST] = true;
        emit ChannelUpdated(cartridgeId, CHANNEL_LATEST, releaseIndex, manifestDigest);

        // If this is the first release (index 0), initialize CHANNEL_STABLE automatically
        if (releaseIndex == 0) {
            channelReleaseIndex[cartridgeId][CHANNEL_STABLE] = 0;
            channelConfigured[cartridgeId][CHANNEL_STABLE] = true;
            emit ChannelUpdated(cartridgeId, CHANNEL_STABLE, 0, manifestDigest);
        }
    }

    /**
     * @notice Points a mutable channel to an existing immutable release.
     * @param cartridgeId The ID of the cartridge.
     * @param channelKey Channel identifier (e.g. CHANNEL_STABLE, CHANNEL_BETA).
     * @param releaseIndex Index of the release to point to.
     */
    function setChannel(
        bytes32 cartridgeId,
        bytes32 channelKey,
        uint256 releaseIndex
    ) external onlyOwner(cartridgeId) {
        if (releaseIndex >= _releases[cartridgeId].length) {
            revert ReleaseNotFound(cartridgeId, releaseIndex);
        }

        channelReleaseIndex[cartridgeId][channelKey] = releaseIndex;
        channelConfigured[cartridgeId][channelKey] = true;

        bytes32 digest = _releases[cartridgeId][releaseIndex].manifestDigest;
        emit ChannelUpdated(cartridgeId, channelKey, releaseIndex, digest);
    }

    /**
     * @notice Proposes an ownership transfer for a cartridge (Step 1 of 2-step transfer).
     */
    function proposeOwnershipTransfer(bytes32 cartridgeId, address proposedNewOwner) external onlyOwner(cartridgeId) {
        if (proposedNewOwner == address(0)) revert InvalidOwner();
        cartridges[cartridgeId].pendingOwner = proposedNewOwner;
        emit OwnershipTransferProposed(cartridgeId, msg.sender, proposedNewOwner);
    }

    /**
     * @notice Accepts ownership of a cartridge (Step 2 of 2-step transfer).
     */
    function acceptOwnership(bytes32 cartridgeId) external {
        address pending = cartridges[cartridgeId].pendingOwner;
        if (pending == address(0) || msg.sender != pending) {
            revert Unauthorized(cartridgeId, msg.sender);
        }

        address previous = cartridges[cartridgeId].owner;
        cartridges[cartridgeId].owner = msg.sender;
        cartridges[cartridgeId].pendingOwner = address(0);

        emit CartridgeOwnershipTransferred(cartridgeId, previous, msg.sender);
    }

    /**
     * @notice Cancels a pending ownership proposal.
     */
    function cancelOwnershipTransfer(bytes32 cartridgeId) external onlyOwner(cartridgeId) {
        cartridges[cartridgeId].pendingOwner = address(0);
        emit OwnershipTransferCancelled(cartridgeId, msg.sender);
    }

    /**
     * @notice Resolves the manifest digest for a specific channel (e.g. CHANNEL_STABLE).
     */
    function resolveManifest(bytes32 cartridgeId, bytes32 channelKey) external view returns (bytes32 manifestDigest) {
        if (cartridges[cartridgeId].owner == address(0)) revert CartridgeNotFound(cartridgeId);
        if (!channelConfigured[cartridgeId][channelKey]) revert ChannelNotSet(cartridgeId, channelKey);

        uint256 index = channelReleaseIndex[cartridgeId][channelKey];
        return _releases[cartridgeId][index].manifestDigest;
    }

    /**
     * @notice Retrieves release by index.
     */
    function getRelease(bytes32 cartridgeId, uint256 releaseIndex) external view returns (Release memory) {
        if (releaseIndex >= _releases[cartridgeId].length) revert ReleaseNotFound(cartridgeId, releaseIndex);
        return _releases[cartridgeId][releaseIndex];
    }

    /**
     * @notice Retrieves total release count for a cartridge.
     */
    function getReleaseCount(bytes32 cartridgeId) external view returns (uint256) {
        return _releases[cartridgeId].length;
    }

    /**
     * @notice Retrieves release by channel key.
     */
    function getChannelRelease(bytes32 cartridgeId, bytes32 channelKey)
        external
        view
        returns (Release memory release, uint256 releaseIndex)
    {
        if (cartridges[cartridgeId].owner == address(0)) revert CartridgeNotFound(cartridgeId);
        if (!channelConfigured[cartridgeId][channelKey]) revert ChannelNotSet(cartridgeId, channelKey);

        releaseIndex = channelReleaseIndex[cartridgeId][channelKey];
        release = _releases[cartridgeId][releaseIndex];
    }

    /**
     * @notice Checks whether a semantic version label has already been published for a cartridge.
     */
    function hasVersion(bytes32 cartridgeId, string calldata version) external view returns (bool) {
        return isVersionPublished[cartridgeId][keccak256(bytes(version))];
    }
}

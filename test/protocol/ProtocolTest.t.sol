// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Test, console2 } from "forge-std/Test.sol";
import { ContentStore } from "../../src/protocol/ContentStore.sol";
import { CartridgeRegistry } from "../../src/protocol/CartridgeRegistry.sol";

contract ProtocolTest is Test {
    ContentStore internal store;
    CartridgeRegistry internal registry;

    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);
    address internal charlie = address(0xC0C);

    function setUp() public {
        store = new ContentStore();
        registry = new CartridgeRegistry();
    }

    // --- CONTENT STORE TESTS ---

    function test_ContentStore_StoreAndReadRoundTrip() public {
        bytes memory sample = "Hello Console Runtime V0.2 & Cartridge Protocol V0.1";
        bytes32 expectedDigest = keccak256(sample);

        (bytes32 digest, address pointer) = store.store(sample);
        assertEq(digest, expectedDigest, "Digest mismatch");
        assertTrue(pointer != address(0), "Pointer should not be zero");
        assertTrue(store.has(digest), "Store should confirm chunk exists");
        assertEq(store.chunkSizes(digest), sample.length, "Size mismatch");

        bytes memory retrieved = store.read(digest);
        assertEq(keccak256(retrieved), expectedDigest, "Retrieved data hash mismatch");
        assertEq(string(retrieved), string(sample), "Retrieved string mismatch");
    }

    function test_ContentStore_DeduplicationInvariant() public {
        bytes memory sharedLib = "function sharedEngine() { return 'hoodquest_engine_v1'; }";
        bytes32 expectedDigest = keccak256(sharedLib);

        // First cartridge / author stores sharedLib
        vm.prank(alice);
        (bytes32 digest1, address pointer1) = store.store(sharedLib);
        assertEq(digest1, expectedDigest, "Digest must match keccak256");

        // Second cartridge / author stores exact same sharedLib
        vm.prank(bob);
        (bytes32 digest2, address pointer2) = store.store(sharedLib);

        assertEq(digest1, digest2, "Digests must be identical");
        assertEq(pointer1, pointer2, "Pointer must be exactly deduplicated to same contract address");

        // Code length of pointer should be exactly sharedLib.length + 1 STOP byte
        assertEq(pointer1.code.length, sharedLib.length + 1);
    }

    function test_ContentStore_BatchStorePreservesProvenance() public {
        bytes[] memory chunks = new bytes[](2);
        chunks[0] = "Batch Chunk 1";
        chunks[1] = "Batch Chunk 2";

        vm.prank(alice);
        (bytes32[] memory digests, address[] memory pointers) = store.storeBatch(chunks);

        assertEq(digests.length, 2);
        assertEq(pointers.length, 2);
        assertEq(string(store.read(digests[0])), "Batch Chunk 1");
        assertEq(string(store.read(digests[1])), "Batch Chunk 2");
    }

    function test_ContentStore_MultiChunkAssembly() public {
        bytes memory part1 = "Part 1: Header and Bootstrap. ";
        bytes memory part2 = "Part 2: Game Logic and Shaders. ";
        bytes memory part3 = "Part 3: Music and Sprites.";

        (bytes32 d1, ) = store.store(part1);
        (bytes32 d2, ) = store.store(part2);
        (bytes32 d3, ) = store.store(part3);

        bytes32[] memory digests = new bytes32[](3);
        digests[0] = d1;
        digests[1] = d2;
        digests[2] = d3;

        bytes memory assembled = store.readChunks(digests);
        bytes memory expected = abi.encodePacked(part1, part2, part3);

        assertEq(keccak256(assembled), keccak256(expected), "Assembled multi-chunk content must match expected");
    }

    function test_ContentStore_CounterfactualPointerPrediction() public view {
        bytes memory sample = "Predictable Content Bytecode";
        address predicted = store.predictPointer(sample);
        assertTrue(predicted != address(0));
    }

    function test_ContentStore_RevertOnEmpty() public {
        vm.expectRevert(ContentStore.ChunkEmpty.selector);
        store.store("");
    }

    function test_ContentStore_RevertOnOversized() public {
        bytes memory oversized = new bytes(24576); // Max is 24575
        vm.expectRevert(abi.encodeWithSelector(ContentStore.ChunkTooLarge.selector, 24576, 24575));
        store.store(oversized);
    }

    function test_ContentStore_RevertOnMissing() public {
        bytes32 nonExistent = keccak256("does_not_exist");
        vm.expectRevert(abi.encodeWithSelector(ContentStore.ChunkNotFound.selector, nonExistent));
        store.read(nonExistent);
    }

    // --- CARTRIDGE REGISTRY TESTS ---

    function test_CartridgeRegistry_DomainSeparatedIdAndReleaseProvenance() public {
        vm.startPrank(alice);

        bytes32 salt = bytes32(uint256(12345));
        bytes32 expectedId = keccak256(abi.encode(registry.CARTRIDGE_ID_DOMAIN(), alice, salt));

        // 1. Register with salt
        bytes32 cartridgeId = registry.registerCartridge(salt, "hoodquest");
        assertEq(cartridgeId, expectedId, "Cartridge ID must match domain-separated keccak256");

        (address owner, address pending, string memory name, uint256 releaseCount) = registry.cartridges(cartridgeId);
        assertEq(owner, alice);
        assertEq(pending, address(0));
        assertEq(name, "hoodquest");
        assertEq(releaseCount, 0);

        // 2. Publish Release 0 (v0.1.0)
        bytes32 manifestV1Digest = keccak256("hoodquest_manifest_v1");
        uint256 idx0 = registry.publishRelease(cartridgeId, "0.1.0", manifestV1Digest);
        assertEq(idx0, 0);

        CartridgeRegistry.Release memory r0 = registry.getRelease(cartridgeId, 0);
        assertEq(r0.publisher, alice, "Release publisher must be recorded directly on release");
        assertEq(r0.manifestDigest, manifestV1Digest);
        assertEq(r0.version, "0.1.0");

        // Stable and Latest both point to idx0 automatically
        bytes32 stableDigest = registry.resolveManifest(cartridgeId, registry.CHANNEL_STABLE());
        bytes32 latestDigest = registry.resolveManifest(cartridgeId, registry.CHANNEL_LATEST());
        assertEq(stableDigest, manifestV1Digest);
        assertEq(latestDigest, manifestV1Digest);

        // 3. Publish Release 1 (v0.2.0)
        bytes32 manifestV2Digest = keccak256("hoodquest_manifest_v2");
        uint256 idx1 = registry.publishRelease(cartridgeId, "0.2.0", manifestV2Digest);
        assertEq(idx1, 1);

        // Latest moves to v0.2.0, while Stable stays on v0.1.0
        assertEq(registry.resolveManifest(cartridgeId, registry.CHANNEL_LATEST()), manifestV2Digest);
        assertEq(registry.resolveManifest(cartridgeId, registry.CHANNEL_STABLE()), manifestV1Digest);

        // 4. Promote v0.2.0 to Stable channel
        registry.setChannel(cartridgeId, registry.CHANNEL_STABLE(), 1);
        assertEq(registry.resolveManifest(cartridgeId, registry.CHANNEL_STABLE()), manifestV2Digest);

        vm.stopPrank();
    }

    function test_CartridgeRegistry_TwoStepOwnershipTransfer() public {
        vm.startPrank(alice);
        bytes32 salt = bytes32(uint256(999));
        bytes32 cartridgeId = registry.registerCartridge(salt, "secure-cart");

        // Step 1: Propose Bob
        registry.proposeOwnershipTransfer(cartridgeId, bob);
        (, address pending, , ) = registry.cartridges(cartridgeId);
        assertEq(pending, bob);

        // Charlie tries to accept -> reverts
        vm.stopPrank();
        vm.prank(charlie);
        vm.expectRevert(abi.encodeWithSelector(CartridgeRegistry.Unauthorized.selector, cartridgeId, charlie));
        registry.acceptOwnership(cartridgeId);

        // Alice is still owner; can publish
        vm.prank(alice);
        registry.publishRelease(cartridgeId, "1.0.0", keccak256("v1"));

        // Bob cannot publish before accepting
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(CartridgeRegistry.Unauthorized.selector, cartridgeId, bob));
        registry.publishRelease(cartridgeId, "1.0.1", keccak256("v1.0.1"));

        // Step 2: Bob accepts
        vm.prank(bob);
        registry.acceptOwnership(cartridgeId);

        (address newOwner, address newPending, , ) = registry.cartridges(cartridgeId);
        assertEq(newOwner, bob);
        assertEq(newPending, address(0));

        // Bob publishes Release 1 with his own publisher provenance
        vm.prank(bob);
        uint256 idx = registry.publishRelease(cartridgeId, "2.0.0", keccak256("v2"));
        assertEq(idx, 1);

        // Historical release 0 provenance still points to Alice!
        CartridgeRegistry.Release memory rel0 = registry.getRelease(cartridgeId, 0);
        assertEq(rel0.publisher, alice, "Historical release publisher must remain immutable");

        // Release 1 provenance points to Bob!
        CartridgeRegistry.Release memory rel1 = registry.getRelease(cartridgeId, 1);
        assertEq(rel1.publisher, bob, "New release publisher must be Bob");
    }

    function test_CartridgeRegistry_CancelOwnershipTransfer() public {
        vm.startPrank(alice);
        bytes32 cartridgeId = registry.registerCartridge(bytes32(uint256(777)), "cancel-test");
        registry.proposeOwnershipTransfer(cartridgeId, bob);

        // Alice changes mind and cancels
        registry.cancelOwnershipTransfer(cartridgeId);
        (, address pending, , ) = registry.cartridges(cartridgeId);
        assertEq(pending, address(0));
        vm.stopPrank();

        // Bob tries to accept -> reverts
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(CartridgeRegistry.Unauthorized.selector, cartridgeId, bob));
        registry.acceptOwnership(cartridgeId);
    }
}

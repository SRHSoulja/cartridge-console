# ContentStore Architecture & On-Chain Storage Substrate

**Status**: Prototype Specification & Reference Implementation  
**Contract**: `src/protocol/ContentStore.sol`  
**Dependencies**: `src/utils/SSTORE2.sol`  

---

## 1. Architectural Purpose

Autonomous on-chain games and virtual consoles require permanent, decentralized access to code, markup, graphics, and audio assets without relying on centralized servers or ephemeral data availability layers.

`ContentStore` provides an immutable, content-addressed on-chain storage substrate where:
- Every chunk of data is keyed by its cryptographic hash: `digest = keccak256(data)`.
- Chunks are stored using EVM contract runtime bytecode (`SSTORE2`), yielding minimal deployment gas and zero execution overhead for read operations.
- Identical data chunks across any number of cartridges are automatically deduplicated.

---

## 2. Chunking & EIP-170 Limits

Under Ethereum Improvement Proposal 170 (Spurious Dragon), the maximum contract code size is bounded at 24,576 bytes (`0x6000`).

SSTORE2 prefixes a single `0x00` (`STOP`) opcode to the runtime bytecode to ensure the contract cannot be executed as arbitrary EVM instructions. Consequently:

$$\text{MAX\_CHUNK\_SIZE} = 24,576 - 1 = 24,575 \text{ bytes}$$

### Multi-Chunk Decomposition

For payloads exceeding 24,575 bytes:
1. Payloads are divided into sequential chunks of at most 24,575 bytes.
2. Each chunk is persisted via `ContentStore.store(chunkBytes)`.
3. The cartridge manifest records the ordered sequence of chunk digests:
   `entry.chunks = [digest_0, digest_1, ..., digest_n]`.
4. Multi-chunk data can be retrieved individually or assembled on-chain via `ContentStore.readChunks(digests)`.

---

## 3. Storage Deduplication Invariant

Because chunk addresses are mapped by `keccak256(data)`, identical content is stored exactly once:

```solidity
function store(bytes calldata data) external returns (bytes32 digest, address pointer) {
    if (data.length == 0) revert ChunkEmpty();
    if (data.length > MAX_CHUNK_SIZE) revert ChunkTooLarge(data.length, MAX_CHUNK_SIZE);

    digest = keccak256(data);
    pointer = chunkAddresses[digest];

    // If chunk already exists, reuse pointer without new contract creation
    if (pointer != address(0)) {
        emit ContentDeduplicated(digest, pointer, msg.sender);
        return (digest, pointer);
    }

    pointer = SSTORE2.write(data);
    chunkAddresses[digest] = pointer;
    chunkSizes[digest] = uint32(data.length);

    emit ContentStored(digest, pointer, data.length, msg.sender);
}
```

### Benefits of Deduplication:
- **Shared Libraries**: Core libraries (e.g. vector math, sound synths, font tables) uploaded by one cartridge can be referenced by subsequent cartridges at zero deployment cost.
- **Gas Conservation**: Authors never pay deployment gas for assets that have already been uploaded by others.

---

## 4. Permanent Storage vs Ephemeral Blobs (EIP-4844)

A critical design choice is the avoidance of EIP-4844 blob storage for canonical cartridge packages.

| Feature | SSTORE2 / ContentStore | EIP-4844 Blobs |
| :--- | :--- | :--- |
| **Persistence Horizon** | **Permanent (Indefinite)** | **Ephemeral (~18 to 30 days)** |
| **EVM Smart Contract Accessibility** | **Direct on-chain via `EXTCODECOPY`** | **Inaccessible from execution layer** |
| **Decentralized Host Independence** | **Complete (Read via any RPC node)** | **Requires external archiving indexers** |
| **Primary Use Case** | **On-chain games, cartridges, permanent NFTs** | **L2 rollup transaction batches** |

Because cartridges represent permanent digital artifacts, relying on ephemeral blobs would reintroduce centralized archiving dependencies, defeating the premise of on-chain gaming.

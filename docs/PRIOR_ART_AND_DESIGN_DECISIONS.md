# Prior Art & Architectural Design Decisions

**Platform**: HoodQuest / Console Protocol V0.2  
**Context**: On-Chain Gaming, Fully On-Chain Applications, Cartridge Platforms  

---

## 1. Prior Art Analysis

The design of the Console Runtime and Cartridge Protocol draws on and synthesizes several prior on-chain gaming and metadata architectures:

### 1.1 Loot (for Adventurers) & SVG On-Chain NFTs
- **Pattern**: Generating deterministic game primitives directly in contract storage and rendering dynamic SVG/HTML in `tokenURI`.
- **Limitation**: Monolithic Solidity contracts that generate markup in contract code become extremely expensive to upgrade, maintain, or render complex interactive game loops with audio and input handling.

### 1.2 Event-Log Based State Reconstruction
- **Pattern**: Applications where state or history is recorded on-chain via sparse events rather than heavy storage arrays, requiring client-side reconstruction.
- **Console Adoption**: Console Protocol V0.2 directly introduces `evm.logs` (`eth_getLogs`) as a first-class host bridge primitive, allowing cartridges to reconstruct application history from blockchain logs without commercial indexing APIs.

### 1.3 MUD, Dojo, and Curio (Autonomous World Frameworks)
- **Pattern**: Entity Component System (ECS) architectures on-chain.
- **Tradeoff**: While powerful for complex multi-entity rulebooks, ECS frameworks often require specialized compilers, heavy indexing dependencies, and impose high transaction overhead on casual interactive experiences.
- **Console Decision**: Decouple client rendering and runtime from on-chain smart contracts. Smart contracts manage assets and settlement rules; the cartridge runtime manages rendering, inputs, and client state machines.

---

## 2. Key Architectural Decisions & Rationale

### Decision 1: SSTORE2 Code Storage vs EIP-4844 Blobs
- **Context**: Storing large game code (HTML, JS, WebAssembly, pixel art) on Ethereum.
- **Decision**: Use `SSTORE2` runtime bytecode deployment over EIP-4844 blobs.
- **Rationale**: EIP-4844 blobs expire after roughly 18 to 30 days. Permanent game cartridges cannot rely on temporary data availability without reintroducing centralized web servers. SSTORE2 stores data as contract runtime bytecode permanently, readable directly by standard EVM nodes via `EXTCODECOPY`.

### Decision 2: Content-Addressed Chunk Deduplication
- **Context**: Multiple cartridges sharing common libraries or sprite sheets.
- **Decision**: Index `ContentStore` by `keccak256(data)`.
- **Rationale**: If Cartridge A and Cartridge B both rely on the same sound engine or graphics table, the second author’s transaction automatically references the existing deployed chunk contract address without paying deployment gas or consuming extra state.

### Decision 3: RFC 8785 JSON Canonicalization Scheme (JCS)
- **Context**: Verifying manifest integrity.
- **Decision**: Mandate deterministic JSON serialization per RFC 8785.
- **Rationale**: Standard JSON serialization is non-deterministic (differing whitespace, object property ordering, floating-point string formats). RFC 8785 ensures that calculating `keccak256(manifest)` yields the exact same hash across any programming language (Solidity, JavaScript, Rust, Python).

### Decision 4: Separation of Immutable Releases and Mutable Channels
- **Context**: How players load updates to a cartridge.
- **Decision**: Separate release records from channel pointers in `CartridgeRegistry`.
- **Rationale**: A software release must be immutable so that players are protected against stealth modifications or retroactive code changes. Channels (`stable`, `latest`, `beta`) provide the necessary developer convenience to publish updates without breaking historical references.

# Cartridge Console

Generic on-chain cartridge runtime, web host container, and decentralized publishing substrate.

## Provenance
This repository was extracted from `SRHSoulja/hoodquest` at pre-split checkpoint:
`f1e528e0350465db652032751063050b9d59c52f`

## Architecture
- **Console Protocol V0.2**: Secure bidirectional MessagePort RPC bridge between privileged host container and sandboxed cartridge payload.
- **Cartridge Protocol V0.1**: Universal client runtime abstraction supporting dual-adapter execution (Direct injected provider or Bridge sandbox).
- **ContentStore**: Immutable, content-addressed storage substrate leveraging SSTORE2 bytecode deployment and chunk deduplication.
- **CartridgeRegistry**: Decentralized namespace and release registry enforcing immutable release records and mutable channel routing (`stable`, `latest`, `beta`).
- **Canonical Manifest V1**: Deterministic RFC 8785 JSON Canonicalization Scheme (JCS) with CAIP-2 chain identifiers.

## Repository Layout
- `runtime/`: Universal cartridge client runtime (`cartridge_host_runtime.js`).
- `host/`: Generic Web Host, resolver abstraction, and MessageChannel bridge (`host_core.js`, `resolver.js`, `index.html`).
- `src/protocol/`: On-chain publishing substrate smart contracts (`ContentStore.sol`, `CartridgeRegistry.sol`).
- `cartridges/`: Reference and adversarial test cartridges.
- `docs/`: Comprehensive protocol specifications and security models.
- `test/`: Hardened adversarial security suite, compatibility harness, and protocol tests.

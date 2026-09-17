# Console Platform & Cartridge Protocol Specification Index

This document is the authoritative index for all technical specifications, schemas, and architectural standards across the Console Platform and Cartridge ecosystem.

---

## 1. Normative & Active Specifications

The following specifications define the active platform architecture. All developers and automated agents should treat these documents as authoritative:

| Document | Status | Description |
| :--- | :--- | :--- |
| [`docs/CONSOLE_PROTOCOL_V0_2.md`](file:///home/arson/RH/cartridge-console/docs/CONSOLE_PROTOCOL_V0_2.md) | **Current (V0.2)** | Console Host Runtime, MessageChannel privileged bridge, RPC interface, permission firewall, capability negotiation, and error semantics. |
| [`docs/CARTRIDGE_MANIFEST_V1.md`](file:///home/arson/RH/cartridge-console/docs/CARTRIDGE_MANIFEST_V1.md) | **Current (V1.0)** | Standard Cartridge Manifest V1 format: CAIP-2 chain binding, 32-byte canonical cartridge ID, entry resource descriptor, encoding, and chunking. |
| [`schemas/cartridge-manifest-v1.schema.json`](file:///home/arson/RH/cartridge-console/schemas/cartridge-manifest-v1.schema.json) | **Current (V1.0)** | Authoritative JSON Schema enforcing Manifest V1 structure, regular expressions, and field types. |
| [`docs/CARTRIDGE_PROTOCOL_V0_1.md`](file:///home/arson/RH/cartridge-console/docs/CARTRIDGE_PROTOCOL_V0_1.md) | **Current (V0.1)** | On-chain publishing pipeline, SSTORE2 content chunking, and deterministic bytecode addresses. |
| [`docs/CARTRIDGE_REGISTRY_V0_1.md`](file:///home/arson/RH/cartridge-console/docs/CARTRIDGE_REGISTRY_V0_1.md) | **Current (V0.1)** | On-chain CartridgeRegistry contract: identity commitments, immutable releases, and mutable channels. |
| [`docs/CONTENT_STORE_ARCHITECTURE.md`](file:///home/arson/RH/cartridge-console/docs/CONTENT_STORE_ARCHITECTURE.md) | **Current (V0.1)** | ContentStore chunking, content-addressed deduplication, and cross-cartridge dependency sharing. |
| [`docs/SECURITY_MODEL.md`](file:///home/arson/RH/cartridge-console/docs/SECURITY_MODEL.md) | **Current** | Threat model, sandboxing, CSPRNG nonces, and defense-in-depth permission boundaries. |
| [`docs/ARCHITECTURE_DECISIONS_V1.md`](file:///home/arson/RH/cartridge-console/docs/ARCHITECTURE_DECISIONS_V1.md) | **Current** | Core architectural decisions, permissionless invariants, ownership boundaries, and deferred scope. |

---

## 2. Canonical Developer Artifacts & Reference Fixtures

| Resource | Version | Purpose |
| :--- | :--- | :--- |
| [`cartridges/reference-cartridge-v1/`](file:///home/arson/RH/cartridge-console/cartridges/reference-cartridge-v1/) | **V1.0** | Primary generic reference cartridge exercising Manifest V1, runtime handshake, and RPC calls. |
| [`cartridge-template/`](file:///home/arson/RH/cartridge-console/cartridge-template/) | **V1.0** | Authoritative developer starter kit with canonical Manifest V1 descriptor and boilerplate runtime adapter. |

---

## 3. Historical & Non-Authoritative Archives

The following documents represent superseded prototype designs. They are retained strictly for backward compatibility testing and audit history:

| Document / Path | Status | Notes |
| :--- | :--- | :--- |
| [`CONSOLE_RUNTIME_V0.md`](file:///home/arson/RH/cartridge-console/CONSOLE_RUNTIME_V0.md) | **Historical Archive** | Superseded by [`CONSOLE_PROTOCOL_V0_2.md`](file:///home/arson/RH/cartridge-console/docs/CONSOLE_PROTOCOL_V0_2.md). |
| [`CARTRIDGE_V0_SPEC.md`](file:///home/arson/RH/cartridge-console/CARTRIDGE_V0_SPEC.md) | **Historical Archive** | Superseded by [`CARTRIDGE_MANIFEST_V1.md`](file:///home/arson/RH/cartridge-console/docs/CARTRIDGE_MANIFEST_V1.md). |
| [`schemas/legacy/cartridge-manifest-v0.schema.json`](file:///home/arson/RH/cartridge-console/schemas/legacy/cartridge-manifest-v0.schema.json) | **Legacy V0 Schema** | Retained to validate legacy V0 cartridges during compatibility tests. |
| [`cartridges/legacy-v0/runtime-test-cartridge/`](file:///home/arson/RH/cartridge-console/cartridges/legacy-v0/runtime-test-cartridge/) | **Legacy V0 Fixture** | Preserved solely for backward-compatibility regression tests. |
| [`cartridge-template/legacy-v0/`](file:///home/arson/RH/cartridge-console/cartridge-template/legacy-v0/) | **Legacy V0 Template** | Preserved for reference; do not use for new development. |
| [`docs/PRIOR_ART_AND_DESIGN_DECISIONS.md`](file:///home/arson/RH/cartridge-console/docs/PRIOR_ART_AND_DESIGN_DECISIONS.md) | **Reference** | Prior-art analysis and design decisions behind ContentStore and Registry. |

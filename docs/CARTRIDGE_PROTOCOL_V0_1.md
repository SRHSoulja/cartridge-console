# Cartridge Protocol V0.1 Specification

**Status**: Draft / Prototype Specification  
**Version**: 0.1.0  
**Target Runtimes**: Universal (Standalone Web, Blockscout Iframe, Embedded Console Host)  

---

## 1. Abstract

The **Cartridge Protocol** standardizes how autonomous on-chain applications (games, interactive dashboards, media experiences) package their assets, declare required permissions, and execute predictably across disparate execution contexts.

A Cartridge targeting Protocol V0.1 requires zero specialized knowledge of host containers, wallet protocols (MetaMask, Phantom, WalletConnect), or RPC node configurations.

---

## 2. Cartridge Architecture & Layers

A cartridge operates across three decoupled architectural tiers:

```
┌─────────────────────────────────────────────────────────────┐
│                      CARTRIDGE PAYLOAD                      │
│   (HTML5, Canvas, Game Mechanics, Audio, State Machines)    │
└──────────────────────────────┬──────────────────────────────┘
                               │ targets
┌──────────────────────────────▼──────────────────────────────┐
│                    CARTRIDGE HOST RUNTIME                   │
│  - CartridgeHost singleton client                           │
│  - Transport auto-detection (Direct vs Bridge)              │
│  - EIP-1193 & Policy abstraction                            │
└──────────────────────────────┬──────────────────────────────┘
                               │ executes within
┌──────────────────────────────▼──────────────────────────────┐
│                       HOST CONTAINER                        │
│  - Minimal Sandbox Iframe (`allow-scripts`)                 │
│  - Requested vs Granted Permission Gatekeeper               │
│  - Wallet & Signer Management                               │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Dual Adapter Execution Model

To ensure universal execution, the Cartridge Runtime provides two runtime adapters:

### 1. `DirectHostAdapter`
- **When Used**: Cartridge is loaded directly in a web browser as a standalone application, or within a mobile wallet's in-app browser.
- **Provider Discovery**: Discovers `window.ethereum` (or `window.phantom?.ethereum`).
- **Read Fallback**: If no wallet is injected, transparently routes read calls and log queries to public JSON-RPC nodes.
- **Write Policy**: Enforces client-side policy evaluation if a granted policy is configured.

### 2. `BridgeHostAdapter`
- **When Used**: Cartridge is executed inside an isolated, sandboxed iframe within a parent Console Host.
- **Isolation Boundary**: Runs in a `null`-origin or opaque sandbox where `window.ethereum` is completely inaccessible.
- **Transport**: Communicates strictly via `MessagePort` over a dedicated `MessageChannel`.
- **Zero Local Keys**: The cartridge never sees user private keys or direct provider handles.

---

## 4. Lifecycle & Boot Sequence

1. **Manifest Parsing**: Host reads the Cartridge Manifest (`cartridge.json` or on-chain manifest).
2. **Permission Computation**: Host derives the granted policy by intersecting requested permissions with user/host allowlists.
3. **Integrity Validation**: Host verifies `keccak256(payloadBytes) === expectedContentHash` before rendering.
4. **Sandbox Instantiation**: Host creates an `<iframe>` with minimal flags: `sandbox="allow-scripts"`.
5. **Handshake Negotiation**:
   - Cartridge initializes `CartridgeHost.initCartridgeHostNegotiation()`.
   - Sends `cartridge:init` with `channel.port2` transferred.
   - Host receives message, binds port RPC, and replies with `handshake_ack` containing initial capabilities.
   - Cartridge switches active adapter to `BridgeHostAdapter`.
6. **Execution**: Cartridge game engine starts and communicates via standard `CartridgeHost` API methods (`readContract`, `writeContract`, `getLogs`, `connect`).

---

## 5. Backward Compatibility & Reference Implementations

- **Cartridge #0001 (HoodQuest: Sanctuary of the Falcon)**: The founding reference cartridge. Chunks 1–7 remain bit-for-bit invariant on Ethereum testnets while targeting this specification.
- **Cartridge #0002 (Runtime Test Cartridge)**: Minimal reference implementation verifying multi-tenant execution without game logic.

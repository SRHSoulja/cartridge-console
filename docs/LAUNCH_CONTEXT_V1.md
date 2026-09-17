# Console Platform: Launch Context Specification V1

**Status:** Normative Specification  
**Version:** 1.0.0  
**Authors:** Console Platform Team  
**Date:** September 16, 2026  

---

## 1. Abstract

Launch Context V1 defines a standardized, secure mechanism for passing initial presentation routing and external asset context (such as an ERC-721 token) into a sandboxed Cartridge at startup.

Launch Context is delivered exclusively across the privileged host-to-cartridge `MessagePort` channel during the initial handshake acknowledgment (`cartridge:handshake:ack`).

---

## 2. Core Security Invariant

```text
LAUNCH CONTEXT != AUTHORITY
```

1. **Informational Route Only**: The host uses Launch Context to advise the cartridge on what initial asset or view to render (e.g., "Display Mark #123").
2. **Zero Inferred Ownership**: Launch Context **never** asserts, conveys, or proves that the active user or connected wallet owns the specified asset.
3. **Independent Authorization**: Any interactive operation or state mutation (such as a burn, merge, or transfer) requires independent verification:
   - Active wallet connection via EIP-1193.
   - On-chain ownership verification via `ownerOf(tokenId) == activeAccount`.
   - Contract-level authorization and explicit user signature.
4. **Zero Permission Escalation**: Launch Context **never** widens or alters the granted contract permissions computed by the host's policy firewall.

---

## 3. Normative Envelope & Schema

Launch Context V1 is represented as a JSON object adhering to the following structure:

```json
{
  "version": "1",
  "resource": "eip155:4663/erc721:0xdd084caa7973fa07b71c7247236738786e04057a/123",
  "route": "detail",
  "params": {
    "tab": "history"
  }
}
```

### Field Definitions

| Field | Type | Required? | Description |
| :--- | :--- | :---: | :--- |
| `version` | string | **Yes** | Protocol version. Must be exactly `"1"`. |
| `resource` | string | No | Standardized asset identifier adhering to **CAIP-19**. |
| `route` | string | No | Opaque, cartridge-defined presentation route. Max 64 characters matching `^[a-zA-Z0-9:_\-\/]+$`. |
| `params` | object | No | Optional key-value dictionary of string, number, or boolean primitives. Max 10 keys, max depth 2. |

---

## 4. CAIP-19 Standardized Asset Identification

When `resource` references a blockchain asset, it **MUST** conform to the **CAIP-19** Asset Identification Scheme:

```text
<chain_id>/<asset_namespace>:<asset_reference>[/<token_id>]
```

### Format Specification & Regex
```regexp
^([-a-z0-9]{3,8}):([-_a-zA-Z0-9]{1,32})\/([-a-z0-9]{3,8}):(0x[0-9a-fA-F]{40}|[-_a-zA-Z0-9]{1,64})(?:\/([-_a-zA-Z0-9]{1,78}))?$
```

### Examples
- **Robinhood Chain ERC-721 Token (e.g., MARKS Mark #123)**:
  `eip155:4663/erc721:0xdd084caa7973fa07b71c7247236738786e04057a/123`
- **Sepolia Testnet ERC-721 Token (e.g., HoodQuest Outlaw #42)**:
  `eip155:11155111/erc721:0xF75323518df7Ce90637e2b93cFd7f7d0627cc205/42`
- **ERC-20 Fungible Asset**:
  `eip155:1/erc20:0x6b175474e89094c44da98b954eedeac495271d0f`

---

## 5. Resource Bounds & Fail-Closed Sanitization

To guarantee denial-of-service resilience and prevent memory or parser exploits:
1. **Maximum Payload Size**: The JSON-serialized Launch Context string must **NOT exceed 1,024 bytes** (`MAX_LAUNCH_CONTEXT_BYTES = 1024`).
2. **Maximum Structure Depth**: Maximum nesting depth is 2 levels. Arrays, symbols, functions, and non-plain objects are strictly rejected.
3. **Fail-Closed Sanitization Policy**:
   - If Launch Context is absent (`null` or `undefined`), the host omits `launchContext` from the handshake acknowledgment, and the cartridge boots to its default landing route.
   - If Launch Context is malformed, oversized, or fails schema validation, the host drops it, logs a warning, and omits `launchContext` from the handshake. A malformed launch context never crashes the host or halts execution.
4. **Immutable Initial State**: Launch Context is delivered strictly during the handshake acknowledgment. It is immutable for the duration of the cartridge session; no mutable post-boot context events are supported in V1.

---

## 6. Transport Wire Protocol

The Console Host communicates Launch Context to the sandboxed cartridge inside the `cartridge:handshake:ack` frame sent over the window bridge when establishing the `MessagePort`:

```javascript
// Window message from Host -> Cartridge
{
  type: 'cartridge:handshake:ack',
  nonce: 'hs_3f8a9e...',
  capabilities: { ... },
  launchContext: {
    version: '1',
    resource: 'eip155:4663/erc721:0xdd084caa7973fa07b71c7247236738786e04057a/123',
    route: 'detail'
  }
}
```

### Cartridge Runtime Consumption
Inside the cartridge, the runtime client exposes the launch context via:
```javascript
const context = CartridgeHost.getLaunchContext();
if (context && context.resource) {
  // Parse CAIP-19 asset and render detail view
} else {
  // Render default landing view
}
```

---

## 7. Backward Compatibility

1. **Legacy Cartridges**: Cartridges built prior to Launch Context V1 completely ignore `launchContext` in the handshake acknowledgment and boot normally.
2. **Missing Context**: When launched without URL parameters or host context inputs, `launchContext` is omitted, preserving default execution.
3. **Cross-Cartridge Genericity**: The schema is 100% agnostic of game or application specifics. It works identically for HoodQuest Outlaw characters, MARKS Arrows, TARGETS Targets, or any generic EVM asset.

# Console Runtime V0.1 Specification (Hardened)

## 1. Overview & Trust Model

**Console Runtime V0.1** defines the execution environment, host capabilities, and security boundary between an on-chain/web application (a *Cartridge*) and the platform hosting it (the *Console* or *Host*).

### Strict Trust Model
* **Cartridges are untrusted**: A cartridge may be buggy, hijacked, or authored by an adversary.
* **Hosts may be compromised or third-party**: Cartridges must not trust unauthenticated host messages.
* **Wallets / Providers are external security boundaries**: Raw provider objects (`window.ethereum`) must **never** be injected directly into untrusted cartridge contexts.
* **Application smart contracts are the final authority**: Contracts enforce ownership, invariants, and authorization independently of any frontend or runtime assumption.

```text
┌─────────────────────────────────────────────────────────────────┐
│                       CONSOLE RUNTIME                           │
│   • Granular Policy (Chain + Target + Selector + Value)         │
│   • Elevated Asset Operation Firewall (Approvals / Transfers)   │
│   • Chain & Account Lifecycle Invalidation                      │
│   • Resource Limits (DoS, Concurrency, Rate Limiting)           │
│   • Isolated MessagePort Transport Boundary                     │
└──────────────────────────────┬──────────────────────────────────┘
                               │ targets
┌──────────────────────────────▼──────────────────────────────────┐
│                      CARTRIDGE STANDARD                         │
│   • cartridge.json manifest         • Lifecycle hooks           │
│   • Requested capabilities          • Requested permissions     │
│   • Chain & runtime requirements    • Standard entrypoint       │
└──────────────────────────────┬──────────────────────────────────┘
                               │ instantiates
┌──────────────────────────────▼──────────────────────────────────┐
│                     APPLICATION LAYER                           │
│   • Cartridge #0001: HoodQuest (Diorama, Camp, Vault Heist)     │
│   • Cartridge #0002: Runtime Test Cartridge                     │
│   • Cartridge #0003: Adversarial Test Fixture                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Formal Runtime API Specification

The developer-facing runtime client is exposed globally as `window.CartridgeHost` (and aliased to `window.HoodQuestHost` for backward compatibility).

### Public Methods

#### `getAddress()`
- **Signature**: `CartridgeHost.getAddress(): string | null`
- **Description**: Returns active connected EVM address or `null` if disconnected.

#### `getChainId()`
- **Signature**: `CartridgeHost.getChainId(): number | null`
- **Description**: Returns active EVM chain ID (e.g. `11155111` for Sepolia) or `null` if uninitialized.

#### `getCapabilities()`
- **Signature**: `CartridgeHost.getCapabilities(): RuntimeCapabilities`
- **Description**: Returns current capability state of the active environment.
- **Return Type**:
  ```typescript
  interface RuntimeCapabilities {
    adapter: 'direct' | 'bridge';
    wallet: {
      supported: boolean;     // Environment is capable of signing
      connected: boolean;     // Wallet is currently connected
      address: string | null; // Primary connected address
      providerName: string;   // Provider brand or host shell identifier
    };
    evm: {
      chainId: number | null; // Active chain ID
      read: { supported: boolean; available: boolean };
      write: { supported: boolean; available: boolean; authorized: boolean };
    };
    environment: {
      isSandboxed: boolean;
      hasHostBridge: boolean;
      openExternalApp: boolean;
      canonicalAppUrl: string;
    };
    // Compatibility flat aliases
    signing: boolean;
    contractRead: boolean;
    contractWrite: boolean;
    isSandboxed: boolean;
    canonicalAppUrl: string;
  }
  ```

#### `requestAccounts()`
- **Signature**: `CartridgeHost.requestAccounts(): Promise<string[]>`
- **Description**: Requests user authorization and accounts from the host provider.
- **Errors**: `4001` (User Rejected), `4100` (Unauthorized).

#### `connect(options)`
- **Signature**: `CartridgeHost.connect(options?: object): Promise<string | null>`
- **Description**: Initiates a wallet connection workflow. Returns primary address upon approval.

#### `disconnect()`
- **Signature**: `CartridgeHost.disconnect(): Promise<void>`
- **Description**: Terminates active wallet session, immediately clearing address and revoking write capability.

#### `readContract(params)`
- **Signature**: `CartridgeHost.readContract(params: { to: string; data: string }): Promise<string>`
- **Description**: Performs an EVM `eth_call` contract read.

#### `writeContract(params)`
- **Signature**: `CartridgeHost.writeContract(params: { to: string; data: string; gas?: string; value?: string }): Promise<string>`
- **Description**: Requests submission of an on-chain transaction. Performs immediate pre-dispatch validation of active account and chainId.
- **Security Rejections**:
  - `4001`: User Rejected Request.
  - `4003`: Policy Violation (Target Not Allowed, Selector Not Allowed, Elevated Operation Blocked, Native Value Forbidden).
  - `4100`: Unauthorized (Wallet disconnected or stale authorization).
  - `4901`: Active Chain Mismatch.
  - `-32000`: Request Timeout.
  - `-32005`: Rate / Concurrency Limit Exceeded.
  - `-32600`: Payload Size Exceeded or Duplicate Request ID.

#### `waitForReceipt(txHash, maxAttempts)`
- **Signature**: `CartridgeHost.waitForReceipt(txHash: string, maxAttempts?: number): Promise<TransactionReceipt | null>`
- **Description**: Polls the host or public RPC until transaction confirmation is mined.

#### `on(event, handler)` / `removeListener(event, handler)`
- **Supported Events**:
  - `'accountsChanged'`: Fired with `address: string | null` when user account changes or disconnects.
  - `'chainChanged'`: Fired with `chainId: number` when network changes.
  - `'capabilitiesChanged'`: Fired with `RuntimeCapabilities` when capabilities update.
  - `'adapterChanged'`: Fired with `adapterName: string` when transport transitions.

---

## 3. Granular Permission Policy & Elevated Operations

Instead of naive target-address allowlisting, Console Runtime V0.1 enforces a 4-tuple security policy on every write:

$$\text{Policy Check} = (\text{chainId}, \text{target address}, \text{function selector}, \text{native value})$$

### Policy Rule Structure
```typescript
interface GrantedContractPolicy {
  address: string;             // Normalized 0x address
  name?: string;               // Descriptive label
  chainId?: string;            // Canonical EIP-1193 hex string (e.g. '0xaa36a7')
  writes: boolean;             // Explicit write permission required
  allowedSelectors?: string[]; // Allowed 4-byte selectors (e.g. ['0x12345678'])
  allowNativeValue?: boolean;  // False by default
  maxValueWei?: string;        // Maximum allowed msg.value in wei (native currency)
  isElevated?: boolean;        // False by default
  argumentConstraints?: PositionalConstraint[]; // Generic ABI-position constraints
}

interface PositionalConstraint {
  selector?: string;           // Optional selector filter (e.g. '0xa9059cbb')
  index: number;               // 0-based 32-byte ABI word index in calldata
  type: 'address' | 'uint256' | 'bool' | 'bytes32';
  op: 'eq' | 'in' | 'lte' | 'gte';
  value: any;                  // Expected value or array of values (unit-neutral token amounts)
  label?: string;
}
```

### Elevated Asset Operation Firewall
Approval and transfer methods are recognized by standard 4-byte signatures and treated as **elevated operations**:
- `0xa22cb465`: `setApprovalForAll(address,bool)`
- `0x095ea7b3`: `approve(address,uint256)`
- `0x23b872dd`: `transferFrom(address,address,uint256)`
- `0x42842e0e`: `safeTransferFrom(address,address,uint256)`
- `0xb88d4fde`: `safeTransferFrom(address,address,uint256,bytes)`
- `0xf242432a`: `safeTransferFrom(address,address,uint256,uint256,bytes)`
- `0x2eb2c2d6`: `safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)`
- `0xa9059cbb`: `transfer(address,uint256)`
- `0xd505accf`: `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)` [EIP-2612]
- `0x745a41bc`: `permit(address,uint256,uint256,bytes)` [Canonical ERC-4494]
- `0x7ac2ff7b`: `permit(address,uint256,uint256,uint8,bytes32,bytes32)` [Nonstandard packed RSV variant]

> [!CAUTION]
> Ordinary contract write permissions **never** grant elevated selectors. Even if an allowed contract is HoodQuest Outlaws or Loot, any approval or transfer call is rejected with code `4003` unless the host explicitly grants elevated permissions after dedicated user consent.

### Canonical Calldata Argument Indexing & Positional Constraints
Argument constraints avoid selector-based heuristics by strictly adhering to canonical 32-byte ABI word positions:
- `transfer(address,uint256)`: `recipient` = Word 0, `amount` = Word 1.
- `transferFrom(address,address,uint256)`: `from` = Word 0, `recipient` = Word 1, `amount`/`tokenId` = Word 2.
- `approve(address,uint256)`: `spender` = Word 0, `amount`/`tokenId` = Word 1.
- `setApprovalForAll(address,bool)`: `operator` = Word 0, `approved` = Word 1.
- `safeTransferFrom(address,address,uint256)`: `from` = Word 0, `to` = Word 1, `tokenId` = Word 2.
- `safeTransferFrom(address,address,uint256,uint256,bytes)`: `from` = Word 0, `to` = Word 1, `id` = Word 2, `value` = Word 3, `dataOffset` = Word 4.

Token amount limits are expressed as unit-neutral typed constraints (`uint256`, `lte`) at their respective word index, while native ETH transfer policies remain denominated in wei (`maxValueWei`).

---

## 4. Chain Lifecycle & Invalidation Behavior

1. **State Invalidation**: When `chainChanged` or `accountsChanged` occurs:
   - All pending write authorisations are immediately invalidated.
   - Capabilities are recalculated and broadcast to the cartridge.
   - Granted permissions are re-evaluated against the new chain context.
2. **Pre-Dispatch Validation**: In `writeContract`, the client verifies that `activeAccount` is non-null and that `activeChainId` matches before transmitting the request.
3. **Host Verification**: The host re-verifies that `params.chainId === host.currentChainId` immediately prior to submitting the transaction to the signer.

---

## 5. Bridge Security, Sandbox Requirements & Manifest Trust

### Minimum Iframe Sandbox
Untrusted cartridges must be embedded using:
```html
<iframe src="cartridge.html" sandbox="allow-scripts allow-forms allow-popups"></iframe>
```
* **Omission of `allow-same-origin`**: Forces the cartridge iframe to receive an opaque `null` origin. This guarantees that:
  - The cartridge cannot access `window.parent` DOM or JavaScript context.
  - The cartridge cannot read host cookies, `localStorage`, or `sessionStorage`.
  - The cartridge cannot directly access `window.parent.ethereum` or raw injected wallets.

### Handshake & MessagePort Isolation
1. **Cryptographic Nonce**: Handshake initiation generates an unpredictable high-entropy nonce (`hs_[crypto-random]`).
2. **Source Window Verification**: Host validates `event.source === iframe.contentWindow`.
3. **MessagePort Lockdown**: Once the `MessagePort` channel is established:
   - All privileged RPC traffic is routed strictly through the isolated `MessagePort`.
   - Any message arriving over global `window.postMessage` is dropped.
   - Any second handshake attempt is rejected (`handshakeEstablished: true`).

### Manifest Trust Requirement & Registry Anchor Invariant
A production third-party release must anchor an immutable manifest hash in a trusted registry (such as an on-chain Cartridge Registry contract). The verified manifest then anchors the cartridge package content hash and exact dependency hashes. 

Without this immutable registry anchor, an attacker controlling the delivery channel could replace both the package and the manifest together, defeating content hash verification.

---

## 6. Resource Limits & DoS Protection

| Resource | Limit | Violation Action | Error Code |
| :--- | :--- | :--- | :--- |
| **Max Payload Size** | 65,536 bytes (64 KB) | Request rejected before processing | `-32600` |
| **Max Concurrent Requests** | 10 in-flight | Queuing rejected | `-32005` |
| **Request Rate Limit** | 25 requests / sec | Rate limit exceeded | `-32005` |
| **Request Timeout** | 15s (read) / 60s (write) | Cancelled and rejected | `-32000` |
| **Duplicate Request ID** | Unique per session | Replay rejected | `-32600` |

---

## 7. Standardized Error Codes

### Standard EIP-1193 Errors
* `4001`: `UserRejectedRequest` (user cancelled signature or dismissed prompt)
* `4100`: `Unauthorized` (wallet disconnected or stale authorization state)
* `4200`: `UnsupportedMethod` (unrecognized or unsupported RPC method)
* `4900`: `Disconnected` (The provider is disconnected from all chains)
* `4901`: `ChainDisconnected` (The provider is disconnected from the specified chain)

### Console Runtime Specific Errors
* `4003`: `PolicyViolation` (all host policy rejections: target not allowed, selector not allowed, elevated op blocked, argument constraint violation, native value forbidden, host active chain mismatch)
* `5001`: `CapabilityNotGranted` (cartridge invoked ungranted capability)
* `5002`: `RuntimeVersionMismatch` (cartridge requires incompatible runtime)
* `5003`: `PackageIntegrityMismatch` (cartridge package hash failed verification)
* `-32000`: `RequestTimeout` (request timed out)
* `-32001`: `TransportUnavailable` (MessagePort / bridge disconnected)
* `-32005`: `LimitExceeded` (rate limit or concurrency limit exceeded)
* `-32600`: `InvalidRequest` (payload too large or duplicate request ID)
* `-32602`: `InvalidParams` (missing or malformed parameters)
* `-32603`: `InternalHostError` (unhandled host exception)

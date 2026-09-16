# Security Model & Threat Assessment

**Status**: Hardened Security Baseline  
**Layers Analyzed**: Cartridge Sandbox, Host Bridge Firewall, Provider Abstraction, On-chain Contracts  

---

## 1. Trust Assumptions

The Console Runtime architecture is built upon zero-implicit-trust principles:

1. **Cartridges are Untrusted**:
   Cartridge code is treated as potentially adversarial or vulnerable. It must NEVER have direct access to private keys, parent window DOM, parent cookies, local storage, or unvetted external network sockets.
2. **Hosts May Be Compromised or Third-Party**:
   Cartridges should not rely on hosts to execute game logic honestly. Smart contracts on-chain are the ultimate source of truth for assets, state transitions, and inventories.
3. **Wallets & Providers are External Security Boundaries**:
   User approval prompts and transaction simulations occur in the wallet layer, but the host acts as an active firewall preventing malicious transactions from even reaching the user prompt.
4. **Smart Contracts are Authoritative**:
   All state updates and asset ownership changes are validated on EVM consensus rules.

---

## 2. Multi-Layer Defense Architecture

```
[ UNTRUSTED CARTRIDGE ]
         │
         ▼
[ LAYER 1: Minimal Sandbox Iframe ]
   - sandbox="allow-scripts"
   - No 'allow-same-origin' (opaque null origin)
   - Zero access to parent window, storage, or window.ethereum
         │
         ▼
[ LAYER 2: Isolated MessageChannel Bridge ]
   - Nonce-authenticated handshake
   - Per-request timeout & reply matching
   - Replay protection & rate limiting
         │
         ▼
[ LAYER 3: Host PolicyEngine Firewall ]
   - Strict chain ID matching
   - Contract allowlist
   - Explicit 4-byte selector verification (unknown selectors fail closed)
   - Native value clamps
   - Elevated asset operation defense-in-depth (ERC-20/721/1155 approval/transfer guards)
         │
         ▼
[ LAYER 4: EIP-1193 Web3 Provider / Signer ]
   - User wallet approval UI
```

---

## 3. Threat Vectors & Mitigations

### 3.1 Unvetted Payload Execution (Malicious Code Injection)
- **Threat**: Attacker tampers with cartridge payload in transit or storage.
- **Mitigation**: **Integrity Verification Before Execution**. `CartridgeLoader` computes `keccak256(packageBytes)` and compares against the manifest's declared hash before mounting the iframe. If hashes mismatch, execution immediately halts (error code `5003`).

### 3.2 Indiscriminate Function Calls (`CALL *`)
- **Threat**: Cartridge attempts to call dangerous functions on an authorized contract (e.g. `setApprovalForAll`, `upgradeTo`, `destroy`).
- **Mitigation**: **Explicit Selector Requirement**. Rules omitting `allowedSelectors` or passing empty arrays fail closed with error code `4003`. Wildcard execution is strictly prohibited on write contracts.

### 3.3 Unauthorized Asset Exfiltration (Approval Drainers)
- **Threat**: Cartridge attempts to trick user into approving tokens to an attacker address.
- **Mitigation**: **Elevated Operation Firewall**. The runtime maintains an authoritative mathematical table of all canonical ERC-20, ERC-721, ERC-1155, and Permit selectors. Standard write rules cannot execute these methods unless explicitly flagged `isElevated: true` with strict positional argument constraints (`allowedSpenders`, `allowedRecipients`, `maxAmount`).

### 3.4 Cross-Origin Privilege Escalation
- **Threat**: Cartridge attempts to break out of iframe and read parent window context.
- **Mitigation**: The iframe sandbox attribute strictly omits `allow-same-origin`. The browser assigns a unique opaque origin (`null`), blocking DOM access, parent cookies, and credentialed requests.

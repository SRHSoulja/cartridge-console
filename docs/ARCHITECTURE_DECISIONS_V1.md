# Console Protocol & Cartridge Architecture Decisions (V1)

This document records the foundational product, ownership, and protocol boundaries established for the Console Platform and Cartridge ecosystem.

---

## 1. Permissionless Protocol Invariant

* **Open Infrastructure**: The Console Protocol is permissionless public infrastructure.
* **No Mandatory Hardware/Console Token**: End users never need to mint, purchase, or hold a "Console NFT" in order to execute compatible cartridges.
* **No Mandatory Cartridge License Token**: End users never need to mint or hold a "Cartridge NFT" merely to run a compatible cartridge. Execution rights are fundamentally open.

---

## 2. Software Releases vs. Application Entitlements

* **Software, Not Licenses**: A Cartridge is a canonical, immutable software/application release, not a user DRM license token.
* **Application-Level Authority**: Individual applications and games determine what entitlements, tokens, or ownership records matter within their internal mechanics.
  * For example, an on-chain RPG application may require ownership of its native companion or character NFTs to unlock in-game progression.
  * These mechanics are owned and enforced by the application's native smart contracts, never by mandatory platform-level gatekeeping.

---

## 3. Canonical Identity & Publishing Authority

* **Cartridge Identity**: Canonical cartridge identity is defined strictly on-chain by the [`CartridgeRegistry`](../src/protocol/CartridgeRegistry.sol) contract via a 256-bit domain-separated identifier (`cartridgeId = keccak256(abi.encode(DOMAIN, publisher, salt))`).
* **Publishing Authority**: Publishing authority is governed strictly by the cartridge owner address within `CartridgeRegistry`, secured with 2-step ownership transfers.
* **Optional Future Portals**: Future Console NFTs or Cartridge NFTs may exist as canonical collectors' artifacts, portals, or curation tokens, but they must **never** define protocol identity, publishing authority, or mandatory runtime execution rights.

---

## 4. Verification and Curation as an Independent Layer

* **Decoupled Verification**: Software verification, safety certification, and community curation operate strictly as an independent layer atop registration.
* **Permissionless Substrate / Curated Experience**: Official host portals or directory clients may curate, review, and highlight verified software releases, while the underlying smart contracts and protocol remain open and permissionless for any developer.

---

## 5. Token-Context and Deep-Linking (Deferred Scope)

* Future token-context launching (e.g. launching a cartridge directly scoped to a specific NFT ID or vault session) is an architectural extension planned for future phases, but is intentionally deferred from the present V0.2 correctness baseline.

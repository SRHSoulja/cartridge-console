# Cartridge V0 Developer Template

This template provides the starter skeleton for creating an on-chain or web Cartridge targeting **Console Runtime V0**.

## Project Structure
```text
.
├── cartridge.json     # Manifest declaring identity, requirements, and permissions
├── src/
│   ├── index.html     # Application entrypoint
│   └── main.js        # Application logic consuming CartridgeHost
├── runtime/           # Standard Console Runtime V0 client module
├── assets/            # Static artwork, audio, or metadata
└── tests/             # Automated test suite
```

## Consuming the Runtime API
Developers never need to manage MetaMask, WalletConnect, or iframe message mechanics. Simply call the standard `CartridgeHost` methods:

```js
const { CartridgeHost } = window;

// 1. Inspect environment capabilities
const caps = CartridgeHost.getCapabilities();

// 2. Connect wallet (delegated to host shell or direct injected provider)
const address = await CartridgeHost.connect();

// 3. Perform contract reads
const result = await CartridgeHost.readContract({
  to: '0x...',
  data: '0x...'
});

// 4. Perform contract writes (permission checked at host boundary)
const txHash = await CartridgeHost.writeContract({
  to: '0x...',
  data: '0x...'
});
```

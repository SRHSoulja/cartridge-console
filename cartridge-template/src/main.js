/**
 * Sample Cartridge Application Entrypoint
 * Demonstrates consuming the standard Console Runtime V0 API.
 */

// Cartridge developer uses only the generic CartridgeHost interface:
const { CartridgeHost } = window;

async function initCartridge() {
  console.log(`🎮 Initializing Cartridge against Console Runtime v${CartridgeHost.version || '0.1.0'}`);

  // 1. Inspect current environment capabilities
  const caps = CartridgeHost.getCapabilities();
  console.log('Detected capabilities:', caps);

  // 2. React to host events
  CartridgeHost.on('accountsChanged', (newAddress) => {
    console.log('Host wallet account changed:', newAddress);
  });

  CartridgeHost.on('capabilitiesChanged', (newCaps) => {
    console.log('Host capabilities updated:', newCaps);
  });

  // 3. Negotiate handshake if running embedded inside a Console Host
  CartridgeHost.initCartridgeHostNegotiation({
    id: 'my-sample-cartridge',
    onAttached: (bridge) => {
      console.log('Attached to host bridge!');
    }
  });
}

window.addEventListener('DOMContentLoaded', initCartridge);

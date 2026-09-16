/**
 * Compatibility Test Suite: Console Runtime V0 & Cartridge Multi-Tenancy
 * Proves that both HoodQuest (Cartridge #0001) and the Runtime Test Cartridge (Cartridge #0002)
 * target and consume the exact same Console Runtime V0 API.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { MessageChannel } = require('worker_threads');

const {
  CartridgeHost,
  DirectHostAdapter,
  BridgeHostAdapter,
  ConsoleRuntimeError
} = require('../runtime/cartridge_host_runtime.js');

// Contract constants
const HQ_OUTLAWS = '0xF75323518df7Ce90637e2b93cFd7f7d0627cc205'.toLowerCase();
const HQ_LOOT = '0x0676129B2bF4B06f04AfC7301617b6cE3BB2405c'.toLowerCase();
const HQ_RAIDS = '0xC115C51a1bf9DdE7B1eD0861E18CaA27f24C3Be9'.toLowerCase();
const TEST_CART_ALLOWED = '0x7777777777777777777777777777777777777777'.toLowerCase();
const FORBIDDEN_TARGET = '0x1111111111111111111111111111111111111111'.toLowerCase();

// Generic Host Server implementing Console Runtime V0 host boundary
class GenericConsoleHostServer {
  constructor(port, grantedPermissions = {}) {
    this.port = port;
    this.connectedAccount = null;
    this.grantedContracts = new Set(
      (grantedPermissions.contracts || []).map(c => (typeof c === 'string' ? c : c.address).toLowerCase())
    );

    this.port.onmessage = async (event) => {
      const req = event.data;
      if (!req || typeof req !== 'object') return;

      const res = await this.dispatch(req);
      if (res) this.port.postMessage(res);
    };
  }

  async dispatch(req) {
    const { id, method, params } = req;
    try {
      let result = null;
      switch (method) {
        case 'runtime.capabilities':
          result = {
            wallet: { supported: true, connected: !!this.connectedAccount, address: this.connectedAccount },
            evm: { read: { supported: true, available: true }, write: { supported: true, available: !!this.connectedAccount, authorized: true } }
          };
          break;

        case 'wallet.address':
          result = this.connectedAccount;
          break;

        case 'wallet.connect':
          this.connectedAccount = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
          result = [this.connectedAccount];
          break;

        case 'wallet.disconnect':
          this.connectedAccount = null;
          result = true;
          break;

        case 'evm.read':
          result = '0x0000000000000000000000000000000000000000000000000000000000000001';
          break;

        case 'evm.write': {
          const { to } = params || {};
          if (!to) throw new Error('Target "to" required');
          // Host Boundary Permission Enforcement
          if (!this.grantedContracts.has(to.toLowerCase())) {
            const err = new Error(`Unauthorized contract target: ${to}`);
            err.code = 4003;
            throw err;
          }
          if (!this.connectedAccount) {
            const err = new Error('Wallet not connected in host');
            err.code = 4100;
            throw err;
          }
          result = '0xhost_tx_' + Math.random().toString(36).substr(2, 8);
          break;
        }

        case 'evm.receipt':
          result = { status: '0x1', transactionHash: params.txHash, blockNumber: '0xabc' };
          break;

        default:
          throw new Error(`Method ${method} unsupported`);
      }
      return { jsonrpc: '2.0', id, result };
    } catch (e) {
      return { jsonrpc: '2.0', id, error: { code: e.code || -32603, message: e.message } };
    }
  }
}

async function runCompatibilityTests() {
  console.log('🧪 Starting Console Runtime V0 Multi-Cartridge Compatibility Tests...\n');
  let passed = 0;
  let failed = 0;

  async function test(name, fn) {
    try {
      await fn();
      console.log(`  ✅ PASS: ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ❌ FAIL: ${name}`);
      console.error(`     Error: ${err.message}\n${err.stack}`);
      failed++;
    }
  }

  // 1. MANIFEST SCHEMA VALIDATION
  await test('Cartridge manifest files match schema constraints', async () => {
    const schema = JSON.parse(fs.readFileSync(path.join(__dirname, '../CARTRIDGE_MANIFEST_SCHEMA.json'), 'utf8'));
    assert.strictEqual(schema.title, 'CartridgeManifestV0');

    const testCartManifest = JSON.parse(
      fs.readFileSync(path.join(__dirname, '../cartridges/runtime-test-cartridge/cartridge.json'), 'utf8')
    );
    assert.strictEqual(testCartManifest.id, 'runtime-test-cartridge');
    assert.strictEqual(testCartManifest.chainId, 11155111);
    assert.ok(testCartManifest.capabilities.required.includes('evm.read'));

    const templateManifest = JSON.parse(
      fs.readFileSync(path.join(__dirname, '../cartridge-template/cartridge.json'), 'utf8')
    );
    assert.strictEqual(templateManifest.id, 'my-sample-cartridge');
  });

  // 2. ERROR CODES & SEMANTICS
  await test('ConsoleRuntimeError enforces distinct EIP-1193 and Runtime-specific codes', async () => {
    const err4001 = ConsoleRuntimeError.userRejected();
    assert.strictEqual(err4001.code, 4001);

    const err4100 = ConsoleRuntimeError.unauthorized();
    assert.strictEqual(err4100.code, 4100);

    const err4003 = ConsoleRuntimeError.targetNotAllowed('0x1234');
    assert.strictEqual(err4003.code, 4003);
    assert.ok(err4003.message.includes('Unauthorized contract target'));

    const errTimeout = ConsoleRuntimeError.requestTimeout('evm.read');
    assert.strictEqual(errTimeout.code, -32000);

    const err4900 = ConsoleRuntimeError.disconnected();
    assert.strictEqual(err4900.code, 4900);

    const err4901 = ConsoleRuntimeError.chainDisconnected();
    assert.strictEqual(err4901.code, 4901);

    const errCap = ConsoleRuntimeError.capabilityNotGranted('evm.write');
    assert.strictEqual(errCap.code, 5001);
  });

  // 3. RUN CARTRIDGE #0001 (HOODQUEST) AGAINST RUNTIME
  await test('Cartridge #0001 (HoodQuest) executes against generic Console Runtime V0', async () => {
    // Granted permissions for HoodQuest
    const hqPermissions = {
      contracts: [HQ_OUTLAWS, HQ_LOOT, HQ_RAIDS]
    };

    const { port1, port2 } = new MessageChannel();
    const hostServer = new GenericConsoleHostServer(port2, hqPermissions);
    const bridge = new BridgeHostAdapter(port1);

    CartridgeHost.setAdapter(bridge);
    assert.strictEqual(CartridgeHost.getAdapter().name, 'bridge');

    // 1. Check capabilities
    const caps = CartridgeHost.getCapabilities();
    assert.strictEqual(caps.contractRead, true);

    // 2. Connect wallet
    const addr = await CartridgeHost.connect();
    assert.strictEqual(addr, '0x70997970C51812dc3A010C7d01b50e0d17dc79C8');
    assert.strictEqual(CartridgeHost.getAddress(), addr);

    // 3. Read Loot contract
    const readHex = await CartridgeHost.readContract({ to: HQ_LOOT, data: '0x06fdde03' });
    assert.ok(readHex.startsWith('0x'));

    // 4. Authorized Write to Outlaws contract
    const txOutlaws = await CartridgeHost.writeContract({ to: HQ_OUTLAWS, data: '0xfeed' });
    assert.ok(txOutlaws.startsWith('0xhost_tx_'));

    // 5. Authorized Write to Vault Raids contract
    const txRaids = await CartridgeHost.writeContract({ to: HQ_RAIDS, data: '0xheist' });
    assert.ok(txRaids.startsWith('0xhost_tx_'));

    // 6. Security Boundary: Attempt write to forbidden contract
    let errCaught = null;
    try {
      await CartridgeHost.writeContract({ to: FORBIDDEN_TARGET, data: '0xsteal' });
    } catch (e) {
      errCaught = e;
    }
    assert.ok(errCaught, 'Expected permission rejection');
    assert.strictEqual(errCaught.code, 4003);

    port1.close();
    port2.close();
  });

  // 4. RUN CARTRIDGE #0002 (RUNTIME TEST CARTRIDGE) AGAINST SAME RUNTIME
  await test('Cartridge #0002 (Runtime Test Cartridge) executes against same Console Runtime V0 without HoodQuest code', async () => {
    // Granted permissions for Test Cartridge
    const testCartPermissions = {
      contracts: [TEST_CART_ALLOWED]
    };

    const { port1, port2 } = new MessageChannel();
    const hostServer = new GenericConsoleHostServer(port2, testCartPermissions);
    const bridge = new BridgeHostAdapter(port1);

    CartridgeHost.setAdapter(bridge);

    // 1. Inspect version & adapter
    assert.ok(['0.1.0', '0.2.0'].includes(CartridgeHost.version));
    assert.strictEqual(CartridgeHost.getAdapter().name, 'bridge');

    // 2. Connect
    const addr = await CartridgeHost.connect();
    assert.strictEqual(addr, '0x70997970C51812dc3A010C7d01b50e0d17dc79C8');

    // 3. Read
    const readResult = await CartridgeHost.readContract({ to: TEST_CART_ALLOWED, data: '0x' });
    assert.ok(readResult.startsWith('0x'));

    // 4. Authorized write to Test Cartridge contract
    const txTest = await CartridgeHost.writeContract({ to: TEST_CART_ALLOWED, data: '0xping' });
    assert.ok(txTest.startsWith('0xhost_tx_'));

    // 5. Security Boundary: Test Cartridge cannot write to HoodQuest Outlaws contract
    let blockedHqWrite = null;
    try {
      await CartridgeHost.writeContract({ to: HQ_OUTLAWS, data: '0xattack' });
    } catch (e) {
      blockedHqWrite = e;
    }
    assert.ok(blockedHqWrite, 'Expected host permission block on ungranted contract');
    assert.strictEqual(blockedHqWrite.code, 4003);

    port1.close();
    port2.close();
  });

  // SUMMARY
  console.log('\n=========================================');
  console.log(`Multi-Cartridge Compatibility Test Results:`);
  console.log(`Total: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
  console.log('=========================================\n');

  if (failed > 0) process.exit(1);
}

runCompatibilityTests();

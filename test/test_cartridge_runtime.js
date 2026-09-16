/**
 * Automated Test Suite for Cartridge Host Runtime V0
 * Verifies: Direct adapter, Bridge adapter, Host handshake, Boundary security,
 * Permission enforcement (allowlist 4003), Timeout, and Event dispatching.
 */

const assert = require('assert');

// Contract constants
const ALLOWED_OUTLAWS = '0xF75323518df7Ce90637e2b93cFd7f7d0627cc205'.toLowerCase();
const ALLOWED_LOOT = '0x0676129B2bF4B06f04AfC7301617b6cE3BB2405c'.toLowerCase();
const ALLOWED_RAIDS = '0xC115C51a1bf9DdE7B1eD0861E18CaA27f24C3Be9'.toLowerCase();
const FORBIDDEN_CONTRACT = '0x1111111111111111111111111111111111111111'.toLowerCase();

const CANONICAL_APP_URL = 'https://srhsoulja.github.io/hoodquest/';

// Simulated Environment Setup
function createMockEnvironment() {
  let connectedUserAddress = null;
  let activeWalletName = null;

  class DirectHostAdapter {
    constructor() {
      this.name = 'direct';
      this.isSandboxed = false;
    }

    getAddress() {
      return connectedUserAddress || null;
    }

    getCapabilities() {
      const isConn = !!connectedUserAddress;
      return {
        adapter: 'direct',
        wallet: {
          supported: true,
          connected: isConn,
          address: connectedUserAddress || null,
          providerName: activeWalletName || 'None'
        },
        evm: {
          read: { supported: true, available: true },
          write: { supported: true, available: isConn, authorized: true }
        },
        environment: {
          isSandboxed: this.isSandboxed,
          hasHostBridge: false,
          openExternalApp: this.isSandboxed && !isConn,
          canonicalAppUrl: CANONICAL_APP_URL
        },
        signing: isConn,
        contractRead: true,
        contractWrite: isConn,
        openExternalApp: this.isSandboxed && !isConn,
        isSandboxed: this.isSandboxed,
        providerName: activeWalletName || 'None',
        canonicalAppUrl: CANONICAL_APP_URL
      };
    }

    async requestAccounts() {
      if (!connectedUserAddress) throw new Error('No direct injected provider available');
      return [connectedUserAddress];
    }

    async connect(options = {}) {
      if (options.mockAddress) {
        connectedUserAddress = options.mockAddress;
        activeWalletName = 'MockInjected';
        CartridgeHost._emit('accountsChanged', connectedUserAddress);
        CartridgeHost._emit('capabilitiesChanged', this.getCapabilities());
        return connectedUserAddress;
      }
      throw new Error('No injected provider');
    }

    async disconnect() {
      connectedUserAddress = null;
      activeWalletName = null;
      CartridgeHost._emit('accountsChanged', null);
      CartridgeHost._emit('capabilitiesChanged', this.getCapabilities());
    }

    async readContract({ to, data }) {
      return '0x0000000000000000000000000000000000000000000000000000000000000001';
    }

    async writeContract({ to, data, gas = '0x55730', value = '0x0' }) {
      if (!connectedUserAddress) throw new Error('No wallet connected');
      return '0xdirect_tx_hash_' + Math.random().toString(36).substr(2, 8);
    }

    async waitForReceipt(txHash, maxAttempts = 15) {
      return { status: '0x1', transactionHash: txHash, blockNumber: '0x100' };
    }
  }

  class BridgeHostAdapter {
    constructor(port, initialCapabilities) {
      this.name = 'bridge';
      this.port = port || null;
      this.caps = initialCapabilities || {
        adapter: 'bridge',
        wallet: { supported: true, connected: false, address: null, providerName: 'Cartridge Host' },
        evm: {
          read: { supported: true, available: true },
          write: { supported: true, available: false, authorized: true }
        },
        environment: { isSandboxed: true, hasHostBridge: true, openExternalApp: false, canonicalAppUrl: CANONICAL_APP_URL },
        signing: false,
        contractRead: true,
        contractWrite: false,
        openExternalApp: false,
        isSandboxed: true,
        providerName: 'Cartridge Host',
        canonicalAppUrl: CANONICAL_APP_URL
      };
      this.pendingRequests = new Map();
      this.setupMessageListener();
    }

    setupMessageListener() {
      const handleMsg = (event) => {
        const data = event.data;
        if (!data || typeof data !== 'object') return;

        // Correlated response resolution
        if (data.id && this.pendingRequests.has(data.id)) {
          const pending = this.pendingRequests.get(data.id);
          clearTimeout(pending.timer);
          this.pendingRequests.delete(data.id);
          if (data.error || data.success === false) {
            const errObj = data.error || {};
            const err = new Error(typeof errObj === 'string' ? errObj : (errObj.message || 'Host bridge error'));
            if (errObj.code) err.code = errObj.code;
            pending.reject(err);
          } else {
            pending.resolve(data.result);
          }
          return;
        }

        // Host pushed events
        if (data.method === 'wallet.accountsChanged') {
          const newAddr = (data.params && data.params.accounts && data.params.accounts[0]) || null;
          this.caps.wallet.address = newAddr;
          this.caps.wallet.connected = !!newAddr;
          this.caps.evm.write.available = !!newAddr;
          this.caps.signing = !!newAddr;
          this.caps.contractWrite = !!newAddr;
          CartridgeHost._emit('accountsChanged', newAddr);
          CartridgeHost._emit('capabilitiesChanged', this.getCapabilities());
        } else if (data.method === 'runtime.capabilitiesChanged') {
          if (data.params && data.params.capabilities) {
            this.caps = { ...this.caps, ...data.params.capabilities };
            CartridgeHost._emit('capabilitiesChanged', this.getCapabilities());
          }
        }
      };

      if (this.port) {
        this.port.onmessage = handleMsg;
      }
    }

    _sendRequest(method, params = {}, timeoutMs = 15000) {
      return new Promise((resolve, reject) => {
        const id = 'req_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        const timer = setTimeout(() => {
          if (this.pendingRequests.has(id)) {
            this.pendingRequests.delete(id);
            const err = new Error(`Cartridge host request timed out (${method})`);
            err.code = -32000;
            reject(err);
          }
        }, timeoutMs);

        this.pendingRequests.set(id, { resolve, reject, timer, method });

        const payload = {
          jsonrpc: '2.0',
          id: id,
          method: method,
          params: params
        };

        try {
          if (this.port) {
            this.port.postMessage(payload);
          } else {
            clearTimeout(timer);
            this.pendingRequests.delete(id);
            reject(new Error('Host bridge transport unavailable'));
          }
        } catch (e) {
          clearTimeout(timer);
          this.pendingRequests.delete(id);
          reject(e);
        }
      });
    }

    getAddress() {
      return this.caps.wallet.address || null;
    }

    getCapabilities() {
      return { ...this.caps };
    }

    async requestAccounts() {
      return await this.connect();
    }

    async connect(options = {}) {
      const res = await this._sendRequest('wallet.connect', options, 30000);
      const accounts = Array.isArray(res) ? res : (res && res.accounts ? res.accounts : [res]);
      const addr = accounts[0] || null;
      if (addr) {
        this.caps.wallet.address = addr;
        this.caps.wallet.connected = true;
        this.caps.evm.write.available = true;
        this.caps.signing = true;
        this.caps.contractWrite = true;
        CartridgeHost._emit('accountsChanged', addr);
        CartridgeHost._emit('capabilitiesChanged', this.getCapabilities());
      }
      return addr;
    }

    async disconnect() {
      await this._sendRequest('wallet.disconnect', {}, 5000).catch(() => {});
      this.caps.wallet.address = null;
      this.caps.wallet.connected = false;
      this.caps.evm.write.available = false;
      this.caps.signing = false;
      this.caps.contractWrite = false;
      CartridgeHost._emit('accountsChanged', null);
      CartridgeHost._emit('capabilitiesChanged', this.getCapabilities());
    }

    async readContract({ to, data }) {
      return await this._sendRequest('evm.read', { to, data }, 10000);
    }

    async writeContract({ to, data, gas, value }) {
      return await this._sendRequest('evm.write', { to, data, gas, value }, 60000);
    }

    async waitForReceipt(txHash, maxAttempts = 15) {
      return await this._sendRequest('evm.receipt', { txHash, maxAttempts }, 60000);
    }
  }

  const CartridgeHost = {
    _adapter: null,
    _listeners: new Map(),

    init(adapter) {
      this._adapter = adapter || new DirectHostAdapter();
    },

    getAdapter() {
      if (!this._adapter) {
        this._adapter = new DirectHostAdapter();
      }
      return this._adapter;
    },

    setAdapter(adapter) {
      this._adapter = adapter;
      this._emit('adapterChanged', adapter.name);
      this._emit('capabilitiesChanged', this.getCapabilities());
    },

    getAddress() {
      return this.getAdapter().getAddress();
    },

    getCapabilities() {
      return this.getAdapter().getCapabilities();
    },

    async requestAccounts() {
      return await this.getAdapter().requestAccounts();
    },

    async connect(options) {
      return await this.getAdapter().connect(options);
    },

    async disconnect() {
      return await this.getAdapter().disconnect();
    },

    async readContract(params) {
      return await this.getAdapter().readContract(params);
    },

    async writeContract(params) {
      return await this.getAdapter().writeContract(params);
    },

    async waitForReceipt(txHash, maxAttempts) {
      return await this.getAdapter().waitForReceipt(txHash, maxAttempts);
    },

    on(event, handler) {
      if (!this._listeners.has(event)) this._listeners.set(event, new Set());
      this._listeners.get(event).add(handler);
    },

    removeListener(event, handler) {
      if (this._listeners.has(event)) {
        this._listeners.get(event).delete(handler);
      }
    },

    _emit(event, data) {
      if (this._listeners.has(event)) {
        for (const h of this._listeners.get(event)) {
          try { h(data); } catch (e) { console.error('CartridgeHost event error:', e); }
        }
      }
    }
  };

  CartridgeHost.init(new DirectHostAdapter());

  return {
    DirectHostAdapter,
    BridgeHostAdapter,
    CartridgeHost,
    setMockAddress: (addr) => { connectedUserAddress = addr; }
  };
}

// Simulated Host Server (represents the embedding shell, e.g. web host or console runtime)
class MockHostServer {
  constructor(port, options = {}) {
    this.port = port;
    this.connectedAccount = options.initialAccount || null;
    this.allowedContracts = new Set([ALLOWED_OUTLAWS, ALLOWED_LOOT, ALLOWED_RAIDS]);
    this.delayMs = options.delayMs || 0;
    this.shouldTimeout = options.shouldTimeout || false;

    this.port.onmessage = async (event) => {
      if (this.shouldTimeout) return; // Simulate unresponsive host

      const req = event.data;
      if (!req || typeof req !== 'object') return;

      if (this.delayMs > 0) {
        await new Promise(r => setTimeout(r, this.delayMs));
      }

      const res = await this.handleRequest(req);
      if (res) {
        this.port.postMessage(res);
      }
    };
  }

  async handleRequest(req) {
    const { id, method, params } = req;
    try {
      let result = null;
      switch (method) {
        case 'runtime.capabilities':
          result = {
            wallet: { supported: true, connected: !!this.connectedAccount, address: this.connectedAccount, providerName: 'MockHost' },
            evm: {
              read: { supported: true, available: true },
              write: { supported: true, available: !!this.connectedAccount, authorized: true }
            },
            signing: !!this.connectedAccount,
            contractRead: true,
            contractWrite: !!this.connectedAccount,
            isSandboxed: false
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
          result = '0x0000000000000000000000000000000000000000000000000000000000000042';
          break;

        case 'evm.write': {
          const { to } = params || {};
          if (!to) throw new Error('Target "to" required');
          // Host Boundary Permission Enforcement
          if (!this.allowedContracts.has(to.toLowerCase())) {
            const err = new Error(`Unauthorized contract target: ${to}`);
            err.code = 4003;
            throw err;
          }
          if (!this.connectedAccount) {
            const err = new Error('Wallet not connected in host');
            err.code = 4100;
            throw err;
          }
          result = '0xbridged_tx_hash_' + Math.random().toString(36).substr(2, 8);
          break;
        }

        case 'evm.receipt':
          result = {
            status: '0x1',
            transactionHash: params.txHash,
            blockNumber: '0x777'
          };
          break;

        default:
          throw new Error(`Unknown method: ${method}`);
      }
      return { jsonrpc: '2.0', id, result };
    } catch (e) {
      return {
        jsonrpc: '2.0',
        id,
        error: { code: e.code || -32603, message: e.message }
      };
    }
  }

  notifyAccount(addr) {
    this.connectedAccount = addr;
    this.port.postMessage({
      method: 'wallet.accountsChanged',
      params: { accounts: addr ? [addr] : [] }
    });
  }

  notifyCapabilities(caps) {
    this.port.postMessage({
      method: 'runtime.capabilitiesChanged',
      params: { capabilities: caps }
    });
  }
}

// RUN TEST MATRIX
async function runTests() {
  console.log('🧪 Starting Cartridge Host Runtime V0 Test Suite...\n');
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

  // --- 1. DIRECT ADAPTER & DEFAULT FALLBACK ---
  await test('Direct adapter defaults to disconnected state and public read-only RPC', async () => {
    const env = createMockEnvironment();
    const host = env.CartridgeHost;
    assert.strictEqual(host.getAdapter().name, 'direct');
    assert.strictEqual(host.getAddress(), null);

    const caps = host.getCapabilities();
    assert.strictEqual(caps.adapter, 'direct');
    assert.strictEqual(caps.wallet.connected, false);
    assert.strictEqual(caps.contractRead, true);
    assert.strictEqual(caps.contractWrite, false);

    // Read contract works via fallback
    const res = await host.readContract({ to: ALLOWED_LOOT, data: '0x1234' });
    assert.ok(res.startsWith('0x'));
  });

  await test('Direct adapter connects and enables write capability', async () => {
    const env = createMockEnvironment();
    const host = env.CartridgeHost;

    const mockAddr = '0x1234567890123456789012345678901234567890';
    await host.connect({ mockAddress: mockAddr });

    assert.strictEqual(host.getAddress(), mockAddr);
    const caps = host.getCapabilities();
    assert.strictEqual(caps.wallet.connected, true);
    assert.strictEqual(caps.contractWrite, true);

    const txHash = await host.writeContract({ to: ALLOWED_OUTLAWS, data: '0xabcd' });
    assert.ok(txHash.startsWith('0xdirect_tx_hash_'));

    await host.disconnect();
    assert.strictEqual(host.getAddress(), null);
    assert.strictEqual(host.getCapabilities().contractWrite, false);
  });

  // --- 2. BRIDGE HANDSHAKE & ADAPTER SWITCHING ---
  await test('Bridge adapter attaches and switches CartridgeHost via MessagePort', async () => {
    const env = createMockEnvironment();
    const host = env.CartridgeHost;

    const { port1, port2 } = new MessageChannel();
    const hostServer = new MockHostServer(port2);

    let adapterChangedEvent = null;
    host.on('adapterChanged', (name) => { adapterChangedEvent = name; });

    const bridgeAdapter = new env.BridgeHostAdapter(port1);
    host.setAdapter(bridgeAdapter);

    assert.strictEqual(host.getAdapter().name, 'bridge');
    assert.strictEqual(adapterChangedEvent, 'bridge');
    assert.strictEqual(host.getCapabilities().adapter, 'bridge');

    port1.close();
    port2.close();
  });

  // --- 3. BRIDGE RPC: EVM READ ---
  await test('Bridge adapter routes evm.read through host', async () => {
    const env = createMockEnvironment();
    const host = env.CartridgeHost;
    const { port1, port2 } = new MessageChannel();
    const hostServer = new MockHostServer(port2);
    host.setAdapter(new env.BridgeHostAdapter(port1));

    const result = await host.readContract({ to: ALLOWED_OUTLAWS, data: '0xownerOf' });
    assert.strictEqual(result, '0x0000000000000000000000000000000000000000000000000000000000000042');

    port1.close();
    port2.close();
  });

  // --- 4. BRIDGE WALLET CONNECT / DISCONNECT ---
  await test('Bridge adapter connects wallet via host and updates capabilities', async () => {
    const env = createMockEnvironment();
    const host = env.CartridgeHost;
    const { port1, port2 } = new MessageChannel();
    const hostServer = new MockHostServer(port2);
    host.setAdapter(new env.BridgeHostAdapter(port1));

    let receivedAddrEvent = null;
    host.on('accountsChanged', (addr) => { receivedAddrEvent = addr; });

    const addr = await host.connect();
    assert.strictEqual(addr, '0x70997970C51812dc3A010C7d01b50e0d17dc79C8');
    assert.strictEqual(host.getAddress(), '0x70997970C51812dc3A010C7d01b50e0d17dc79C8');
    assert.strictEqual(receivedAddrEvent, '0x70997970C51812dc3A010C7d01b50e0d17dc79C8');
    assert.strictEqual(host.getCapabilities().contractWrite, true);

    await host.disconnect();
    assert.strictEqual(host.getAddress(), null);
    assert.strictEqual(receivedAddrEvent, null);
    assert.strictEqual(host.getCapabilities().contractWrite, false);

    port1.close();
    port2.close();
  });

  // --- 5. BRIDGE EVM WRITE: AUTHORIZED VS UNAUTHORIZED ---
  await test('Bridge evm.write succeeds for allowed contracts (Outlaws, Loot, Raids)', async () => {
    const env = createMockEnvironment();
    const host = env.CartridgeHost;
    const { port1, port2 } = new MessageChannel();
    const hostServer = new MockHostServer(port2, { initialAccount: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' });
    host.setAdapter(new env.BridgeHostAdapter(port1));

    // Must connect first
    await host.connect();

    // Outlaws
    const tx1 = await host.writeContract({ to: ALLOWED_OUTLAWS, data: '0x1111' });
    assert.ok(tx1.startsWith('0xbridged_tx_hash_'));

    // Loot
    const tx2 = await host.writeContract({ to: ALLOWED_LOOT, data: '0x2222' });
    assert.ok(tx2.startsWith('0xbridged_tx_hash_'));

    // Raids
    const tx3 = await host.writeContract({ to: ALLOWED_RAIDS, data: '0x3333' });
    assert.ok(tx3.startsWith('0xbridged_tx_hash_'));

    port1.close();
    port2.close();
  });

  await test('Host boundary blocks unauthorized contract target with error code 4003', async () => {
    const env = createMockEnvironment();
    const host = env.CartridgeHost;
    const { port1, port2 } = new MessageChannel();
    const hostServer = new MockHostServer(port2, { initialAccount: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' });
    host.setAdapter(new env.BridgeHostAdapter(port1));

    await host.connect();

    let errCaught = null;
    try {
      await host.writeContract({ to: FORBIDDEN_CONTRACT, data: '0xsteal' });
    } catch (e) {
      errCaught = e;
    }

    assert.ok(errCaught, 'Expected permission error');
    assert.strictEqual(errCaught.code, 4003, 'Expected error code 4003 (Unauthorized target)');
    assert.ok(errCaught.message.includes('Unauthorized contract target'));

    port1.close();
    port2.close();
  });

  // --- 6. RECEIPT RETRIEVAL ---
  await test('Bridge evm.receipt returns valid transaction receipt', async () => {
    const env = createMockEnvironment();
    const host = env.CartridgeHost;
    const { port1, port2 } = new MessageChannel();
    const hostServer = new MockHostServer(port2);
    host.setAdapter(new env.BridgeHostAdapter(port1));

    const receipt = await host.waitForReceipt('0xtest_tx_hash');
    assert.strictEqual(receipt.status, '0x1');
    assert.strictEqual(receipt.transactionHash, '0xtest_tx_hash');
    assert.strictEqual(receipt.blockNumber, '0x777');

    port1.close();
    port2.close();
  });

  // --- 7. DYNAMIC HOST EVENT PUSH ---
  await test('Host dynamic event dispatching triggers CartridgeHost subscribers', async () => {
    const env = createMockEnvironment();
    const host = env.CartridgeHost;
    const { port1, port2 } = new MessageChannel();
    const hostServer = new MockHostServer(port2);
    host.setAdapter(new env.BridgeHostAdapter(port1));

    let pushedAddr = null;
    let pushedCaps = null;
    host.on('accountsChanged', (addr) => { pushedAddr = addr; });
    host.on('capabilitiesChanged', (caps) => { pushedCaps = caps; });

    // Host pushes account change
    const newAddr = '0x8888888888888888888888888888888888888888';
    hostServer.notifyAccount(newAddr);

    // Allow event loop cycle
    await new Promise(r => setTimeout(r, 50));

    assert.strictEqual(pushedAddr, newAddr);
    assert.strictEqual(host.getAddress(), newAddr);
    assert.strictEqual(host.getCapabilities().wallet.connected, true);
    assert.strictEqual(host.getCapabilities().contractWrite, true);

    // Host pushes capability update
    hostServer.notifyCapabilities({ customFeatureFlag: true });
    await new Promise(r => setTimeout(r, 50));
    assert.strictEqual(host.getCapabilities().customFeatureFlag, true);

    port1.close();
    port2.close();
  });

  // --- 8. REQUEST TIMEOUT HANDLING ---
  await test('Bridge adapter properly rejects pending request on timeout', async () => {
    const env = createMockEnvironment();
    const host = env.CartridgeHost;
    const { port1, port2 } = new MessageChannel();
    // Create unresponsive host server
    const hostServer = new MockHostServer(port2, { shouldTimeout: true });
    const bridge = new env.BridgeHostAdapter(port1);
    host.setAdapter(bridge);

    let timeoutErr = null;
    try {
      // Send request with short 100ms timeout
      await bridge._sendRequest('evm.read', { to: ALLOWED_LOOT }, 100);
    } catch (e) {
      timeoutErr = e;
    }

    assert.ok(timeoutErr, 'Expected timeout rejection');
    assert.strictEqual(timeoutErr.code, -32000);
    assert.ok(timeoutErr.message.includes('timed out'));

    port1.close();
    port2.close();
  });

  // --- 9. MALFORMED / UNEXPECTED MESSAGE DROPPING ---
  await test('Bridge adapter silently ignores malformed messages and unknown IDs', async () => {
    const env = createMockEnvironment();
    const host = env.CartridgeHost;
    const { port1, port2 } = new MessageChannel();
    const hostServer = new MockHostServer(port2);
    host.setAdapter(new env.BridgeHostAdapter(port1));

    // Send malformed non-object messages
    port2.postMessage(null);
    port2.postMessage("plain text string");
    port2.postMessage({ id: 'non_existent_req_id', result: 'orphan' });

    // Verify adapter state is unaffected and next legitimate request succeeds
    const result = await host.readContract({ to: ALLOWED_OUTLAWS, data: '0x' });
    assert.strictEqual(result, '0x0000000000000000000000000000000000000000000000000000000000000042');

    port1.close();
    port2.close();
  });

  // SUMMARY
  console.log('\n=========================================');
  console.log(`Cartridge Host Runtime V0 Test Results:`);
  console.log(`Total: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
  console.log('=========================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests();

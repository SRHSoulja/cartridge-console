/**
 * Automated Regression Test Suite: Generic Web Host & Multi-Cartridge Platform Proof
 *
 * Verifies:
 * 1. LocalCartridgeResolver resolves Cartridge #0001 (HoodQuest) and Cartridge #0002 (Runtime Test Cartridge)
 * 2. Package integrity verification rejects tampered bytes before execution (Code 5003)
 * 3. Generic host loads and runs Cartridge #0001 solely from manifest
 * 4. Generic host loads and runs Cartridge #0002 solely from manifest
 * 5. Zero application-specific or game-specific logic in the host
 * 6. Dynamic Requested vs Granted permission enforcement
 * 7. Host isolation & MessageChannel RPC bridge
 * 8. Clean multi-tenant cartridge switching in the same host instance
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const { MessageChannel } = require('worker_threads');
const { keccak256 } = require('js-sha3');

const {
  CartridgeHost,
  BridgeHostAdapter,
  DirectHostAdapter,
  ConsoleRuntimeError,
  PolicyEngine
} = require('../runtime/cartridge_host_runtime.js');

const {
  CartridgeResolver,
  LocalCartridgeResolver,
  createDefaultResolver
} = require('../host/resolver.js');

const {
  GenericHostCore
} = require('../host/host_core.js');

const SEPOLIA_HEX = '0xaa36a7';
const MAINNET_HEX = '0x1';

async function runGenericHostTestSuite() {
  console.log('🏛️ Starting Generic Web Host & Multi-Cartridge Compatibility Test Suite...\n');
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

  const resolver = createDefaultResolver(path.join(__dirname, '../cartridges'));
  const keccakFn = (b) => keccak256(b);

  // --- 1. LOCAL CARTRIDGE RESOLVER TESTS ---
  await test('Resolver: Resolves both HoodQuest and Runtime Test Cartridge manifests & packages', async () => {
    const list = await resolver.listCartridges();
    assert.strictEqual(list.length >= 2, true);
    assert.ok(list.some(c => c.id === 'hoodquest'));
    assert.ok(list.some(c => c.id === 'runtime-test-cartridge'));

    // Resolve HoodQuest
    const hq = await resolver.resolve('hoodquest');
    assert.strictEqual(hq.id, 'hoodquest');
    assert.strictEqual(hq.name, 'HoodQuest: Sanctuary of the Falcon');
    assert.strictEqual(hq.expectedContentHash, '0x8a883ea5b9e8497de85abdd1007af9454d01c49e6594bd1743175de0ea0456c0');
    assert.strictEqual(typeof hq.fetchPackageBytes, 'function');

    // Resolve Runtime Test Cartridge
    const testCart = await resolver.resolve('runtime-test-cartridge');
    assert.strictEqual(testCart.id, 'runtime-test-cartridge');
    assert.strictEqual(testCart.name, 'Runtime Test Cartridge');
    assert.strictEqual(testCart.expectedContentHash, '0x60d0bde3416316c5eda839cd1d20350a977ea14edaba4480bc5f3e4f8be95194');

    // Unknown Cartridge fails
    let caughtUnknown = null;
    try {
      await resolver.resolve('non-existent-cartridge');
    } catch (e) {
      caughtUnknown = e;
    }
    assert.ok(caughtUnknown);
  });

  // --- 2. INTEGRITY-BEFORE-EXECUTION VERIFICATION ---
  await test('Integrity: Generic host verifies package content hash before execution and halts on mismatch', async () => {
    const host = new GenericHostCore({ resolver, keccakFn });

    // A. Valid package passes verification
    const booted = await host.loadCartridge('runtime-test-cartridge');
    assert.strictEqual(booted.verified, true);
    assert.strictEqual(host.integrityVerified, true);
    assert.strictEqual(host.computedHash, '0x60d0bde3416316c5eda839cd1d20350a977ea14edaba4480bc5f3e4f8be95194');

    // B. Tampered package fails closed before mount
    const tamperedResolver = new LocalCartridgeResolver();
    tamperedResolver.register('tampered-cartridge', {
      id: 'tampered-cartridge',
      manifest: {
        id: 'tampered-cartridge',
        name: 'Tampered Cartridge',
        version: '1.0.0',
        runtime: { version: '^0.1.0' },
        entry: 'index.html',
        integrity: { contentHash: '0x1111111111111111111111111111111111111111111111111111111111111111' }
      },
      rawBytes: '<html><body>Malicious Payload</body></html>'
    });

    const hostTampered = new GenericHostCore({ resolver: tamperedResolver, keccakFn });
    let integrityCaught = null;
    try {
      await hostTampered.loadCartridge('tampered-cartridge');
    } catch (e) {
      integrityCaught = e;
    }
    assert.ok(integrityCaught, 'Must reject corrupted package bytes');
    assert.strictEqual(integrityCaught.code, 5003);
    assert.ok(integrityCaught.message.includes('Package integrity mismatch'));
    assert.strictEqual(hostTampered.integrityVerified, false);
  });

  // --- 3. REQUESTED VS GRANTED PERMISSIONS GATEKEEPER ---
  await test('Permissions: Host computes granted policy from manifest without self-authorization', async () => {
    const host = new GenericHostCore({ resolver, keccakFn });
    const booted = await host.loadCartridge('runtime-test-cartridge');

    const granted = booted.grantedPolicy;
    assert.ok(granted);
    assert.strictEqual(granted.chainId, SEPOLIA_HEX);

    // Contract 1: PublicLoot (writes: false in manifest -> writes: false in granted)
    const lootRule = granted.contracts.find(c => c.address === '0x0676129B2bF4B06f04AfC7301617b6cE3BB2405c'.toLowerCase());
    assert.ok(lootRule);
    assert.strictEqual(lootRule.writes, false);

    // Contract 2: AllowedEcho (writes: true in manifest -> writes: true in granted)
    const echoRule = granted.contracts.find(c => c.address === '0x7777777777777777777777777777777777777777'.toLowerCase());
    assert.ok(echoRule);
    assert.strictEqual(echoRule.writes, true);
    assert.deepStrictEqual(echoRule.allowedSelectors, ['0x12345678', '0xa9059cbb']);
    assert.strictEqual(echoRule.isElevated, false); // Ordinary write does NOT grant elevated ops

    // Host user overrides write permission: revoke AllowedEcho
    const customizedBoot = await host.loadCartridge('runtime-test-cartridge', {
      ['0x7777777777777777777777777777777777777777'.toLowerCase()]: { writes: false }
    });
    const revokedRule = customizedBoot.grantedPolicy.contracts.find(c => c.address === '0x7777777777777777777777777777777777777777'.toLowerCase());
    assert.strictEqual(revokedRule.writes, false, 'User/host override must successfully revoke write permission');
  });

  // --- 4. HOST BRIDGE RPC DISPATCHER & HARDENED POLICY ---
  await test('Host Bridge: Dispatches RPC methods and enforces fail-closed policy over MessagePort', async () => {
    const host = new GenericHostCore({
      resolver,
      keccakFn,
      account: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      chainId: SEPOLIA_HEX
    });
    await host.loadCartridge('runtime-test-cartridge');

    const { port1, port2 } = new MessageChannel();
    host.bindPortRpc(port1);

    const bridge = new BridgeHostAdapter(port2);
    CartridgeHost.setAdapter(bridge);

    // A. Connect wallet via bridge
    const connectedAddr = await bridge.connect();
    assert.strictEqual(connectedAddr, '0x70997970C51812dc3A010C7d01b50e0d17dc79C8');

    const caps = bridge.getCapabilities();
    assert.strictEqual(caps.adapter, 'bridge');
    assert.strictEqual(caps.contractRead, true);
    assert.strictEqual(caps.contractWrite, true);

    // B. evm.read
    const readVal = await bridge.readContract({
      to: '0x0676129B2bF4B06f04AfC7301617b6cE3BB2405c',
      data: '0x12345678'
    });
    assert.ok(readVal);

    // C. evm.write to authorized target & selector succeeds
    const txHash = await bridge.writeContract({
      to: '0x7777777777777777777777777777777777777777',
      data: '0x12345678'
    });
    assert.ok(txHash.startsWith('0x'));

    // D. evm.write to unauthorized selector fails closed (4003)
    let caughtBadSelector = null;
    try {
      await bridge.writeContract({
        to: '0x7777777777777777777777777777777777777777',
        data: '0xbad0bad0'
      });
    } catch (e) {
      caughtBadSelector = e;
    }
    assert.ok(caughtBadSelector);
    assert.strictEqual(caughtBadSelector.code, 4003);

    // E. evm.write to read-only target fails closed (4003)
    let caughtReadOnlyTarget = null;
    try {
      await bridge.writeContract({
        to: '0x0676129B2bF4B06f04AfC7301617b6cE3BB2405c',
        data: '0x12345678'
      });
    } catch (e) {
      caughtReadOnlyTarget = e;
    }
    assert.ok(caughtReadOnlyTarget);
    assert.strictEqual(caughtReadOnlyTarget.code, 4003);

    // F. evm.receipt returns receipt
    const receipt = await bridge.waitForReceipt(txHash);
    assert.ok(receipt);
    assert.strictEqual(receipt.transactionHash, txHash);

    port1.close();
    port2.close();
  });

  // --- 4B. EVM.LOGS BRIDGE DISPATCHING & CHAIN GATING ---
  await test('Host Bridge: Dispatches evm.logs with normalization, parameter validation, and fail-closed chain gating', async () => {
    const host = new GenericHostCore({
      resolver,
      keccakFn,
      account: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      chainId: SEPOLIA_HEX
    });

    host.logsHandler = async (filter) => {
      return [
        {
          address: '0xF75323518DF7CE90637E2B93CFD7F7D0627CC205',
          topics: ['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'],
          data: '0x0000000000000000000000000000000000000000000000000000000000000001',
          blockNumber: 123456,
          blockHash: '0xABCD',
          transactionHash: '0x1234',
          transactionIndex: 2,
          logIndex: 0,
          removed: false
        }
      ];
    };

    await host.loadCartridge('runtime-test-cartridge');

    const { port1, port2 } = new MessageChannel();
    host.bindPortRpc(port1);
    const bridge = new BridgeHostAdapter(port2);

    // 1. Query logs successfully
    const logs = await bridge.getLogs({
      address: '0xF75323518df7Ce90637e2b93cFd7f7d0627cc205',
      topics: ['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef']
    });

    assert.strictEqual(Array.isArray(logs), true);
    assert.strictEqual(logs.length, 1);
    assert.strictEqual(logs[0].address, '0xf75323518df7ce90637e2b93cfd7f7d0627cc205');
    assert.strictEqual(logs[0].blockNumber, '0x1e240'); // 123456 in hex
    assert.strictEqual(logs[0].transactionIndex, '0x2');
    assert.strictEqual(logs[0].logIndex, '0x0');
    assert.strictEqual(logs[0].removed, false);

    // 2. Chain mismatch fails closed (4901)
    let caughtChainMismatch = null;
    try {
      await bridge._sendRequest('evm.logs', { chainId: MAINNET_HEX, address: '0xF75323518df7Ce90637e2b93cFd7f7d0627cc205' });
    } catch (e) {
      caughtChainMismatch = e;
    }
    assert.ok(caughtChainMismatch, 'Chain mismatch must fail closed');
    assert.strictEqual(caughtChainMismatch.code, 4901);

    // 3. Malformed filter fails closed (-32602)
    let caughtBadFilter = null;
    try {
      await bridge.getLogs('not-an-object');
    } catch (e) {
      caughtBadFilter = e;
    }
    assert.ok(caughtBadFilter);
    assert.strictEqual(caughtBadFilter.code, -32602);

    port1.close();
    port2.close();
  });

  // --- 5. TWO-CARTRIDGE HOSTING PROOF (CARTRIDGE #0001 & #0002) ---
  await test('Two-Cartridge Proof: Host loads Cartridge #0001 and #0002 sequentially through exact same path', async () => {
    const host = new GenericHostCore({
      resolver,
      keccakFn,
      account: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      chainId: SEPOLIA_HEX
    });

    // 1. Boot Cartridge #0001 (HoodQuest)
    const hqBoot = await host.loadCartridge('hoodquest');
    assert.strictEqual(hqBoot.id, 'hoodquest');
    assert.strictEqual(hqBoot.name, 'HoodQuest: Sanctuary of the Falcon');
    assert.strictEqual(hqBoot.verified, true);
    assert.strictEqual(host.integrityVerified, true);
    assert.strictEqual(host.computedHash, '0x8a883ea5b9e8497de85abdd1007af9454d01c49e6594bd1743175de0ea0456c0');

    // Test HoodQuest RPC via Host
    const { port1: hqPort1, port2: hqPort2 } = new MessageChannel();
    host.bindPortRpc(hqPort1);
    const hqBridge = new BridgeHostAdapter(hqPort2);
    await hqBridge.connect();

    const hqWriteOutlaws = await hqBridge.writeContract({
      to: '0xF75323518df7Ce90637e2b93cFd7f7d0627cc205',
      data: '0xf59dfdfb' + '00'.repeat(32) // feed(uint256)
    });
    assert.ok(hqWriteOutlaws.startsWith('0x'));

    hqPort1.close();
    hqPort2.close();

    // 2. Switch Host to Cartridge #0002 (Runtime Test Cartridge) without restart
    const testCartBoot = await host.loadCartridge('runtime-test-cartridge');
    assert.strictEqual(testCartBoot.id, 'runtime-test-cartridge');
    assert.strictEqual(testCartBoot.name, 'Runtime Test Cartridge');
    assert.strictEqual(testCartBoot.verified, true);
    assert.strictEqual(host.integrityVerified, true);
    assert.strictEqual(host.computedHash, '0x60d0bde3416316c5eda839cd1d20350a977ea14edaba4480bc5f3e4f8be95194');

    // Test Runtime Test Cartridge RPC via Same Host
    const { port1: tcPort1, port2: tcPort2 } = new MessageChannel();
    host.bindPortRpc(tcPort1);
    const tcBridge = new BridgeHostAdapter(tcPort2);
    await tcBridge.connect();

    const tcWriteEcho = await tcBridge.writeContract({
      to: '0x7777777777777777777777777777777777777777',
      data: '0x12345678'
    });
    assert.ok(tcWriteEcho.startsWith('0x'));

    tcPort1.close();
    tcPort2.close();
  });

  // --- 6. AUDIT: ZERO APPLICATION-SPECIFIC LOGIC IN HOST SOURCE ---
  await test('Audit: Generic host source code contains zero application-specific or game-specific references', async () => {
    const hostCoreSource = fs.readFileSync(path.join(__dirname, '../host/host_core.js'), 'utf8');
    const hostHtmlSource = fs.readFileSync(path.join(__dirname, '../host/index.html'), 'utf8');
    const resolverSource = fs.readFileSync(path.join(__dirname, '../host/resolver.js'), 'utf8');

    const forbiddenTerms = [
      'outlaws',
      'loot',
      'raids',
      'falcon',
      'sanctuary',
      'bow',
      'arrow',
      'pet',
      'debond',
      'bazaar',
      'heist',
      'marks',
      'targets',
      'shoot',
      'poach',
      'cross'
    ];

    // Check host_core.js (the actual host boundary engine)
    for (const term of forbiddenTerms) {
      const regex = new RegExp(`\\b${term}\\b`, 'i');
      assert.ok(!regex.test(hostCoreSource), `host_core.js must not contain application term: "${term}"`);
    }

    // Check host/index.html
    for (const term of forbiddenTerms) {
      // Allow 'hoodquest' only in the default query param string or default fallback ID
      const regex = new RegExp(`\\b${term}\\b`, 'i');
      assert.ok(!regex.test(hostHtmlSource), `host/index.html must not contain application term: "${term}"`);
    }

    // Check host/resolver.js core logic
    const resolverCoreLogic = resolverSource.split('createDefaultResolver')[0];
    for (const term of forbiddenTerms) {
      const regex = new RegExp(`\\b${term}\\b`, 'i');
      assert.ok(!regex.test(resolverCoreLogic), `resolver.js core logic must not contain application term: "${term}"`);
    }
  });

  // SUMMARY
  console.log('\n=============================================================');
  console.log(`Generic Web Host & Compatibility Suite Results:`);
  console.log(`Total: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
  console.log('=============================================================\n');

  if (failed > 0) process.exit(1);
}

runGenericHostTestSuite();

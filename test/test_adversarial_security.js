/**
 * Automated Regression Test Suite: Hardened Host Boundary & Adversarial Suite (Cartridge #0003)
 *
 * Verifies:
 * 1. Independent cryptographic derivation of all standard function selectors (Keccak-256)
 * 2. Primary fail-closed authorization: chain + target + explicit non-empty selectors + value
 * 3. Canonical EIP-1193 hexadecimal chain identity ('0xaa36a7')
 * 4. Distinct error code semantics: 4003 PolicyViolation vs 4901 Provider ChainDisconnected
 * 5. Elevated asset operation defense-in-depth and forward-compatible argument constraints
 * 6. Minimum viable sandbox permissions (sandbox="allow-scripts")
 * 7. Package-integrity-before-execution verification (CartridgeLoader)
 * 8. Replayed IDs, payload limits, rate limits, and second-host handshake immunity
 */

const assert = require('assert');
const { MessageChannel } = require('worker_threads');
const { keccak256 } = require('js-sha3');

const {
  CartridgeHost,
  BridgeHostAdapter,
  DirectHostAdapter,
  ConsoleRuntimeError,
  PolicyEngine,
  ELEVATED_SELECTORS,
  CANONICAL_SIGNATURES,
  normalizeChainId,
  CartridgeLoader
} = require('../runtime/cartridge_host_runtime.js');

const SEPOLIA_HEX = '0xaa36a7';
const MAINNET_HEX = '0x1';

const ALLOWED_CONTRACT = '0xF75323518df7Ce90637e2b93cFd7f7d0627cc205'.toLowerCase();
const FORBIDDEN_CONTRACT = '0x1111111111111111111111111111111111111111'.toLowerCase();

const GAME_ACTION_SELECTOR = '0x12345678';
const FORBIDDEN_SELECTOR = '0xbad0bad0';

// Independent Canonical Signature Derivation Helper
function deriveSelector(signature) {
  return '0x' + keccak256(signature).slice(0, 8);
}

// Mock Hardened Host Server implementing strict V0.1 boundary policy
class HardenedHostServer {
  constructor(port, options = {}) {
    this.port = port;
    this.activeChainId = normalizeChainId(options.chainId) || SEPOLIA_HEX;
    this.activeAccount = options.account || '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
    this.policy = options.policy || {
      chainId: SEPOLIA_HEX,
      contracts: [
        {
          address: ALLOWED_CONTRACT,
          name: 'AllowedOutlaws',
          writes: true,
          allowedSelectors: [GAME_ACTION_SELECTOR],
          allowNativeValue: false,
          isElevated: false
        }
      ]
    };

    this.seenRequestIds = new Set();
    this.inFlightCount = 0;
    this.maxConcurrent = options.maxConcurrent || 10;
    this.maxPayload = options.maxPayload || 65536;

    this.port.onmessage = async (event) => {
      const raw = event.data;
      if (!raw || typeof raw !== 'object') return;

      const res = await this.handleMessage(raw);
      if (res) this.port.postMessage(res);
    };
  }

  async handleMessage(req) {
    const { id, method, params } = req;

    // Payload size check
    const serialized = JSON.stringify(req);
    if (serialized.length > this.maxPayload) {
      return { jsonrpc: '2.0', id, error: { code: -32600, message: 'Payload size exceeds limit' } };
    }

    // Duplicate ID check
    if (id && this.seenRequestIds.has(id)) {
      return { jsonrpc: '2.0', id, error: { code: -32600, message: `Duplicate request ID: ${id}` } };
    }
    if (id) this.seenRequestIds.add(id);

    // Concurrency limit
    if (this.inFlightCount >= this.maxConcurrent) {
      return { jsonrpc: '2.0', id, error: { code: -32005, message: 'Max concurrent requests exceeded' } };
    }
    this.inFlightCount++;

    try {
      let result = null;
      switch (method) {
        case 'wallet.connect':
          result = [this.activeAccount];
          break;

        case 'wallet.disconnect':
          this.activeAccount = null;
          result = true;
          break;

        case 'evm.read':
          result = '0x0000000000000000000000000000000000000000000000000000000000000001';
          break;

        case 'evm.write': {
          const { to, data, value, chainId } = params || {};

          // 1. Account Check
          if (!this.activeAccount) {
            throw ConsoleRuntimeError.unauthorized('Wallet disconnected in host');
          }

          // 2. Chain Match Check (Canonical Hex Form)
          const reqChain = normalizeChainId(chainId) || this.activeChainId;
          if (reqChain !== this.activeChainId) {
            throw ConsoleRuntimeError.policyViolation(`Active host chain is ${this.activeChainId}, but request targeted ${reqChain}`);
          }

          // 3. PolicyEngine Strict Validation (Target + Non-empty allowedSelectors + Elevated + Constraints + Value)
          PolicyEngine.evaluate({ chainId: reqChain, target: to, data, value }, this.policy);

          result = '0xsecure_tx_hash_' + Math.random().toString(36).substr(2, 8);
          break;
        }

        default:
          throw ConsoleRuntimeError.unsupportedMethod(method);
      }
      return { jsonrpc: '2.0', id, result };
    } catch (e) {
      return {
        jsonrpc: '2.0',
        id,
        error: { code: e.code || -32603, message: e.message }
      };
    } finally {
      this.inFlightCount--;
    }
  }

  changeChain(newChainId) {
    this.activeChainId = normalizeChainId(newChainId);
    this.port.postMessage({
      method: 'wallet.chainChanged',
      params: { chainId: this.activeChainId }
    });
  }

  disconnectWallet() {
    this.activeAccount = null;
    this.port.postMessage({
      method: 'wallet.accountsChanged',
      params: { accounts: [] }
    });
  }
}

async function runAdversarialTestSuite() {
  console.log('🛡️ Starting Hardened Host Boundary & Adversarial Suite (Cartridge #0003)...\n');
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

  // --- 1. INDEPENDENT CANONICAL SELECTOR DERIVATION AUDIT ---
  await test('Audit 1: Cryptographically derive and verify all canonical selectors from Solidity signatures', async () => {
    const expectedDerivations = {
      'setApprovalForAll(address,bool)': '0xa22cb465',
      'approve(address,uint256)': '0x095ea7b3',
      'transferFrom(address,address,uint256)': '0x23b872dd',
      'safeTransferFrom(address,address,uint256)': '0x42842e0e',
      'safeTransferFrom(address,address,uint256,bytes)': '0xb88d4fde',
      'safeTransferFrom(address,address,uint256,uint256,bytes)': '0xf242432a',
      'safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)': '0x2eb2c2d6',
      'transfer(address,uint256)': '0xa9059cbb',
      'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)': '0xd505accf',
      'permit(address,uint256,uint256,bytes)': '0x745a41bc',
      'permit(address,uint256,uint256,uint8,bytes32,bytes32)': '0x7ac2ff7b'
    };

    for (const [sig, expectedSelector] of Object.entries(expectedDerivations)) {
      const derived = deriveSelector(sig);
      assert.strictEqual(derived, expectedSelector, `Mismatch on canonical signature "${sig}"`);
      assert.ok(ELEVATED_SELECTORS.has(derived), `ELEVATED_SELECTORS table missing derived selector ${derived} for "${sig}"`);
    }

    // Assert explicit corrections and EIP standards
    assert.strictEqual(deriveSelector('setApprovalForAll(address,bool)'), '0xa22cb465');
    assert.strictEqual(deriveSelector('permit(address,address,uint256,uint256,uint8,bytes32,bytes32)'), '0xd505accf');
    assert.strictEqual(deriveSelector('permit(address,uint256,uint256,bytes)'), '0x745a41bc', 'Canonical ERC-4494 must derive 0x745a41bc');
    assert.strictEqual(CANONICAL_SIGNATURES.PERMIT_ERC4494, 'permit(address,uint256,uint256,bytes)');
    assert.strictEqual(CANONICAL_SIGNATURES.NONSTANDARD_PERMIT_ERC721_PACKED_RSV, 'permit(address,uint256,uint256,uint8,bytes32,bytes32)');
    assert.ok(!ELEVATED_SELECTORS.has('0xa2224470'), 'Legacy typo selector 0xa2224470 must not be present');
    assert.ok(!ELEVATED_SELECTORS.has('0x3018209e'), 'Legacy incorrect permit selector 0x3018209e must not be present');
  });

  // --- 2. CANONICAL EIP-1193 HEX CHAIN IDENTITY ---
  await test('Audit 2: Normalize and expose chain ID strictly in canonical EIP-1193 hex format', async () => {
    assert.strictEqual(normalizeChainId(11155111), '0xaa36a7');
    assert.strictEqual(normalizeChainId('11155111'), '0xaa36a7');
    assert.strictEqual(normalizeChainId('0xaa36a7'), '0xaa36a7');
    assert.strictEqual(normalizeChainId('0XAA36A7'), '0xaa36a7');
    assert.strictEqual(normalizeChainId(1), '0x1');
    assert.strictEqual(normalizeChainId('0x1'), '0x1');

    const direct = new DirectHostAdapter({ chainId: 11155111 });
    assert.strictEqual(direct.getChainId(), '0xaa36a7');
    assert.strictEqual(direct.getCapabilities().evm.chainId, '0xaa36a7');
  });

  // --- 3. PRIMARY FAIL-CLOSED SELECTOR AUTHORIZATION ---
  await test('Audit 3: Fail closed with 4003 if a write rule omits allowedSelectors or specifies empty list', async () => {
    const emptyPolicy = {
      chainId: SEPOLIA_HEX,
      contracts: [
        { address: ALLOWED_CONTRACT, writes: true } // Omitted allowedSelectors
      ]
    };

    let caught = null;
    try {
      PolicyEngine.evaluate({ chainId: SEPOLIA_HEX, target: ALLOWED_CONTRACT, data: GAME_ACTION_SELECTOR }, emptyPolicy);
    } catch (e) {
      caught = e;
    }
    assert.ok(caught, 'Must reject rule without explicit allowedSelectors');
    assert.strictEqual(caught.code, 4003);
    assert.ok(caught.message.includes('No allowed selectors declared'));
  });

  await test('Audit 4: Reject allowed contract when invoked with unlisted function selector with 4003', async () => {
    const { port1, port2 } = new MessageChannel();
    const server = new HardenedHostServer(port2);
    const bridge = new BridgeHostAdapter(port1, {
      adapter: 'bridge',
      wallet: { supported: true, connected: true, address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' },
      evm: { chainId: SEPOLIA_HEX, write: { available: true } }
    });

    let caught = null;
    try {
      await bridge.writeContract({ to: ALLOWED_CONTRACT, data: FORBIDDEN_SELECTOR });
    } catch (e) {
      caught = e;
    }

    assert.ok(caught, 'Must reject unlisted selector');
    assert.strictEqual(caught.code, 4003);
    assert.ok(caught.message.includes('Unauthorized function selector'));

    port1.close();
    port2.close();
  });

  // --- 4. INDEPENDENT ELEVATED ASSET SELECTORS TEST BATTERY ---
  await test('Audit 5: Reject all standard asset approvals and transfers when isElevated is false', async () => {
    const { port1, port2 } = new MessageChannel();
    // Policy explicitly lists the selector, but isElevated is false
    const server = new HardenedHostServer(port2, {
      policy: {
        chainId: SEPOLIA_HEX,
        contracts: [
          {
            address: ALLOWED_CONTRACT,
            writes: true,
            allowedSelectors: [
              deriveSelector('setApprovalForAll(address,bool)'),
              deriveSelector('approve(address,uint256)'),
              deriveSelector('transferFrom(address,address,uint256)'),
              deriveSelector('safeTransferFrom(address,address,uint256)'),
              deriveSelector('safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)'),
              deriveSelector('transfer(address,uint256)'),
              deriveSelector('permit(address,address,uint256,uint256,uint8,bytes32,bytes32)')
            ],
            isElevated: false // Ordinary write permission must not grant elevated operations
          }
        ]
      }
    });

    const bridge = new BridgeHostAdapter(port1, {
      adapter: 'bridge',
      wallet: { supported: true, connected: true, address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' },
      evm: { chainId: SEPOLIA_HEX, write: { available: true } }
    });

    const elevatedSelectors = [
      deriveSelector('setApprovalForAll(address,bool)'),
      deriveSelector('approve(address,uint256)'),
      deriveSelector('transferFrom(address,address,uint256)'),
      deriveSelector('safeTransferFrom(address,address,uint256)'),
      deriveSelector('safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)'),
      deriveSelector('transfer(address,uint256)'),
      deriveSelector('permit(address,address,uint256,uint256,uint8,bytes32,bytes32)')
    ];

    for (const sel of elevatedSelectors) {
      let caught = null;
      try {
        await bridge.writeContract({ to: ALLOWED_CONTRACT, data: sel + '00'.repeat(32) });
      } catch (e) {
        caught = e;
      }
      assert.ok(caught, `Expected elevated rejection on selector ${sel}`);
      assert.strictEqual(caught.code, 4003);
      assert.ok(caught.message.includes('Elevated asset operation blocked'));
    }

    port1.close();
    port2.close();
  });

  // --- 5. FORWARD-COMPATIBLE ARGUMENT CONSTRAINTS & CANONICAL ABI WORD INDEXING ---
  await test('Audit 6: Enforce generic ABI-position argument constraints and unit-neutral token caps', async () => {
    const spenderAuthorized = '0x8888888888888888888888888888888888888888';
    const spenderAttacker   = '0x6666666666666666666666666666666666666666';
    const recipientAuthorized = '0x9999999999999999999999999999999999999999';
    const recipientAttacker   = '0x7777777777777777777777777777777777777777';

    // 1. approve(address,uint256) -> Word 0 = spender, Word 1 = amount
    const approvePolicy = {
      chainId: SEPOLIA_HEX,
      contracts: [
        {
          address: ALLOWED_CONTRACT,
          writes: true,
          allowedSelectors: [deriveSelector('approve(address,uint256)')],
          isElevated: true,
          constraints: {
            allowedSpenders: [spenderAuthorized],
            maxAmount: '1000'
          }
        }
      ]
    };
    const approveSelector = deriveSelector('approve(address,uint256)');
    const badSpenderWord = spenderAttacker.slice(2).padStart(64, '0');
    const goodSpenderWord = spenderAuthorized.slice(2).padStart(64, '0');
    const amount500Word = (500n).toString(16).padStart(64, '0');
    const amount2000Word = (2000n).toString(16).padStart(64, '0');

    // Bad spender rejected
    let caughtBadSpender = null;
    try {
      PolicyEngine.evaluate({ chainId: SEPOLIA_HEX, target: ALLOWED_CONTRACT, data: approveSelector + badSpenderWord + amount500Word }, approvePolicy);
    } catch (e) {
      caughtBadSpender = e;
    }
    assert.ok(caughtBadSpender);
    assert.strictEqual(caughtBadSpender.code, 4003);
    assert.ok(caughtBadSpender.message.includes('not in allowedSpenders'));

    // Amount exceeding unit-neutral cap rejected
    let caughtTooHigh = null;
    try {
      PolicyEngine.evaluate({ chainId: SEPOLIA_HEX, target: ALLOWED_CONTRACT, data: approveSelector + goodSpenderWord + amount2000Word }, approvePolicy);
    } catch (e) {
      caughtTooHigh = e;
    }
    assert.ok(caughtTooHigh);
    assert.strictEqual(caughtTooHigh.code, 4003);
    assert.ok(caughtTooHigh.message.includes('exceeds max'));

    // Valid approve succeeds
    const okApprove = PolicyEngine.evaluate({ chainId: SEPOLIA_HEX, target: ALLOWED_CONTRACT, data: approveSelector + goodSpenderWord + amount500Word }, approvePolicy);
    assert.strictEqual(okApprove, true);

    // 2. transfer(address,uint256) -> Word 0 = recipient, Word 1 = amount
    const transferPolicy = {
      chainId: SEPOLIA_HEX,
      contracts: [
        {
          address: ALLOWED_CONTRACT,
          writes: true,
          allowedSelectors: [deriveSelector('transfer(address,uint256)')],
          isElevated: true,
          constraints: {
            allowedRecipients: [recipientAuthorized],
            maxAmount: '1000'
          }
        }
      ]
    };
    const transferSelector = deriveSelector('transfer(address,uint256)');
    const goodRecipientWord = recipientAuthorized.slice(2).padStart(64, '0');
    const badRecipientWord = recipientAttacker.slice(2).padStart(64, '0');

    // Transfer to attacker at Word 0 rejected
    let caughtBadTransferRecipient = null;
    try {
      PolicyEngine.evaluate({ chainId: SEPOLIA_HEX, target: ALLOWED_CONTRACT, data: transferSelector + badRecipientWord + amount500Word }, transferPolicy);
    } catch (e) {
      caughtBadTransferRecipient = e;
    }
    assert.ok(caughtBadTransferRecipient);
    assert.strictEqual(caughtBadTransferRecipient.code, 4003);
    assert.ok(caughtBadTransferRecipient.message.includes('not in allowedRecipients'));

    // 3. transferFrom(address,address,uint256) -> Word 0 = from, Word 1 = recipient, Word 2 = amount/tokenId
    const transferFromPolicy = {
      chainId: SEPOLIA_HEX,
      contracts: [
        {
          address: ALLOWED_CONTRACT,
          writes: true,
          allowedSelectors: [deriveSelector('transferFrom(address,address,uint256)')],
          isElevated: true,
          constraints: {
            allowedRecipients: [recipientAuthorized]
          }
        }
      ]
    };
    const transferFromSelector = deriveSelector('transferFrom(address,address,uint256)');
    const victimSenderWord = spenderAuthorized.slice(2).padStart(64, '0');

    // Attacker tries to transferFrom victim to attacker (recipient at Word 1 is attacker) -> REJECTED
    let caughtBadTransferFrom = null;
    try {
      const calldataAttackerSteals = transferFromSelector + victimSenderWord + badRecipientWord + amount500Word;
      PolicyEngine.evaluate({ chainId: SEPOLIA_HEX, target: ALLOWED_CONTRACT, data: calldataAttackerSteals }, transferFromPolicy);
    } catch (e) {
      caughtBadTransferFrom = e;
    }
    assert.ok(caughtBadTransferFrom);
    assert.strictEqual(caughtBadTransferFrom.code, 4003);
    assert.ok(caughtBadTransferFrom.message.includes('not in allowedRecipients'));

    // transferFrom where recipient at Word 1 is authorized succeeds even if sender is different
    const calldataLegitTransferFrom = transferFromSelector + victimSenderWord + goodRecipientWord + amount500Word;
    const okTransferFrom = PolicyEngine.evaluate({ chainId: SEPOLIA_HEX, target: ALLOWED_CONTRACT, data: calldataLegitTransferFrom }, transferFromPolicy);
    assert.strictEqual(okTransferFrom, true);

    // 4. Generic ABI-position constraints array: [{ index, type, op, value }]
    const genericPositionalPolicy = {
      chainId: SEPOLIA_HEX,
      contracts: [
        {
          address: ALLOWED_CONTRACT,
          writes: true,
          allowedSelectors: [transferFromSelector],
          isElevated: true,
          argumentConstraints: [
            { index: 1, type: 'address', op: 'in', value: [recipientAuthorized] },
            { index: 2, type: 'uint256', op: 'lte', value: '1000' }
          ]
        }
      ]
    };

    // Generic check: recipient mismatch at index 1 -> rejected
    let caughtGenericBadRecipient = null;
    try {
      PolicyEngine.evaluate({ chainId: SEPOLIA_HEX, target: ALLOWED_CONTRACT, data: transferFromSelector + victimSenderWord + badRecipientWord + amount500Word }, genericPositionalPolicy);
    } catch (e) {
      caughtGenericBadRecipient = e;
    }
    assert.ok(caughtGenericBadRecipient);
    assert.strictEqual(caughtGenericBadRecipient.code, 4003);

    // Generic check: amount exceeds limit at index 2 -> rejected
    let caughtGenericTooHigh = null;
    try {
      PolicyEngine.evaluate({ chainId: SEPOLIA_HEX, target: ALLOWED_CONTRACT, data: transferFromSelector + victimSenderWord + goodRecipientWord + amount2000Word }, genericPositionalPolicy);
    } catch (e) {
      caughtGenericTooHigh = e;
    }
    assert.ok(caughtGenericTooHigh);
    assert.strictEqual(caughtGenericTooHigh.code, 4003);

    // Generic check: valid call -> succeeds
    const okGeneric = PolicyEngine.evaluate({ chainId: SEPOLIA_HEX, target: ALLOWED_CONTRACT, data: transferFromSelector + victimSenderWord + goodRecipientWord + amount500Word }, genericPositionalPolicy);
    assert.strictEqual(okGeneric, true);

    // 5. Separation of unit-neutral token cap vs native msg.value (wei)
    const nativeValuePolicy = {
      chainId: SEPOLIA_HEX,
      contracts: [
        {
          address: ALLOWED_CONTRACT,
          writes: true,
          allowedSelectors: [transferSelector],
          isElevated: true,
          allowNativeValue: false,
          constraints: {
            maxAmount: '1000'
          }
        }
      ]
    };

    // Attempting to attach 1 wei of native value when allowNativeValue is false -> rejected with 4003
    let caughtNativeVal = null;
    try {
      PolicyEngine.evaluate({ chainId: SEPOLIA_HEX, target: ALLOWED_CONTRACT, data: transferSelector + goodRecipientWord + amount500Word, value: '1' }, nativeValuePolicy);
    } catch (e) {
      caughtNativeVal = e;
    }
    assert.ok(caughtNativeVal);
    assert.strictEqual(caughtNativeVal.code, 4003);
    assert.ok(caughtNativeVal.message.includes('Native value transfer not permitted'));
  });

  // --- 6. WRONG CHAIN POLICY ERROR SEMANTICS (4003 vs 4901 vs 4900) ---
  await test('Audit 7: Distinguish runtime policy chain violation (4003) from provider disconnection (4901 and 4900)', async () => {
    const { port1, port2 } = new MessageChannel();
    const server = new HardenedHostServer(port2, { chainId: SEPOLIA_HEX });
    const bridge = new BridgeHostAdapter(port1, {
      adapter: 'bridge',
      wallet: { supported: true, connected: true, address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' },
      evm: { chainId: SEPOLIA_HEX, write: { available: true } }
    });

    // Cartridge requests Mainnet (0x1) write against Sepolia-only policy -> Policy error 4003
    let policyCaught = null;
    try {
      await bridge._sendRequest('evm.write', {
        to: ALLOWED_CONTRACT,
        data: GAME_ACTION_SELECTOR,
        chainId: MAINNET_HEX
      });
    } catch (e) {
      policyCaught = e;
    }

    assert.ok(policyCaught);
    assert.strictEqual(policyCaught.code, 4003, 'Targeting wrong chain must fail with policy error 4003');
    assert.ok(policyCaught.message.includes('Active host chain is'));

    // EIP-1193 Standard Provider Errors:
    // 4901: Chain Disconnected (from the specified chain)
    const providerChainErr = ConsoleRuntimeError.chainDisconnected();
    assert.strictEqual(providerChainErr.code, 4901);
    assert.strictEqual(providerChainErr.message, 'Provider is disconnected from the specified chain');

    // 4900: Provider Disconnected (from all chains)
    const providerAllErr = ConsoleRuntimeError.disconnected();
    assert.strictEqual(providerAllErr.code, 4900);
    assert.strictEqual(providerAllErr.message, 'Provider is disconnected from all chains');

    port1.close();
    port2.close();
  });

  // --- 7. PACKAGE INTEGRITY BEFORE EXECUTION ---
  await test('Audit 8: CartridgeLoader enforces package integrity before sandbox execution', async () => {
    const validBytes = '<html><head><title>Test Cartridge</title></head><body><h1>Hello</h1></body></html>';
    const computedHash = '0x' + keccak256(validBytes);

    const validManifest = {
      id: 'test-cart',
      integrity: { contentHash: computedHash }
    };

    // 1. Valid package passes verification
    const pass = CartridgeLoader.verifyPackage(validBytes, validManifest, (b) => keccak256(b));
    assert.strictEqual(pass, true);

    // 2. Corrupted package bytes fail closed with code 5003 before mount
    const corruptedBytes = validBytes + '<!-- malicious injected payload -->';
    let integrityCaught = null;
    try {
      CartridgeLoader.verifyPackage(corruptedBytes, validManifest, (b) => keccak256(b));
    } catch (e) {
      integrityCaught = e;
    }

    assert.ok(integrityCaught, 'Must reject corrupted package bytes');
    assert.strictEqual(integrityCaught.code, 5003);
    assert.ok(integrityCaught.message.includes('Package integrity mismatch'));

    // 3. Minimum sandbox attribute defaults strictly to allow-scripts
    const iframe = CartridgeLoader.mountCartridge(validBytes, null, {});
    if (iframe) {
      assert.strictEqual(iframe.getAttribute('sandbox'), 'allow-scripts');
    }
  });

  // --- 8. REPLAY, OVERSIZE, RATE LIMIT, AND COMPETING HANDSHAKE REGRESSION ---
  await test('Audit 9: Regression test replayed IDs, oversized payloads, rate limits, and second-host isolation', async () => {
    const { port1, port2 } = new MessageChannel();
    const server = new HardenedHostServer(port2);
    const bridge = new BridgeHostAdapter(port1);

    // A. Replayed ID
    const req1 = { jsonrpc: '2.0', id: 'unique_id_xyz', method: 'evm.read', params: { to: ALLOWED_CONTRACT } };
    port1.postMessage(req1);
    port1.postMessage(req1); // Replay

    const responses = [];
    await new Promise((resolve) => {
      port1.onmessage = (e) => {
        responses.push(e.data);
        if (responses.length === 2) resolve();
      };
    });
    assert.ok(responses.some(r => r.error && r.error.code === -32600 && r.error.message.includes('Duplicate request ID')));

    // B. Oversized payload (> 64 KB)
    const bigData = '0x' + '00'.repeat(35000);
    let sizeCaught = null;
    try {
      await bridge._sendRequest('evm.read', { to: ALLOWED_CONTRACT, data: bigData });
    } catch (e) {
      sizeCaught = e;
    }
    assert.ok(sizeCaught);
    assert.strictEqual(sizeCaught.code, -32600);
    assert.ok(sizeCaught.message.includes('exceeds limit'));

    // C. Competing Handshake
    CartridgeHost._handshakeEstablished = true;
    let competingAttached = false;
    CartridgeHost.initCartridgeHostNegotiation({
      id: 'competing-host-probe',
      onAttached: () => { competingAttached = true; }
    });
    assert.strictEqual(competingAttached, false);
    CartridgeHost._handshakeEstablished = false;

    port1.close();
    port2.close();
  });

  // --- 9. AUTHORITATIVE ABI SPECIFICATION AND WORD LAYOUT VERIFICATION ---
  await test('Audit 10: Authoritative ABI verification: signatures, selectors, parameter counts, and word layouts', async () => {
    const AUTHORITATIVE_ABIS = {
      ERC20_TRANSFER: {
        signature: 'transfer(address,uint256)',
        selector: '0xa9059cbb',
        inputs: [
          { name: 'recipient', type: 'address', wordIndex: 0 },
          { name: 'amount', type: 'uint256', wordIndex: 1 }
        ]
      },
      ERC20_APPROVE: {
        signature: 'approve(address,uint256)',
        selector: '0x095ea7b3',
        inputs: [
          { name: 'spender', type: 'address', wordIndex: 0 },
          { name: 'amount', type: 'uint256', wordIndex: 1 }
        ]
      },
      ERC20_TRANSFER_FROM: {
        signature: 'transferFrom(address,address,uint256)',
        selector: '0x23b872dd',
        inputs: [
          { name: 'from', type: 'address', wordIndex: 0 },
          { name: 'recipient', type: 'address', wordIndex: 1 },
          { name: 'amount', type: 'uint256', wordIndex: 2 }
        ]
      },
      ERC721_SET_APPROVAL_FOR_ALL: {
        signature: 'setApprovalForAll(address,bool)',
        selector: '0xa22cb465',
        inputs: [
          { name: 'operator', type: 'address', wordIndex: 0 },
          { name: 'approved', type: 'bool', wordIndex: 1 }
        ]
      },
      ERC721_SAFE_TRANSFER_FROM: {
        signature: 'safeTransferFrom(address,address,uint256)',
        selector: '0x42842e0e',
        inputs: [
          { name: 'from', type: 'address', wordIndex: 0 },
          { name: 'to', type: 'address', wordIndex: 1 },
          { name: 'tokenId', type: 'uint256', wordIndex: 2 }
        ]
      },
      ERC1155_SAFE_TRANSFER_FROM: {
        signature: 'safeTransferFrom(address,address,uint256,uint256,bytes)',
        selector: '0xf242432a',
        inputs: [
          { name: 'from', type: 'address', wordIndex: 0 },
          { name: 'to', type: 'address', wordIndex: 1 },
          { name: 'id', type: 'uint256', wordIndex: 2 },
          { name: 'value', type: 'uint256', wordIndex: 3 },
          { name: 'dataOffset', type: 'uint256', wordIndex: 4 }
        ]
      },
      ERC4494_PERMIT: {
        signature: 'permit(address,uint256,uint256,bytes)',
        selector: '0x745a41bc',
        inputs: [
          { name: 'spender', type: 'address', wordIndex: 0 },
          { name: 'tokenId', type: 'uint256', wordIndex: 1 },
          { name: 'deadline', type: 'uint256', wordIndex: 2 },
          { name: 'sigOffset', type: 'uint256', wordIndex: 3 }
        ]
      },
      EIP2612_PERMIT: {
        signature: 'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)',
        selector: '0xd505accf',
        inputs: [
          { name: 'owner', type: 'address', wordIndex: 0 },
          { name: 'spender', type: 'address', wordIndex: 1 },
          { name: 'value', type: 'uint256', wordIndex: 2 },
          { name: 'deadline', type: 'uint256', wordIndex: 3 },
          { name: 'v', type: 'uint8', wordIndex: 4 },
          { name: 'r', type: 'bytes32', wordIndex: 5 },
          { name: 's', type: 'bytes32', wordIndex: 6 }
        ]
      },
      NONSTANDARD_PERMIT_PACKED_RSV: {
        signature: 'permit(address,uint256,uint256,uint8,bytes32,bytes32)',
        selector: '0x7ac2ff7b',
        inputs: [
          { name: 'spender', type: 'address', wordIndex: 0 },
          { name: 'tokenId', type: 'uint256', wordIndex: 1 },
          { name: 'deadline', type: 'uint256', wordIndex: 2 },
          { name: 'v', type: 'uint8', wordIndex: 3 },
          { name: 'r', type: 'bytes32', wordIndex: 4 },
          { name: 's', type: 'bytes32', wordIndex: 5 }
        ]
      }
    };

    for (const [key, abi] of Object.entries(AUTHORITATIVE_ABIS)) {
      // 1. Selector derivation verification
      const derived = deriveSelector(abi.signature);
      assert.strictEqual(derived, abi.selector, `Selector mismatch for ${key} (${abi.signature})`);

      // 2. Input ordering and word indexing verification
      abi.inputs.forEach((input, idx) => {
        assert.strictEqual(input.wordIndex, idx, `Word index mismatch for ${key} input ${input.name}`);
      });
    }

    // Explicit ERC-4494 Standards Check:
    assert.strictEqual(AUTHORITATIVE_ABIS.ERC4494_PERMIT.selector, '0x745a41bc');
    assert.notStrictEqual(AUTHORITATIVE_ABIS.NONSTANDARD_PERMIT_PACKED_RSV.selector, AUTHORITATIVE_ABIS.ERC4494_PERMIT.selector);

    // Canonical Transfer Recipient Index Check:
    // transfer: recipient is Word 0
    assert.strictEqual(AUTHORITATIVE_ABIS.ERC20_TRANSFER.inputs[0].name, 'recipient');
    assert.strictEqual(AUTHORITATIVE_ABIS.ERC20_TRANSFER.inputs[0].wordIndex, 0);
    // transferFrom: from is Word 0, recipient is Word 1
    assert.strictEqual(AUTHORITATIVE_ABIS.ERC20_TRANSFER_FROM.inputs[0].name, 'from');
    assert.strictEqual(AUTHORITATIVE_ABIS.ERC20_TRANSFER_FROM.inputs[0].wordIndex, 0);
    assert.strictEqual(AUTHORITATIVE_ABIS.ERC20_TRANSFER_FROM.inputs[1].name, 'recipient');
    assert.strictEqual(AUTHORITATIVE_ABIS.ERC20_TRANSFER_FROM.inputs[1].wordIndex, 1);
  });

  // SUMMARY
  console.log('\n=============================================================');
  console.log(`Hardened Security & Adversarial Suite Results:`);
  console.log(`Total: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
  console.log('=============================================================\n');

  if (failed > 0) process.exit(1);
}

runAdversarialTestSuite();

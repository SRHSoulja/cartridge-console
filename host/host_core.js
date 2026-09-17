/**
 * Console Runtime V0.1 - Generic Host Core Controller
 *
 * Implements the generic host runtime boundary, cartridge loader lifecycle,
 * permission gatekeeper (requested vs granted), and isolated MessageChannel bridge.
 *
 * ABSOLUTELY ZERO APPLICATION-SPECIFIC / GAME-SPECIFIC LOGIC.
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    define(['../runtime/cartridge_host_runtime.js', './resolver.js'], factory);
  } else if (typeof module === 'object' && module.exports) {
    const runtime = require('../runtime/cartridge_host_runtime.js');
    const resolver = require('./resolver.js');
    module.exports = factory(runtime, resolver);
  } else {
    root.GenericHostCore = factory(root, root);
  }
}(typeof self !== 'undefined' ? self : this, function(runtimeModule, resolverModule) {

  const {
    ConsoleRuntimeError,
    PolicyEngine,
    normalizeChainId,
    satisfiesSemVer,
    normalizeLog,
    normalizeLogs,
    CartridgeLoader,
    ELEVATED_SELECTORS
  } = runtimeModule;

  const DEFAULT_CHAIN_ID = '0xaa36a7'; // Sepolia (11155111)
  const DEFAULT_RPC = 'https://rpc.ankr.com/eth_sepolia';
  const MAX_PAYLOAD_BYTES = 65536;
  const MAX_CONCURRENT_REQUESTS = 10;
  const RATE_LIMIT_WINDOW_MS = 1000;
  const MAX_REQUESTS_PER_WINDOW = 25;

  // Log filter resource bounds (EIP-1193 / Console Protocol V0.2)
  const MAX_BLOCK_RANGE = 50000;
  const MAX_ADDRESS_COUNT = 100;
  const MAX_TOPICS_COUNT = 4;
  const MAX_TOPIC_OR_COUNT = 50;
  const MAX_LOGS_RETURN_LIMIT = 1000;

  class GenericHostCore {
    constructor(options = {}) {
      this.resolver = options.resolver || null;
      this.rpcUrl = options.rpcUrl !== undefined ? options.rpcUrl : DEFAULT_RPC;
      this.activeChainId = normalizeChainId(options.chainId) || DEFAULT_CHAIN_ID;
      this.activeAccount = options.account || null;
      this.providerName = options.providerName || 'Console Host (Runtime V0.1)';
      this.mockMode = Boolean(options.mockMode);
      this.mockAccount = options.mockAccount || '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
      this.allowUnverifiedDevelopment = Boolean(options.allowUnverifiedDevelopment);
      this.customPermissions = null;
      this.rpcHandler = options.rpcHandler || null;
      this.logsHandler = options.logsHandler || null;
      this.sendTxHandler = options.sendTxHandler || null;
      this.receiptHandler = options.receiptHandler || null;

      // Active Cartridge State
      this.activeCartridge = null;
      this.activeManifest = null;
      this.packageBytes = null;
      this.computedHash = null;
      this.integrityVerified = false;
      this.grantedPolicy = null;

      // Transport & Handshake State
      this.iframe = options.iframe || null;
      this.activePort = null;
      this.handshakeEstablished = false;
      this.handshakeNonce = null;

      // DoS Protection & Rate Limiting
      this.seenRequestIds = new Set();
      this.inFlightCount = 0;
      this.requestTimestamps = [];

      // Keccak-256 Hash Function delegate
      this.keccakFn = options.keccakFn || (typeof window !== 'undefined' && window.keccak256 ? window.keccak256 : null);

      // Event listeners for UI
      this.listeners = {
        log: [],
        status: [],
        wallet: [],
        chain: [],
        policy: []
      };
    }

    on(event, fn) {
      if (this.listeners[event]) this.listeners[event].push(fn);
    }

    emit(event, data) {
      if (this.listeners[event]) {
        this.listeners[event].forEach(fn => {
          try { fn(data); } catch (e) { console.error(`Error in host event listener (${event}):`, e); }
        });
      }
    }

    log(type, method, detail, error = false) {
      const entry = {
        time: new Date().toISOString(),
        type,
        method,
        detail,
        error: !!error
      };
      this.emit('log', entry);
    }

    /**
     * 1. Boot cartridge completely through manifest-driven pipeline
     */
    async loadCartridge(cartridgeId, customPermissions = null) {
      this.emit('status', { state: 'resolving', cartridgeId });
      this.log('HOST', 'RESOLVE', `Resolving cartridge descriptor for: ${cartridgeId}`);

      // A. Terminate previous session if active
      this.teardownActiveCartridge();
      this.customPermissions = customPermissions;

      // B. Resolve Cartridge via Resolver Interface
      if (!this.resolver) {
        throw new Error('No cartridge resolver configured in host');
      }
      const resolved = await this.resolver.resolve(cartridgeId);
      this.activeCartridge = resolved;
      this.activeManifest = resolved.manifest;

      // C. Check Runtime Compatibility with strict SemVer
      const requiredRuntime = resolved.runtimeRequirement || '^0.1.0';
      const HOST_RUNTIME_VERSIONS = ['0.1.0', '0.2.0'];
      const isCompatible = HOST_RUNTIME_VERSIONS.some(v => satisfiesSemVer(v, requiredRuntime));
      if (!isCompatible) {
        const err = ConsoleRuntimeError.runtimeVersionMismatch(requiredRuntime, '0.2.0');
        this.log('HOST', 'COMPATIBILITY_FAIL', err.message, true);
        this.emit('status', { state: 'error', error: err.message });
        throw err;
      }

      // D. Fetch Package Bytes
      this.emit('status', { state: 'fetching', cartridgeId });
      const bytes = await resolved.fetchPackageBytes();
      this.packageBytes = bytes;

      // E. Verify Package Integrity Before Execution (Fail-Closed)
      this.emit('status', { state: 'verifying', cartridgeId });
      if (!this.keccakFn && typeof require === 'function') {
        try {
          const { keccak256 } = require('js-sha3');
          this.keccakFn = (b) => keccak256(b);
        } catch (_) {}
      }

      if (resolved.expectedContentHash) {
        if (!this.keccakFn) {
          this.integrityVerified = false;
          const err = ConsoleRuntimeError.integrityFailure(resolved.expectedContentHash, 'unavailable');
          this.log('SECURITY', 'INTEGRITY_FAIL', 'Keccak-256 implementation unavailable for verification', true);
          this.emit('status', { state: 'integrity_failed', error: err.message });
          throw err;
        }

        this.computedHash = '0x' + this.keccakFn(bytes);
        if (this.computedHash.toLowerCase() !== resolved.expectedContentHash.toLowerCase()) {
          this.integrityVerified = false;
          const err = ConsoleRuntimeError.integrityFailure(resolved.expectedContentHash, this.computedHash);
          this.log('SECURITY', 'INTEGRITY_FAIL', `Expected ${resolved.expectedContentHash}, got ${this.computedHash}`, true);
          this.emit('status', { state: 'integrity_failed', error: err.message });
          throw err;
        }
        this.integrityVerified = true;
        this.log('SECURITY', 'INTEGRITY_PASS', `Hash verified: ${this.computedHash}`);
      } else {
        if (this.allowUnverifiedDevelopment) {
          this.computedHash = 'unverified';
          this.integrityVerified = false;
          this.log('SECURITY', 'UNVERIFIED_DEV', 'Loading unverified package in allowUnverifiedDevelopment mode', true);
        } else {
          this.integrityVerified = false;
          const err = ConsoleRuntimeError.integrityFailure('missing_content_hash', 'unhashed');
          this.log('SECURITY', 'INTEGRITY_FAIL', 'Missing expected package content hash in production mode', true);
          this.emit('status', { state: 'integrity_failed', error: err.message });
          throw err;
        }
      }

      // F. Evaluate Requested vs Granted Permissions (writes default DENIED)
      this.grantedPolicy = this.computeGrantedPolicy(resolved.manifest, customPermissions);
      this.emit('policy', {
        requested: resolved.manifest.permissions,
        granted: this.grantedPolicy
      });
      this.log('HOST', 'POLICY_INITIALIZED', `Granted policy computed for chain ${this.grantedPolicy.chainId} (supported: ${this.grantedPolicy.isChainSupported})`);

      // G. Mount Sandbox (iframe with minimal sandbox="allow-scripts")
      this.emit('status', { state: 'mounting', cartridgeId });
      this.mountSandbox(bytes);

      this.emit('status', {
        state: this.integrityVerified ? 'ready' : 'unverified-development',
        cartridgeId,
        name: resolved.name,
        version: resolved.version,
        verified: this.integrityVerified
      });

      return {
        id: resolved.id,
        name: resolved.name,
        manifest: resolved.manifest,
        verified: this.integrityVerified,
        grantedPolicy: this.grantedPolicy
      };
    }

    /**
     * Translates manifest requested permissions into hardened GrantedContractPolicy.
     * Enforces strict permission subsetting (granted ⊆ requested):
     * - Manifest V1 permissions.chains (CAIP-2) is authoritative
     * - If active host chain is outside requested permissions.chains, writes and selectors are denied
     * - A cartridge cannot grant itself permissions it did not request
     * - Host overrides can restrict or revoke, but cannot widen permissions beyond requested
     * - Granted selectors are the strict intersection of requested and host-allowed selectors
     * - Granted native value limit cannot exceed requested limit
     * - isElevated is false by default and can only be enabled by explicit host override
     * - Argument constraints cannot be loosened
     */
    computeGrantedPolicy(manifest, overrides = null) {
      // Determine requested chains from Manifest V1 permissions.chains or legacy chainId
      let supportedChains = [];
      if (Array.isArray(manifest.permissions?.chains)) {
        supportedChains = manifest.permissions.chains.map(c => {
          const match = String(c).match(/^eip155:(\d+)$/i);
          return match ? normalizeChainId(match[1]) : normalizeChainId(c);
        }).filter(Boolean);
      } else if (manifest.chainId) {
        // Explicit legacy V0 fallback
        const norm = normalizeChainId(manifest.chainId);
        if (norm) supportedChains = [norm];
      }

      // Invariant: active host chain must be included in requested permissions.chains
      const isChainSupported = supportedChains.length > 0 && supportedChains.includes(this.activeChainId);
      const requestedContracts = manifest.permissions?.contracts || [];
      const hostGrants = overrides || {};

      const contracts = requestedContracts.map(req => {
        const address = req.address.toLowerCase();
        const grant = hostGrants[address];

        if (!isChainSupported || !grant) {
          // Invariant: writes default to DENIED without explicit host grant or if chain unsupported
          return {
            address,
            name: req.name || address.substring(0, 8),
            writes: false,
            allowedSelectors: [],
            allowNativeValue: false,
            maxValueWei: '0',
            isElevated: false,
            argumentConstraints: req.argumentConstraints || req.constraints || null
          };
        }

        // Writes: granted ⊆ requested (requires BOTH manifest request AND explicit host grant)
        const writesGranted = Boolean(req.writes) && Boolean(grant.writes);

        // Selectors: strict intersection between requested and host granted selectors
        const reqSelectors = Array.isArray(req.allowedSelectors) ? req.allowedSelectors.map(s => s.toLowerCase()) : [];
        const grantSelectors = Array.isArray(grant.allowedSelectors) ? grant.allowedSelectors.map(s => s.toLowerCase()) : [];
        const grantSet = new Set(grantSelectors);
        const allowedSelectors = writesGranted ? reqSelectors.filter(s => grantSet.has(s)) : [];

        // Native value: requires BOTH manifest request AND explicit host grant
        const allowNativeValue = writesGranted && Boolean(req.allowNativeValue) && Boolean(grant.allowNativeValue);
        let maxValueWei = '0';
        if (allowNativeValue) {
          const reqMax = BigInt(req.maxValueWei || '0');
          const grantMax = grant.maxValueWei !== undefined ? BigInt(grant.maxValueWei) : reqMax;
          maxValueWei = (grantMax < reqMax ? grantMax : reqMax).toString();
        }

        // Elevated operations: requires BOTH manifest request AND explicit host grant
        const isElevated = writesGranted && Boolean(req.isElevated) && Boolean(grant.isElevated);

        // Argument constraints: preserve requested constraints, cannot be loosened
        const argumentConstraints = req.argumentConstraints || req.constraints || null;

        return {
          address,
          name: req.name || address.substring(0, 8),
          writes: writesGranted,
          allowedSelectors,
          allowNativeValue,
          maxValueWei,
          isElevated,
          argumentConstraints
        };
      });

      return {
        chainId: this.activeChainId,
        isChainSupported,
        supportedChains,
        contracts
      };
    }

    /**
     * Mounts cartridge into sandboxed iframe and prepares MessageChannel handshake
     */
    mountSandbox(packageBytes) {
      if (!this.iframe && typeof document !== 'undefined') {
        this.iframe = document.getElementById('cartridgeFrame');
      }

      if (this.iframe) {
        // Enforce strict minimal sandbox (NEVER allow-same-origin)
        this.iframe.setAttribute('sandbox', 'allow-scripts');
        this.setupHandshakeListener();
        if (typeof packageBytes === 'string') {
          this.iframe.srcdoc = packageBytes;
        } else if (packageBytes instanceof Uint8Array && typeof URL !== 'undefined' && typeof Blob !== 'undefined') {
          const mediaType = this.activeManifest?.entry?.mediaType || 'text/html';
          const blob = new Blob([packageBytes], { type: mediaType });
          this.iframe.src = URL.createObjectURL(blob);
        }
      }
    }

    /**
     * Listens for the cartridge's handshake probe and binds the MessagePort
     */
    setupHandshakeListener() {
      if (typeof window === 'undefined') return;

      this.handshakeEstablished = false;
      let randHex = '';
      if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        const buf = new Uint8Array(16);
        crypto.getRandomValues(buf);
        randHex = Array.from(buf, b => b.toString(16).padStart(2, '0')).join('');
      } else if (typeof require === 'function') {
        try {
          const { randomBytes } = require('crypto');
          randHex = randomBytes(16).toString('hex');
        } catch (_) {}
      }
      if (!randHex) {
        throw new Error('CSPRNG unavailable: cannot generate secure handshake nonce');
      }
      this.handshakeNonce = 'hs_' + randHex;

      const onWindowMessage = (event) => {
        // 1. Source Window Verification
        if (this.iframe && event.source !== this.iframe.contentWindow) return;

        const data = event.data;
        if (!data || typeof data !== 'object') return;

        // 2. Handshake Probe Handling
        if (data.type === 'cartridge:handshake') {
          if (this.handshakeEstablished) {
            this.log('SECURITY', 'REDUNDANT_HANDSHAKE', 'Handshake already active; dropping probe', true);
            return;
          }

          this.log('BRIDGE', 'HANDSHAKE_RECEIVED', `Initiating isolated MessagePort channel (nonce: ${this.handshakeNonce})`);
          const channel = new MessageChannel();
          this.activePort = channel.port1;
          this.bindPortRpc(this.activePort);

          // Transmit port2 and nonce acknowledgment to cartridge
          event.source.postMessage({
            type: 'cartridge:handshake:ack',
            nonce: this.handshakeNonce,
            capabilities: this.getCapabilities()
          }, '*', [channel.port2]);

          this.handshakeEstablished = true;
          window.removeEventListener('message', onWindowMessage);
          this.log('BRIDGE', 'HANDSHAKE_COMPLETE', 'Privileged RPC bound to MessagePort channel');
        }
      };

      window.addEventListener('message', onWindowMessage);
    }

    /**
     * Binds RPC dispatcher to the MessagePort
     */
    bindPortRpc(port) {
      port.onmessage = async (event) => {
        const raw = event.data;
        if (!raw || typeof raw !== 'object') return;

        const res = await this.handleRpcMessage(raw);
        if (res && port) {
          port.postMessage(res);
        }
      };
    }

    /**
     * Core RPC Message Dispatcher
     * Evaluates policy boundaries, payload limits, rate limits, and routes EVM operations
     */
    async handleRpcMessage(req) {
      const { id, method, params } = req;

      // 1. Payload size check (64 KB DoS protection)
      const serialized = JSON.stringify(req);
      if (serialized.length > MAX_PAYLOAD_BYTES) {
        this.log('SECURITY', 'PAYLOAD_OVERSIZE', `Rejected request ${id}: size ${serialized.length}B exceeds 64KB`, true);
        return { jsonrpc: '2.0', id, error: { code: -32600, message: 'Payload size exceeds limit' } };
      }

      // 2. Replayed request ID protection
      if (id) {
        if (this.seenRequestIds.has(id)) {
          this.log('SECURITY', 'DUPLICATE_ID', `Rejected replayed request ID: ${id}`, true);
          return { jsonrpc: '2.0', id, error: { code: -32600, message: `Duplicate request ID: ${id}` } };
        }
        this.seenRequestIds.add(id);
      }

      // 3. Concurrency limit check
      if (this.inFlightCount >= MAX_CONCURRENT_REQUESTS) {
        this.log('RATE_LIMIT', 'CONCURRENCY_EXCEEDED', `Max concurrent in-flight requests (${MAX_CONCURRENT_REQUESTS}) exceeded`, true);
        return { jsonrpc: '2.0', id, error: { code: -32005, message: 'Max concurrent requests exceeded' } };
      }

      // 4. Rate limiting check
      const now = Date.now();
      this.requestTimestamps = this.requestTimestamps.filter(t => now - t < RATE_LIMIT_WINDOW_MS);
      if (this.requestTimestamps.length >= MAX_REQUESTS_PER_WINDOW) {
        this.log('RATE_LIMIT', 'RATE_EXCEEDED', `Rate limit (${MAX_REQUESTS_PER_WINDOW}/sec) exceeded`, true);
        return { jsonrpc: '2.0', id, error: { code: -32005, message: 'Request rate limit exceeded' } };
      }
      this.requestTimestamps.push(now);

      this.inFlightCount++;
      this.log('RPC_IN', method, JSON.stringify(params || {}));

      try {
        let result = null;

        switch (method) {
          case 'runtime.capabilities':
            result = this.getCapabilities();
            break;

          case 'wallet.address':
            result = this.activeAccount;
            break;

          case 'wallet.connect':
            if (!this.activeAccount) {
              await this.connectWallet();
            }
            result = [this.activeAccount];
            break;

          case 'wallet.disconnect':
            this.disconnectWallet();
            result = true;
            break;

          case 'evm.read': {
            const { to, data } = params || {};
            result = await this.executeEthCall(to, data);
            break;
          }

          case 'evm.write': {
            const { to, data, value, chainId } = params || {};

            // A. Account Check
            if (!this.activeAccount) {
              throw ConsoleRuntimeError.unauthorized('Wallet not connected in host console');
            }

            // B. Chain ID Canonical Check & Policy Support Check
            const reqChain = normalizeChainId(chainId) || this.activeChainId;
            if (reqChain !== this.activeChainId) {
              throw ConsoleRuntimeError.policyViolation(`Active host chain is ${this.activeChainId}, but write targeted ${reqChain}`);
            }

            // C. PolicyEngine Primary & Defense-in-Depth Validation
            if (!this.grantedPolicy) {
              throw ConsoleRuntimeError.policyViolation('No granted policy active on host');
            }
            if (!this.grantedPolicy.isChainSupported) {
              throw ConsoleRuntimeError.policyViolation(`Chain ${this.activeChainId} is not supported by active cartridge permissions`);
            }
            PolicyEngine.evaluate({ chainId: reqChain, target: to, data, value }, this.grantedPolicy);

            // D. Dispatch Transaction to Active Signer
            result = await this.executeSendTransaction({ to, data, value });
            break;
          }

          case 'evm.receipt': {
            const { txHash } = params || {};
            result = await this.fetchReceipt(txHash);
            break;
          }

          case 'evm.logs': {
            const { chainId, ...filter } = params || {};
            const reqChain = normalizeChainId(chainId) || this.activeChainId;
            if (reqChain !== this.activeChainId) {
              throw ConsoleRuntimeError.policyViolation(`Active host chain is ${this.activeChainId}, but logs requested chain ${reqChain}`);
            }
            if (this.grantedPolicy && !this.grantedPolicy.isChainSupported) {
              throw ConsoleRuntimeError.policyViolation(`Chain ${this.activeChainId} is not supported by active cartridge permissions`);
            }
            result = await this.executeGetLogs(filter);
            break;
          }

          default:
            throw ConsoleRuntimeError.unsupportedMethod(method);
        }

        this.log('RPC_OUT', method, typeof result === 'object' ? JSON.stringify(result) : String(result));
        return { jsonrpc: '2.0', id, result };

      } catch (e) {
        this.log('RPC_ERR', method, e.message, true);
        return {
          jsonrpc: '2.0',
          id,
          error: {
            code: e.code || -32603,
            message: e.message
          }
        };
      } finally {
        this.inFlightCount--;
      }
    }

    async executeEthCall(to, data) {
      if (this.rpcHandler) {
        return await this.rpcHandler({ to, data });
      }
      if (typeof fetch === 'function' && this.rpcUrl) {
        try {
          const resp = await fetch(this.rpcUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id: 1,
              method: 'eth_call',
              params: [{ to, data }, 'latest']
            })
          });
          if (resp.ok) {
            const json = await resp.json();
            if (json && json.result) return json.result;
            if (json && json.error) throw new Error(json.error.message || 'RPC eth_call error');
          }
        } catch (e) {
          if (!this.mockMode) throw e;
        }
      }
      if (this.mockMode) {
        return '0x0000000000000000000000000000000000000000000000000000000000000001';
      }
      throw ConsoleRuntimeError.disconnected('RPC eth_call unavailable');
    }

    /**
     * Submits on-chain transaction via injected provider, explicit sendTxHandler, or mock simulator
     */
    async executeSendTransaction({ to, data, value }) {
      if (this.sendTxHandler) {
        return await this.sendTxHandler({ to, data, value });
      }
      if (typeof window !== 'undefined' && window.ethereum && this.activeAccount && !this.activeAccount.startsWith('0xsimulated')) {
        return await window.ethereum.request({
          method: 'eth_sendTransaction',
          params: [{
            from: this.activeAccount,
            to,
            data,
            value: value || '0x0'
          }]
        });
      }
      if (this.mockMode) {
        let randHex = '';
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
          const arr = new Uint8Array(32);
          crypto.getRandomValues(arr);
          randHex = Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
        } else if (typeof require === 'function') {
          try {
            const { randomBytes } = require('crypto');
            randHex = randomBytes(32).toString('hex');
          } catch (_) {}
        }
        if (!randHex) {
          randHex = '00'.repeat(32);
        }
        return '0x' + randHex;
      }
      throw ConsoleRuntimeError.unauthorized('No transaction signer available');
    }

    validateLogFilter(filter) {
      if (typeof filter !== 'object' || filter === null) {
        throw ConsoleRuntimeError.invalidParams('Filter must be an object');
      }

      // BlockHash vs fromBlock/toBlock mutual exclusivity
      if (filter.blockHash !== undefined && filter.blockHash !== null) {
        if (filter.fromBlock !== undefined || filter.toBlock !== undefined) {
          throw ConsoleRuntimeError.invalidParams('blockHash cannot be specified together with fromBlock or toBlock');
        }
      } else {
        const parseBlockNum = (b) => {
          if (typeof b === 'number') return b;
          if (typeof b === 'string' && b.startsWith('0x')) return parseInt(b, 16);
          if (typeof b === 'string' && /^\d+$/.test(b)) return parseInt(b, 10);
          return null;
        };
        const from = parseBlockNum(filter.fromBlock);
        const to = parseBlockNum(filter.toBlock);
        if (from !== null && to !== null && to >= from) {
          const range = to - from;
          if (range > MAX_BLOCK_RANGE) {
            throw ConsoleRuntimeError.invalidParams(`Block range ${range} exceeds maximum allowed range of ${MAX_BLOCK_RANGE}`);
          }
        }
      }

      // Address filter shape and count
      if (filter.address !== undefined && filter.address !== null) {
        if (Array.isArray(filter.address)) {
          if (filter.address.length > MAX_ADDRESS_COUNT) {
            throw ConsoleRuntimeError.invalidParams(`Address filter count ${filter.address.length} exceeds limit of ${MAX_ADDRESS_COUNT}`);
          }
        } else if (typeof filter.address !== 'string') {
          throw ConsoleRuntimeError.invalidParams('Address filter must be a string or array of strings');
        }
      }

      // Topics filter shape and count
      if (filter.topics !== undefined && filter.topics !== null) {
        if (!Array.isArray(filter.topics)) {
          throw ConsoleRuntimeError.invalidParams('Topics filter must be an array');
        }
        if (filter.topics.length > MAX_TOPICS_COUNT) {
          throw ConsoleRuntimeError.invalidParams(`Topics count ${filter.topics.length} exceeds limit of ${MAX_TOPICS_COUNT}`);
        }
        for (const topicItem of filter.topics) {
          if (Array.isArray(topicItem)) {
            if (topicItem.length > MAX_TOPIC_OR_COUNT) {
              throw ConsoleRuntimeError.invalidParams(`Topic OR array count ${topicItem.length} exceeds limit of ${MAX_TOPIC_OR_COUNT}`);
            }
          }
        }
      }
    }

    async executeGetLogs(filter = {}) {
      this.validateLogFilter(filter);

      let logs = [];
      if (this.logsHandler) {
        const raw = await this.logsHandler(filter);
        logs = normalizeLogs(raw || []);
      } else if (typeof window !== 'undefined' && window.ethereum && window.ethereum.request) {
        try {
          const res = await window.ethereum.request({
            method: 'eth_getLogs',
            params: [filter]
          });
          if (Array.isArray(res)) logs = normalizeLogs(res);
        } catch (_) {}
      } else if (typeof fetch === 'function' && this.rpcUrl) {
        try {
          const resp = await fetch(this.rpcUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id: 3,
              method: 'eth_getLogs',
              params: [filter]
            })
          });
          const json = await resp.json();
          if (json && json.result) logs = normalizeLogs(json.result);
          if (json && json.error) throw new Error(json.error.message || 'RPC eth_getLogs error');
        } catch (e) {
          if (!this.mockMode) throw e;
        }
      } else if (this.mockMode) {
        logs = [];
      } else {
        throw ConsoleRuntimeError.disconnected('RPC eth_getLogs unavailable');
      }

      if (logs.length > MAX_LOGS_RETURN_LIMIT) {
        throw ConsoleRuntimeError.invalidParams(`Logs result count ${logs.length} exceeds maximum limit of ${MAX_LOGS_RETURN_LIMIT}`);
      }
      return logs;
    }

    async fetchReceipt(txHash) {
      if (this.receiptHandler) {
        return await this.receiptHandler(txHash);
      }
      if (typeof fetch === 'function' && this.rpcUrl) {
        try {
          const resp = await fetch(this.rpcUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id: 2,
              method: 'eth_getTransactionReceipt',
              params: [txHash]
            })
          });
          if (resp.ok) {
            const json = await resp.json();
            if (json) {
              if (json.error) throw new Error(json.error.message || 'RPC receipt error');
              if (json.result !== undefined) return json.result; // note: null means transaction pending
            }
          }
        } catch (e) {
          if (!this.mockMode) throw e;
        }
      }
      if (this.mockMode) {
        return {
          status: '0x1',
          transactionHash: txHash,
          blockNumber: '0x1000'
        };
      }
      throw ConsoleRuntimeError.disconnected('Unable to fetch transaction receipt: RPC unavailable');
    }

    async connectWallet() {
      if (typeof window !== 'undefined' && window.ethereum) {
        const accs = await window.ethereum.request({ method: 'eth_requestAccounts' });
        this.activeAccount = accs[0];
        this.providerName = window.ethereum.isMetaMask ? 'MetaMask' : (window.ethereum.isPhantom ? 'Phantom' : 'Injected Web3');
      } else if (this.mockMode) {
        this.activeAccount = this.mockAccount || '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
        this.providerName = 'Simulated Dev Signer';
      } else {
        throw ConsoleRuntimeError.unauthorized('No injected Ethereum provider available');
      }

      this.emit('wallet', { account: this.activeAccount, provider: this.providerName });
      this.broadcastEvent('wallet.accountsChanged', { accounts: [this.activeAccount] });
      return this.activeAccount;
    }

    disconnectWallet() {
      this.activeAccount = null;
      this.emit('wallet', { account: null, provider: null });
      this.broadcastEvent('wallet.accountsChanged', { accounts: [] });
    }

    setChainId(newChainId) {
      this.activeChainId = normalizeChainId(newChainId);
      if (this.activeManifest) {
        this.grantedPolicy = this.computeGrantedPolicy(this.activeManifest, this.customPermissions);
        this.emit('policy', {
          requested: this.activeManifest.permissions,
          granted: this.grantedPolicy
        });
      }
      this.emit('chain', { chainId: this.activeChainId });
      this.broadcastEvent('wallet.chainChanged', { chainId: this.activeChainId });
      this.log('HOST', 'CHAIN_CHANGED', `Active chain switched to ${this.activeChainId}`);
    }

    broadcastEvent(method, params) {
      if (this.activePort) {
        this.activePort.postMessage({ method, params });
      }
    }

    getCapabilities() {
      const isChainSupported = this.grantedPolicy ? Boolean(this.grantedPolicy.isChainSupported) : true;
      const writeTargets = this.grantedPolicy && Array.isArray(this.grantedPolicy.contracts)
        ? this.grantedPolicy.contracts.filter(c => c.writes && Array.isArray(c.allowedSelectors) && c.allowedSelectors.length > 0)
        : [];
      const writeAuthorized = Boolean(this.activeAccount && isChainSupported && writeTargets.length > 0);

      return {
        adapter: 'bridge',
        wallet: {
          supported: true,
          connected: !!this.activeAccount,
          address: this.activeAccount,
          providerName: this.providerName
        },
        evm: {
          chainId: this.activeChainId,
          read: { supported: true, available: true },
          write: {
            supported: true,
            available: !!this.activeAccount,
            authorized: writeAuthorized
          }
        },
        signing: !!this.activeAccount,
        contractRead: true,
        contractWrite: writeAuthorized,
        isSandboxed: true
      };
    }

    teardownActiveCartridge() {
      if (this.activePort) {
        try { this.activePort.close(); } catch (_) {}
        this.activePort = null;
      }
      this.handshakeEstablished = false;
      this.handshakeNonce = null;
      this.activeCartridge = null;
      this.activeManifest = null;
      this.packageBytes = null;
      this.computedHash = null;
      this.integrityVerified = false;
      this.grantedPolicy = null;
      this.seenRequestIds.clear();
      this.inFlightCount = 0;
    }
  }

  return {
    GenericHostCore,
    DEFAULT_CHAIN_ID,
    DEFAULT_RPC
  };
}));

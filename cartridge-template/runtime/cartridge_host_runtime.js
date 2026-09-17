/**
 * Console Runtime V0.2.0 Client Module (Hardened)
 * Universal client abstraction for Console Protocol V0.2 and Cartridge Protocol V0.1.
 *
 * Core Security Features:
 *  - Explicit Canonical Selectors derived via Keccak-256
 *  - Primary Fail-Closed Policy Authorization (chain + target + explicit non-empty selectors + value)
 *  - Defense-in-depth Elevated Asset Operation Firewall (Approvals & Transfers)
 *  - Forward-compatible argument constraints (spender, recipient, maxAmount, tokenIds)
 *  - EIP-1193 Hexadecimal Chain Identity (e.g. '0xaa36a7')
 *  - Strict separation of EIP-1193 provider errors (4901 ChainDisconnected, 4900 Disconnected) vs Runtime Policy errors (4003 PolicyViolation)
 *  - Full RFC 8785 JSON Canonicalization Scheme (JCS) with domain validation
 *  - Strict SemVer 2.0.0 Prerelease Compatibility Evaluator
 *  - Package Integrity Verification Before Execution (CartridgeLoader)
 *  - Fail-closed CSPRNG handshake nonce generation
 *  - Minimal Sandbox Permissions (default 'allow-scripts')
 *  - Resource limits & DoS Protection
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    const exports = factory();
    root.CartridgeHost = exports.CartridgeHost;
    root.HoodQuestHost = exports.CartridgeHost; // Backward compatibility alias
    root.DirectHostAdapter = exports.DirectHostAdapter;
    root.BridgeHostAdapter = exports.BridgeHostAdapter;
    root.ConsoleRuntimeError = exports.ConsoleRuntimeError;
    root.PolicyEngine = exports.PolicyEngine;
    root.ELEVATED_SELECTORS = exports.ELEVATED_SELECTORS;
    root.CANONICAL_SIGNATURES = exports.CANONICAL_SIGNATURES;
    root.normalizeChainId = exports.normalizeChainId;
    root.toCaip2ChainId = exports.toCaip2ChainId;
    root.canonicalizeJson = exports.canonicalizeJson;
    root.parseSemVer = exports.parseSemVer;
    root.satisfiesSemVer = exports.satisfiesSemVer;
    root.normalizeLog = exports.normalizeLog;
    root.normalizeLogs = exports.normalizeLogs;
    root.CartridgeLoader = exports.CartridgeLoader;
    root.generateSecureNonce = exports.generateSecureNonce;
  }
}(typeof self !== 'undefined' ? self : this, function() {

  // Canonical Function Signatures for Elevated Operations
  const CANONICAL_SIGNATURES = {
    SET_APPROVAL_FOR_ALL: 'setApprovalForAll(address,bool)',
    APPROVE: 'approve(address,uint256)',
    TRANSFER_FROM: 'transferFrom(address,address,uint256)',
    SAFE_TRANSFER_FROM_ERC721: 'safeTransferFrom(address,address,uint256)',
    SAFE_TRANSFER_FROM_ERC721_DATA: 'safeTransferFrom(address,address,uint256,bytes)',
    SAFE_TRANSFER_FROM_ERC1155: 'safeTransferFrom(address,address,uint256,uint256,bytes)',
    SAFE_BATCH_TRANSFER_FROM_ERC1155: 'safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)',
    TRANSFER: 'transfer(address,uint256)',
    PERMIT_EIP2612: 'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)',
    PERMIT_ERC4494: 'permit(address,uint256,uint256,bytes)',
    NONSTANDARD_PERMIT_ERC721_PACKED_RSV: 'permit(address,uint256,uint256,uint8,bytes32,bytes32)'
  };

  // Exact 4-byte Keccak-256 Selectors for Elevated Operations
  // Verified mathematically against canonical signatures
  const ELEVATED_SELECTORS = new Set([
    '0xa22cb465', // setApprovalForAll(address,bool)
    '0x095ea7b3', // approve(address,uint256)
    '0x23b872dd', // transferFrom(address,address,uint256)
    '0x42842e0e', // safeTransferFrom(address,address,uint256)
    '0xb88d4fde', // safeTransferFrom(address,address,uint256,bytes)
    '0xf242432a', // safeTransferFrom(address,address,uint256,uint256,bytes)
    '0x2eb2c2d6', // safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)
    '0xa9059cbb', // transfer(address,uint256)
    '0xd505accf', // permit(address,address,uint256,uint256,uint8,bytes32,bytes32) [EIP-2612]
    '0x745a41bc', // permit(address,uint256,uint256,bytes) [Canonical ERC-4494]
    '0x7ac2ff7b'  // permit(address,uint256,uint256,uint8,bytes32,bytes32) [Nonstandard packed RSV variant]
  ]);

  // Normalize chain ID to canonical EIP-1193 hex string (e.g. '0xaa36a7', '0x1')
  // Supports both hex strings, integers, and CAIP-2 identifiers (e.g. 'eip155:11155111')
  function normalizeChainId(chainId) {
    if (chainId === null || chainId === undefined) return null;
    if (typeof chainId === 'string') {
      if (chainId.startsWith('eip155:')) {
        return '0x' + BigInt(chainId.slice(7)).toString(16).toLowerCase();
      }
      if (chainId.startsWith('0x') || chainId.startsWith('0X')) {
        return '0x' + BigInt(chainId).toString(16).toLowerCase();
      }
      return '0x' + BigInt(chainId).toString(16).toLowerCase();
    }
    if (typeof chainId === 'number' || typeof chainId === 'bigint') {
      return '0x' + BigInt(chainId).toString(16).toLowerCase();
    }
    return null;
  }

  // Convert EIP-1193 hex chain ID to CAIP-2 identifier (e.g. '0xaa36a7' -> 'eip155:11155111')
  function toCaip2ChainId(chainId) {
    const hex = normalizeChainId(chainId);
    if (!hex) return null;
    return 'eip155:' + BigInt(hex).toString(10);
  }

  // RFC 8785 JSON Canonicalization Scheme (JCS)
  // Deterministic serialization: UTF-16 code unit property sorting, no whitespace, ECMAScript number formatting, domain validation
  function canonicalizeJson(value) {
    if (value === undefined) {
      throw new TypeError('JCS: undefined value is not supported in canonical JSON');
    }
    if (typeof value === 'function') {
      throw new TypeError('JCS: function value is not supported in canonical JSON');
    }
    if (typeof value === 'symbol') {
      throw new TypeError('JCS: symbol value is not supported in canonical JSON');
    }
    if (typeof value === 'bigint') {
      throw new TypeError('JCS: BigInt value is not supported in canonical JSON');
    }
    if (value === null) return 'null';
    if (typeof value === 'boolean') return value ? 'true' : 'false';

    if (typeof value === 'number') {
      if (!Number.isFinite(value)) {
        throw new TypeError('JCS: non-finite number is not supported in canonical JSON');
      }
      if (Object.is(value, -0)) return '0';
      return JSON.stringify(value);
    }

    if (typeof value === 'string') {
      // Validate Unicode: reject lone or unpaired surrogates
      for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i);
        if (code >= 0xD800 && code <= 0xDBFF) {
          if (i + 1 >= value.length) throw new TypeError('JCS: lone high surrogate');
          const next = value.charCodeAt(i + 1);
          if (next < 0xDC00 || next > 0xDFFF) throw new TypeError('JCS: unpaired high surrogate');
          i++;
        } else if (code >= 0xDC00 && code <= 0xDFFF) {
          throw new TypeError('JCS: lone low surrogate');
        }
      }
      return JSON.stringify(value);
    }

    if (Array.isArray(value)) {
      const elements = value.map(v => canonicalizeJson(v));
      return '[' + elements.join(',') + ']';
    }

    if (typeof value === 'object') {
      // Properties are sorted based on their UTF-16 code unit values lexicographically
      const keys = Object.keys(value).sort();
      const pairs = [];
      for (const key of keys) {
        const val = value[key];
        if (val === undefined || typeof val === 'symbol' || typeof val === 'function') {
          throw new TypeError(`JCS: object contains unsupported property type for key "${key}": ${typeof val}`);
        }
        pairs.push(canonicalizeJson(key) + ':' + canonicalizeJson(val));
      }
      return '{' + pairs.join(',') + '}';
    }

    throw new TypeError(`JCS: unsupported type: ${typeof value}`);
  }

  // Strict SemVer 2.0.0 specification regex (disallows leading zeros on numbers)
  const SEMVER_SPEC_REGEX = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

  // Strict SemVer 2.0.0 parser
  function parseSemVer(versionStr) {
    if (typeof versionStr !== 'string') return null;
    const clean = versionStr.trim().replace(/^v/, '');
    const match = clean.match(SEMVER_SPEC_REGEX);
    if (!match) return null;
    return {
      major: parseInt(match[1], 10),
      minor: parseInt(match[2], 10),
      patch: parseInt(match[3], 10),
      prerelease: match[4] || null,
      build: match[5] || null
    };
  }

  function comparePrereleases(preA, preB) {
    if (preA === preB) return 0;
    if (!preA && preB) return 1; // stable (no prerelease) > prerelease
    if (preA && !preB) return -1; // prerelease < stable
    const partsA = preA.split('.');
    const partsB = preB.split('.');
    const len = Math.max(partsA.length, partsB.length);
    for (let i = 0; i < len; i++) {
      if (i >= partsA.length) return -1;
      if (i >= partsB.length) return 1;
      const a = partsA[i];
      const b = partsB[i];
      if (a === b) continue;
      const aNum = /^\d+$/.test(a);
      const bNum = /^\d+$/.test(b);
      if (aNum && bNum) {
        return parseInt(a, 10) - parseInt(b, 10) > 0 ? 1 : -1;
      }
      if (aNum && !bNum) return -1; // numeric identifiers have lower precedence than non-numeric
      if (!aNum && bNum) return 1;
      return a > b ? 1 : -1;
    }
    return 0;
  }

  function compareSemVer(v1, v2) {
    if (v1.major !== v2.major) return v1.major > v2.major ? 1 : -1;
    if (v1.minor !== v2.minor) return v1.minor > v2.minor ? 1 : -1;
    if (v1.patch !== v2.patch) return v1.patch > v2.patch ? 1 : -1;
    return comparePrereleases(v1.prerelease, v2.prerelease);
  }

  // Console Runtime Compatibility Range Profile (strict subset: =, ^, ~, >, >=, <, <=)
  function satisfiesSemVer(targetVersion, rangeStr) {
    const target = parseSemVer(targetVersion);
    if (!target || typeof rangeStr !== 'string') return false;
    const cleanRange = rangeStr.trim();

    let op = '=';
    let baseStr = cleanRange;
    if (cleanRange.startsWith('^') || cleanRange.startsWith('~') || cleanRange.startsWith('=')) {
      op = cleanRange[0];
      baseStr = cleanRange.slice(1);
    } else if (cleanRange.startsWith('>=')) {
      op = '>=';
      baseStr = cleanRange.slice(2);
    } else if (cleanRange.startsWith('<=')) {
      op = '<=';
      baseStr = cleanRange.slice(2);
    } else if (cleanRange.startsWith('>')) {
      op = '>';
      baseStr = cleanRange.slice(1);
    } else if (cleanRange.startsWith('<')) {
      op = '<';
      baseStr = cleanRange.slice(1);
    } else if (/^[0-9]/.test(cleanRange)) {
      op = '=';
      baseStr = cleanRange;
    } else {
      // Unsupported range syntax rejected
      return false;
    }

    const base = parseSemVer(baseStr);
    if (!base) return false;

    // Strict Prerelease Isolation Rule:
    // A prerelease version NEVER satisfies a range unless the range explicitly specified
    // a prerelease on the exact same major.minor.patch tuple.
    if (target.prerelease) {
      if (!base.prerelease) return false;
      if (target.major !== base.major || target.minor !== base.minor || target.patch !== base.patch) {
        return false;
      }
      const cmp = compareSemVer(target, base);
      if (op === '=') return cmp === 0;
      if (op === '>=') return cmp >= 0;
      if (op === '<=') return cmp <= 0;
      if (op === '>') return cmp > 0;
      if (op === '<') return cmp < 0;
      if (op === '^' || op === '~') return cmp >= 0;
      return false;
    }

    // Target is stable release
    if (base.prerelease) {
      if (target.major === base.major && target.minor === base.minor && target.patch === base.patch) {
        // Stable on same tuple satisfies >=, >, ^, ~ of its prereleases
        if (op === '>=' || op === '>' || op === '^' || op === '~') return true;
        return false;
      }
    }

    const cmp = compareSemVer(target, base);
    if (op === '=') return cmp === 0;
    if (op === '>=') return cmp >= 0;
    if (op === '<=') return cmp <= 0;
    if (op === '>') return cmp > 0;
    if (op === '<') return cmp < 0;

    if (op === '^') {
      if (base.major === 0) {
        if (base.minor === 0) {
          return target.major === 0 && target.minor === 0 && target.patch === base.patch;
        }
        return target.major === 0 && target.minor === base.minor && target.patch >= base.patch;
      }
      return target.major === base.major && (
        target.minor > base.minor || (target.minor === base.minor && target.patch >= base.patch)
      );
    }

    if (op === '~') {
      return target.major === base.major && target.minor === base.minor && target.patch >= base.patch;
    }

    return false;
  }

  // Parse 20-byte address from 32-byte ABI word
  function parseAddressFromWord(wordHex) {
    if (!wordHex || wordHex.length < 40) return '';
    return '0x' + wordHex.slice(-40).toLowerCase();
  }

  // Normalize hex string / integer values
  function normalizeHex(value) {
    if (value === null || value === undefined) return null;
    if (typeof value === 'string') {
      if (value.startsWith('0x') || value.startsWith('0X')) {
        return value.toLowerCase();
      }
      return '0x' + BigInt(value).toString(16).toLowerCase();
    }
    if (typeof value === 'number' || typeof value === 'bigint') {
      return '0x' + BigInt(value).toString(16).toLowerCase();
    }
    return null;
  }

  // Normalize EVM event log structure
  function normalizeLog(log) {
    if (!log || typeof log !== 'object') return null;
    return {
      address: (log.address || '').toLowerCase(),
      topics: Array.isArray(log.topics) ? log.topics.map(t => (t || '').toLowerCase()) : [],
      data: log.data || '0x',
      blockNumber: normalizeHex(log.blockNumber),
      blockHash: log.blockHash ? log.blockHash.toLowerCase() : null,
      transactionHash: log.transactionHash ? log.transactionHash.toLowerCase() : null,
      transactionIndex: normalizeHex(log.transactionIndex),
      logIndex: normalizeHex(log.logIndex),
      removed: !!log.removed
    };
  }

  // Normalize an array of EVM event logs
  function normalizeLogs(logs) {
    if (!Array.isArray(logs)) return [];
    return logs.map(normalizeLog).filter(Boolean);
  }

  // Standardized Console Runtime Error Hierarchy
  class ConsoleRuntimeError extends Error {
    constructor(message, code, data) {
      super(message);
      this.name = 'ConsoleRuntimeError';
      this.code = code;
      this.data = data;
    }

    // EIP-1193 Standard Provider Errors
    static userRejected(msg = 'User rejected request') {
      return new ConsoleRuntimeError(msg, 4001);
    }

    static unauthorized(msg = 'Wallet not connected or authorized') {
      return new ConsoleRuntimeError(msg, 4100);
    }

    static unsupportedMethod(method) {
      return new ConsoleRuntimeError(`Unsupported method: ${method}`, 4200);
    }

    static disconnected(msg = 'Provider is disconnected from all chains') {
      return new ConsoleRuntimeError(msg, 4900);
    }

    static chainDisconnected(msg = 'Provider is disconnected from the specified chain') {
      return new ConsoleRuntimeError(msg, 4901);
    }

    // Console Runtime Policy & Boundary Errors (4003)
    static policyViolation(reason) {
      return new ConsoleRuntimeError(`Policy violation: ${reason}`, 4003);
    }

    static targetNotAllowed(target) {
      return new ConsoleRuntimeError(`Unauthorized contract target: ${target}`, 4003);
    }

    static selectorNotAllowed(selector) {
      return new ConsoleRuntimeError(`Unauthorized function selector: ${selector}; must be explicitly declared in granted policy`, 4003);
    }

    static elevatedOperationBlocked(selector) {
      return new ConsoleRuntimeError(`Elevated asset operation blocked (${selector}); requires explicit elevated policy grant`, 4003);
    }

    static constraintViolation(reason) {
      return new ConsoleRuntimeError(`Argument constraint violation: ${reason}`, 4003);
    }

    static nativeValueNotAllowed(val) {
      return new ConsoleRuntimeError(`Native value transfer not permitted (${val} wei); policy forbids native value`, 4003);
    }

    static capabilityNotGranted(cap) {
      return new ConsoleRuntimeError(`Required capability not granted: ${cap}`, 5001);
    }

    static runtimeVersionMismatch(required, actual) {
      return new ConsoleRuntimeError(`Incompatible runtime: requested ${required}, active ${actual}`, 5002);
    }

    static integrityFailure(expected, actual) {
      return new ConsoleRuntimeError(`Package integrity mismatch! Expected ${expected}, computed ${actual}`, 5003);
    }

    // Transport & Limit Errors
    static requestTimeout(method) {
      return new ConsoleRuntimeError(`Cartridge host request timed out (${method})`, -32000);
    }

    static transportUnavailable(msg = 'Host transport unavailable') {
      return new ConsoleRuntimeError(msg, -32001);
    }

    static limitExceeded(msg = 'Resource limit exceeded') {
      return new ConsoleRuntimeError(msg, -32005);
    }

    static payloadTooLarge(size, max) {
      return new ConsoleRuntimeError(`Payload size (${size} bytes) exceeds limit (${max} bytes)`, -32600);
    }

    static duplicateRequestId(id) {
      return new ConsoleRuntimeError(`Duplicate or replayed request ID: ${id}`, -32600);
    }

    static invalidRequest(msg = 'Invalid JSON-RPC request') {
      return new ConsoleRuntimeError(msg, -32600);
    }

    static invalidParams(msg = 'Invalid parameters') {
      return new ConsoleRuntimeError(msg, -32602);
    }
  }

  // --- Policy Engine for Strict Authorization ---
  const PolicyEngine = {
    evaluate({ chainId, target, data, value }, grantedPolicy) {
      if (!target) throw ConsoleRuntimeError.invalidParams('Target address required');
      if (!grantedPolicy || !grantedPolicy.contracts) {
        throw ConsoleRuntimeError.targetNotAllowed(target);
      }

      const normTarget = target.toLowerCase();
      const normChain = normalizeChainId(chainId);

      // 1. Policy-Level Chain ID Check
      if (grantedPolicy.chainId) {
        const normPolicyChain = normalizeChainId(grantedPolicy.chainId);
        if (normChain && normPolicyChain !== normChain) {
          throw ConsoleRuntimeError.policyViolation(`Target chain ${normChain} not permitted by policy chain ${normPolicyChain}`);
        }
      }

      // 2. Find Contract Rule
      const rule = grantedPolicy.contracts.find(r => {
        const addrMatch = (typeof r === 'string' ? r : r.address).toLowerCase() === normTarget;
        if (!addrMatch) return false;
        if (r.chainId) {
          const ruleChain = normalizeChainId(r.chainId);
          if (normChain && ruleChain !== normChain) return false;
        }
        return true;
      });

      if (!rule) {
        throw ConsoleRuntimeError.targetNotAllowed(target);
      }

      // 3. Writes Permission Check
      if (typeof rule === 'object' && rule.writes === false) {
        throw ConsoleRuntimeError.targetNotAllowed(target + ' (writes not permitted)');
      }

      // 4. Extract 4-Byte Function Selector
      const selector = (data && data.length >= 10) ? data.slice(0, 10).toLowerCase() : '0x';

      // 5. PRIMARY AUTHORIZATION: allowedSelectors MUST be explicit and non-empty
      if (!rule.wildcard) {
        if (!rule.allowedSelectors || !Array.isArray(rule.allowedSelectors) || rule.allowedSelectors.length === 0) {
          throw ConsoleRuntimeError.policyViolation(`No allowed selectors declared for write target ${target}; explicit selector allowlist required`);
        }
        const normalizedAllowed = rule.allowedSelectors.map(s => s.toLowerCase());
        if (!normalizedAllowed.includes(selector)) {
          throw ConsoleRuntimeError.selectorNotAllowed(selector);
        }
      }

      // 6. DEFENSE-IN-DEPTH: Elevated Asset Operations Check
      if (ELEVATED_SELECTORS.has(selector)) {
        if (!rule.isElevated && !rule.allowApprovals && !rule.allowTransfers) {
          throw ConsoleRuntimeError.elevatedOperationBlocked(selector);
        }
      }

      // 7. Generic ABI-Position and Argument Constraints Validation
      const constraints = rule.argumentConstraints || rule.constraints;
      if (constraints && data && data.length > 10) {
        const calldataBody = data.slice(10);
        this.validateArgumentConstraints(selector, calldataBody, constraints);
      }

      // 8. Native Value Transfer Check
      const numValue = value ? BigInt(value) : 0n;
      if (numValue > 0n) {
        if (!rule.allowNativeValue) {
          throw ConsoleRuntimeError.nativeValueNotAllowed(numValue.toString());
        }
        if (rule.maxValueWei && numValue > BigInt(rule.maxValueWei)) {
          throw ConsoleRuntimeError.nativeValueNotAllowed(`value ${numValue} exceeds max allowed ${rule.maxValueWei}`);
        }
      }

      return true;
    },

    /**
     * Evaluates a single generic positional argument constraint against calldata:
     * constraint: { index, type, op, value, label? }
     * Word index 0 = chars 0..64 of calldataBody, Word index 1 = chars 64..128, etc.
     */
    evaluatePositionalConstraint(calldataBody, constraint) {
      const { index, type, op, value, label } = constraint;
      if (typeof index !== 'number' || index < 0) {
        throw ConsoleRuntimeError.constraintViolation(`Invalid constraint word index: ${index}`);
      }
      const start = index * 64;
      const end = start + 64;
      if (calldataBody.length < end) {
        throw ConsoleRuntimeError.constraintViolation(`Calldata length too short for argument at word index ${index}`);
      }
      const wordHex = calldataBody.slice(start, end);

      let parsed;
      if (type === 'address') {
        parsed = parseAddressFromWord(wordHex);
      } else if (type === 'uint256') {
        parsed = BigInt('0x' + wordHex);
      } else if (type === 'bool') {
        parsed = BigInt('0x' + wordHex) !== 0n;
      } else if (type === 'bytes32') {
        parsed = '0x' + wordHex.toLowerCase();
      } else {
        throw ConsoleRuntimeError.constraintViolation(`Unsupported constraint argument type: ${type}`);
      }

      const desc = label || `Argument at word index ${index}`;

      switch (op) {
        case 'eq': {
          let match = false;
          if (type === 'address' || type === 'bytes32') {
            match = parsed === String(value).toLowerCase();
          } else if (type === 'uint256') {
            match = parsed === BigInt(value);
          } else if (type === 'bool') {
            match = parsed === Boolean(value);
          }
          if (!match) {
            throw ConsoleRuntimeError.constraintViolation(`${desc} value ${parsed} does not equal expected ${value}`);
          }
          break;
        }

        case 'in': {
          if (!Array.isArray(value)) {
            throw ConsoleRuntimeError.constraintViolation(`Constraint op 'in' requires array value`);
          }
          let match = false;
          if (type === 'address' || type === 'bytes32') {
            const allowed = value.map(v => String(v).toLowerCase());
            match = allowed.includes(parsed);
          } else if (type === 'uint256') {
            const allowed = value.map(v => BigInt(v));
            match = allowed.includes(parsed);
          } else if (type === 'bool') {
            match = value.map(Boolean).includes(parsed);
          }
          if (!match) {
            const listName = label === 'Spender' || label === 'Operator' ? 'allowedSpenders' :
                             label === 'Recipient' ? 'allowedRecipients' :
                             label === 'TokenId' ? 'allowedTokenIds' : 'allowed list';
            throw ConsoleRuntimeError.constraintViolation(`${desc} ${parsed} not in ${listName}`);
          }
          break;
        }

        case 'lte': {
          if (type !== 'uint256') {
            throw ConsoleRuntimeError.constraintViolation(`Constraint op 'lte' only valid on uint256`);
          }
          const max = BigInt(value);
          if (parsed > max) {
            throw ConsoleRuntimeError.constraintViolation(`${desc} ${parsed} exceeds max ${value}`);
          }
          break;
        }

        case 'gte': {
          if (type !== 'uint256') {
            throw ConsoleRuntimeError.constraintViolation(`Constraint op 'gte' only valid on uint256`);
          }
          const min = BigInt(value);
          if (parsed < min) {
            throw ConsoleRuntimeError.constraintViolation(`${desc} ${parsed} below minimum ${value}`);
          }
          break;
        }

        default:
          throw ConsoleRuntimeError.constraintViolation(`Unsupported constraint operator: ${op}`);
      }
    },

    /**
     * Validates argument constraints on calldata.
     * Supports:
     *  - Generic positional constraints: [{ selector?, index, type, op, value }]
     *  - Selector-mapped positional constraints: { [selector]: [{ index, type, op, value }] }
     *  - Unit-neutral typed constraints & canonical ABI mapping for high-level shorthand:
     *      allowedSpenders (Word 0 for approve/setApprovalForAll)
     *      allowedRecipients (Word 0 for transfer, Word 1 for transferFrom/safeTransferFrom)
     *      allowedTokenIds (Word 2 for transferFrom/safeTransferFrom)
     *      maxAmount / maxAmountWei (Word 1 for transfer/approve, Word 2 for transferFrom, Word 3 for ERC1155 safeTransferFrom)
     */
    validateArgumentConstraints(selector, calldataBody, constraints) {
      if (!calldataBody || !constraints) return;

      // 1. If constraints is an Array of generic position constraints
      if (Array.isArray(constraints)) {
        for (const c of constraints) {
          if (!c.selector || c.selector.toLowerCase() === selector.toLowerCase()) {
            this.evaluatePositionalConstraint(calldataBody, c);
          }
        }
        return;
      }

      // 2. If constraints has selector-specific array: constraints[selector]
      if (constraints[selector] && Array.isArray(constraints[selector])) {
        for (const c of constraints[selector]) {
          this.evaluatePositionalConstraint(calldataBody, c);
        }
      }

      // 3. If constraints has generic positional list under args or positional
      if (Array.isArray(constraints.positional)) {
        for (const c of constraints.positional) {
          if (!c.selector || c.selector.toLowerCase() === selector.toLowerCase()) {
            this.evaluatePositionalConstraint(calldataBody, c);
          }
        }
      }
      if (Array.isArray(constraints.args)) {
        for (const c of constraints.args) {
          if (!c.selector || c.selector.toLowerCase() === selector.toLowerCase()) {
            this.evaluatePositionalConstraint(calldataBody, c);
          }
        }
      }

      // 4. Canonical ABI mapping for standard high-level constraints:
      // A. approve(address,uint256) -> Word 0: spender, Word 1: amount
      if (selector === '0x095ea7b3') {
        if (constraints.allowedSpenders) {
          this.evaluatePositionalConstraint(calldataBody, {
            index: 0,
            type: 'address',
            op: 'in',
            value: constraints.allowedSpenders,
            label: 'Spender'
          });
        }
        const maxVal = constraints.maxAmount !== undefined ? constraints.maxAmount : constraints.maxAmountWei;
        if (maxVal !== undefined) {
          this.evaluatePositionalConstraint(calldataBody, {
            index: 1,
            type: 'uint256',
            op: 'lte',
            value: maxVal,
            label: 'Approve amount'
          });
        }
      }
      // B. setApprovalForAll(address,bool) -> Word 0: operator, Word 1: approved
      else if (selector === '0xa22cb465') {
        if (constraints.allowedSpenders) {
          this.evaluatePositionalConstraint(calldataBody, {
            index: 0,
            type: 'address',
            op: 'in',
            value: constraints.allowedSpenders,
            label: 'Operator'
          });
        }
        if (constraints.allowedApproved !== undefined) {
          this.evaluatePositionalConstraint(calldataBody, {
            index: 1,
            type: 'bool',
            op: 'eq',
            value: constraints.allowedApproved,
            label: 'Approved'
          });
        }
      }
      // C. transferFrom(address,address,uint256) -> Word 0: from, Word 1: recipient, Word 2: amount/tokenId
      else if (selector === '0x23b872dd') {
        if (constraints.allowedRecipients) {
          this.evaluatePositionalConstraint(calldataBody, {
            index: 1,
            type: 'address',
            op: 'in',
            value: constraints.allowedRecipients,
            label: 'Recipient'
          });
        }
        if (constraints.allowedTokenIds) {
          this.evaluatePositionalConstraint(calldataBody, {
            index: 2,
            type: 'uint256',
            op: 'in',
            value: constraints.allowedTokenIds,
            label: 'TokenId'
          });
        }
        const maxVal = constraints.maxAmount !== undefined ? constraints.maxAmount : constraints.maxAmountWei;
        if (maxVal !== undefined) {
          this.evaluatePositionalConstraint(calldataBody, {
            index: 2,
            type: 'uint256',
            op: 'lte',
            value: maxVal,
            label: 'Transfer amount'
          });
        }
      }
      // D. safeTransferFrom(address,address,uint256) & with bytes -> Word 0: from, Word 1: recipient, Word 2: tokenId
      else if (selector === '0x42842e0e' || selector === '0xb88d4fde') {
        if (constraints.allowedRecipients) {
          this.evaluatePositionalConstraint(calldataBody, {
            index: 1,
            type: 'address',
            op: 'in',
            value: constraints.allowedRecipients,
            label: 'Recipient'
          });
        }
        if (constraints.allowedTokenIds) {
          this.evaluatePositionalConstraint(calldataBody, {
            index: 2,
            type: 'uint256',
            op: 'in',
            value: constraints.allowedTokenIds,
            label: 'TokenId'
          });
        }
      }
      // E. safeTransferFrom ERC-1155 (address,address,uint256,uint256,bytes) -> Word 0: from, Word 1: to, Word 2: id, Word 3: value
      else if (selector === '0xf242432a') {
        if (constraints.allowedRecipients) {
          this.evaluatePositionalConstraint(calldataBody, {
            index: 1,
            type: 'address',
            op: 'in',
            value: constraints.allowedRecipients,
            label: 'Recipient'
          });
        }
        if (constraints.allowedTokenIds) {
          this.evaluatePositionalConstraint(calldataBody, {
            index: 2,
            type: 'uint256',
            op: 'in',
            value: constraints.allowedTokenIds,
            label: 'TokenId'
          });
        }
        const maxVal = constraints.maxAmount !== undefined ? constraints.maxAmount : constraints.maxAmountWei;
        if (maxVal !== undefined) {
          this.evaluatePositionalConstraint(calldataBody, {
            index: 3,
            type: 'uint256',
            op: 'lte',
            value: maxVal,
            label: 'Transfer amount'
          });
        }
      }
      // F. transfer(address,uint256) -> Word 0: recipient, Word 1: amount
      else if (selector === '0xa9059cbb') {
        if (constraints.allowedRecipients) {
          this.evaluatePositionalConstraint(calldataBody, {
            index: 0,
            type: 'address',
            op: 'in',
            value: constraints.allowedRecipients,
            label: 'Recipient'
          });
        }
        const maxVal = constraints.maxAmount !== undefined ? constraints.maxAmount : constraints.maxAmountWei;
        if (maxVal !== undefined) {
          this.evaluatePositionalConstraint(calldataBody, {
            index: 1,
            type: 'uint256',
            op: 'lte',
            value: maxVal,
            label: 'Transfer amount'
          });
        }
      }
    }
  };

  const DEFAULT_RPC = 'https://rpc.ankr.com/eth_sepolia';
  const DEFAULT_CHAIN_ID = '0xaa36a7'; // Sepolia (11155111)
  const MAX_PAYLOAD_BYTES = 65536;     // 64 KB limit
  const MAX_CONCURRENT_REQUESTS = 10;
  const RATE_LIMIT_WINDOW_MS = 1000;
  const MAX_REQUESTS_PER_WINDOW = 25;

  function isSandboxedIframe() {
    if (typeof window === 'undefined') return false;
    try {
      if (window.self === window.top) return false;
      return window.origin === 'null' || !window.location.origin || window.location.origin === 'null';
    } catch (_) {
      return true;
    }
  }

  function getInjectedProvider() {
    if (typeof window === 'undefined') return null;
    if (window.ethereum) return window.ethereum;
    if (window.phantom && window.phantom.ethereum) return window.phantom.ethereum;
    return null;
  }

  function generateSecureNonce(prefix = 'hs_') {
    let c = null;
    if (typeof crypto !== 'undefined') {
      c = crypto;
    } else if (typeof globalThis !== 'undefined' && globalThis.crypto) {
      c = globalThis.crypto;
    } else if (typeof require === 'function') {
      try {
        c = require('crypto');
      } catch (_) {}
    }
    if (c) {
      if (typeof c.randomUUID === 'function') return prefix + c.randomUUID();
      if (typeof c.getRandomValues === 'function') {
        const arr = new Uint8Array(16);
        c.getRandomValues(arr);
        return prefix + Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
      }
      if (typeof c.randomBytes === 'function') {
        return prefix + c.randomBytes(16).toString('hex');
      }
    }
    throw new Error('CSPRNG unavailable: cannot generate secure nonce');
  }

  // --- CAIP-19 Asset Identification & Launch Context V1 ---
  const CAIP19_REGEX = /^([-a-z0-9]{3,8}):([-_a-zA-Z0-9]{1,32})\/([-a-z0-9]{3,8}):(0x[0-9a-fA-F]{40}|[-_a-zA-Z0-9]{1,64})(?:\/([-_a-zA-Z0-9]{1,78}))?$/;
  const MAX_LAUNCH_CONTEXT_BYTES = 1024;
  const ROUTE_REGEX = /^[a-zA-Z0-9:_\-\/]+$/;

  function parseCaip19(uri) {
    if (typeof uri !== 'string') return null;
    const match = CAIP19_REGEX.exec(uri);
    if (!match) return null;
    return {
      chainId: `${match[1]}:${match[2]}`,
      chainNamespace: match[1],
      chainReference: match[2],
      assetNamespace: match[3],
      assetReference: match[4],
      tokenId: match[5] || null
    };
  }

  function validateLaunchContext(context) {
    if (!context || typeof context !== 'object' || Array.isArray(context)) {
      throw new TypeError('launchContext must be a non-null plain object');
    }

    const serialized = JSON.stringify(context);
    if (serialized.length > MAX_LAUNCH_CONTEXT_BYTES) {
      throw new RangeError(`launchContext exceeds maximum size of ${MAX_LAUNCH_CONTEXT_BYTES} bytes`);
    }

    if (context.version !== '1') {
      throw new Error(`Invalid launchContext version: expected "1", got "${context.version}"`);
    }

    if (context.resource !== undefined) {
      if (typeof context.resource !== 'string') {
        throw new TypeError('launchContext.resource must be a string');
      }
      const parsed = parseCaip19(context.resource);
      if (!parsed) {
        throw new Error(`Invalid CAIP-19 resource identifier: "${context.resource}"`);
      }
    }

    if (context.route !== undefined) {
      if (typeof context.route !== 'string' || context.route.length > 64 || !ROUTE_REGEX.test(context.route)) {
        throw new Error(`Invalid launchContext.route: "${context.route}". Must be <= 64 chars matching ${ROUTE_REGEX}`);
      }
    }

    if (context.params !== undefined) {
      if (!context.params || typeof context.params !== 'object' || Array.isArray(context.params)) {
        throw new TypeError('launchContext.params must be a plain object');
      }
      const keys = Object.keys(context.params);
      if (keys.length > 10) {
        throw new RangeError('launchContext.params cannot have more than 10 keys');
      }
      for (const k of keys) {
        const v = context.params[k];
        const t = typeof v;
        if (t !== 'string' && t !== 'number' && t !== 'boolean') {
          throw new TypeError(`launchContext.params["${k}"] must be a string, number, or boolean`);
        }
      }
    }

    return true;
  }

  function sanitizeLaunchContext(context) {
    if (!context) return null;
    try {
      validateLaunchContext(context);
      const sanitized = { version: '1' };
      if (typeof context.resource === 'string') sanitized.resource = context.resource;
      if (typeof context.route === 'string') sanitized.route = context.route;
      if (context.params && typeof context.params === 'object' && !Array.isArray(context.params)) {
        sanitized.params = { ...context.params };
      }
      return Object.freeze(sanitized);
    } catch (_) {
      return null;
    }
  }

  // --- DirectHostAdapter ---
  class DirectHostAdapter {
    constructor(options = {}) {
      this.name = 'direct';
      this.rpcUrl = options.rpcUrl || DEFAULT_RPC;
      this.canonicalAppUrl = options.canonicalAppUrl || (typeof window !== 'undefined' ? window.location?.href : '');
      this.injectedProvider = options.provider || getInjectedProvider();
      this.activeAccount = null;
      this.activeChainId = normalizeChainId(options.chainId) || DEFAULT_CHAIN_ID;
      this.grantedPolicy = options.grantedPolicy || null;
      this._launchContext = sanitizeLaunchContext(options.launchContext);

      if (this.injectedProvider && this.injectedProvider.on) {
        this.injectedProvider.on('chainChanged', (cId) => {
          this.setChainId(normalizeChainId(cId));
        });
        this.injectedProvider.on('accountsChanged', (accs) => {
          const newAddr = (accs && accs[0]) || null;
          this.setAccount(newAddr);
        });
      }
    }

    getAddress() {
      return this.activeAccount;
    }

    getChainId() {
      return this.activeChainId;
    }

    getLaunchContext() {
      return this._launchContext ? JSON.parse(JSON.stringify(this._launchContext)) : null;
    }

    setAccount(addr) {
      this.activeAccount = addr;
      CartridgeHost._emit('accountsChanged', addr);
      CartridgeHost._emit('capabilitiesChanged', this.getCapabilities());
    }

    setChainId(cId) {
      this.activeChainId = normalizeChainId(cId);
      CartridgeHost._emit('chainChanged', this.activeChainId);
      CartridgeHost._emit('capabilitiesChanged', this.getCapabilities());
    }

    getCapabilities() {
      const sandboxed = isSandboxedIframe();
      const hasSigner = !!this.injectedProvider;
      const isConn = !!this.activeAccount;

      return {
        adapter: 'direct',
        wallet: {
          supported: hasSigner && !sandboxed,
          connected: isConn,
          address: this.activeAccount,
          providerName: this.injectedProvider ? 'Injected Provider' : 'None'
        },
        evm: {
          chainId: this.activeChainId,
          read: { supported: true, available: true },
          logs: { supported: true, available: true },
          write: { supported: hasSigner && !sandboxed, available: hasSigner && isConn, authorized: true }
        },
        environment: {
          isSandboxed: sandboxed,
          hasHostBridge: false,
          openExternalApp: sandboxed && !hasSigner,
          canonicalAppUrl: this.canonicalAppUrl
        },
        // Flat compatibility aliases
        signing: hasSigner && isConn,
        contractRead: true,
        contractWrite: hasSigner && isConn,
        openExternalApp: sandboxed && !hasSigner,
        isSandboxed: sandboxed,
        canonicalAppUrl: this.canonicalAppUrl
      };
    }

    async requestAccounts() {
      if (!this.injectedProvider || !this.injectedProvider.request) {
        throw ConsoleRuntimeError.unauthorized('No injected provider available in environment');
      }
      const accounts = await this.injectedProvider.request({ method: 'eth_requestAccounts' });
      if (accounts && accounts[0]) {
        this.setAccount(accounts[0]);
      }
      return accounts;
    }

    async connect(options = {}) {
      const accounts = await this.requestAccounts();
      return accounts[0] || null;
    }

    async disconnect() {
      this.setAccount(null);
    }

    async readContract({ to, data }) {
      if (!to || !data) throw ConsoleRuntimeError.invalidParams('"to" and "data" required');
      if (this.injectedProvider && this.injectedProvider.request) {
        try {
          const res = await this.injectedProvider.request({
            method: 'eth_call',
            params: [{ to, data }, 'latest']
          });
          if (res && res !== '0x') return res;
        } catch (_) {}
      }

      if (typeof fetch === 'function') {
        const resp = await fetch(this.rpcUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: Date.now(),
            method: 'eth_call',
            params: [{ to, data }, 'latest']
          })
        });
        const json = await resp.json();
        if (json.error) throw new Error(json.error.message || 'RPC Error');
        return json.result;
      }
      throw ConsoleRuntimeError.transportUnavailable('No transport available for readContract');
    }

    async getLogs(filter = {}) {
      if (typeof filter !== 'object' || filter === null) {
        throw ConsoleRuntimeError.invalidParams('Filter must be an object');
      }

      if (this.injectedProvider && this.injectedProvider.request) {
        try {
          const res = await this.injectedProvider.request({
            method: 'eth_getLogs',
            params: [filter]
          });
          if (Array.isArray(res)) return normalizeLogs(res);
        } catch (_) {}
      }

      if (typeof fetch === 'function') {
        const resp = await fetch(this.rpcUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: Date.now(),
            method: 'eth_getLogs',
            params: [filter]
          })
        });
        const json = await resp.json();
        if (json.error) throw new Error(json.error.message || 'RPC Error');
        return normalizeLogs(json.result || []);
      }
      throw ConsoleRuntimeError.transportUnavailable('No transport available for getLogs');
    }

    async writeContract({ to, data, gas = '0x55730', value = '0x0' }) {
      if (!to || !data) throw ConsoleRuntimeError.invalidParams('"to" and "data" required');
      if (!this.activeAccount) throw ConsoleRuntimeError.unauthorized('Wallet not connected');
      if (!this.injectedProvider || !this.injectedProvider.request) {
        throw ConsoleRuntimeError.transportUnavailable('Injected provider unavailable for writes');
      }

      // Validate against local granted policy if present
      if (this.grantedPolicy) {
        PolicyEngine.evaluate({ chainId: this.activeChainId, target: to, data, value }, this.grantedPolicy);
      }

      return await this.injectedProvider.request({
        method: 'eth_sendTransaction',
        params: [{
          from: this.activeAccount,
          to,
          data,
          gas,
          value
        }]
      });
    }

    async waitForReceipt(txHash, maxAttempts = 15) {
      if (!txHash) throw ConsoleRuntimeError.invalidParams('txHash required');
      if (typeof fetch !== 'function') return null;

      for (let i = 0; i < maxAttempts; i++) {
        await new Promise(r => setTimeout(r, 1500));
        try {
          const resp = await fetch(this.rpcUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id: i + 1,
              method: 'eth_getTransactionReceipt',
              params: [txHash]
            })
          });
          const json = await resp.json();
          if (json && json.result && json.result.blockNumber) {
            return json.result;
          }
        } catch (_) {}
      }
      return null;
    }
  }

  // --- BridgeHostAdapter with Strict MessagePort Isolation ---
  class BridgeHostAdapter {
    constructor(port, initialCapabilities, launchContext = null) {
      this.name = 'bridge';
      this.port = port || null;
      this.portAttached = !!port;
      this._launchContext = sanitizeLaunchContext(launchContext);
      this.activeAccount = (initialCapabilities?.wallet?.address) || null;
      this.activeChainId = normalizeChainId(initialCapabilities?.evm?.chainId) || DEFAULT_CHAIN_ID;
      this.caps = initialCapabilities || {
        adapter: 'bridge',
        wallet: { supported: true, connected: false, address: null, providerName: 'Cartridge Host' },
        evm: {
          chainId: this.activeChainId,
          read: { supported: true, available: true },
          logs: { supported: true, available: true },
          write: { supported: true, available: false, authorized: true }
        },
        environment: { isSandboxed: true, hasHostBridge: true, openExternalApp: false, canonicalAppUrl: '' },
        signing: false,
        contractRead: true,
        contractWrite: false,
        openExternalApp: false,
        isSandboxed: true
      };

      this.pendingRequests = new Map();
      this.activeRequestIds = new Set();
      this.requestTimestamps = [];
      this.setupMessageListener();
    }

    getAddress() {
      return this.activeAccount;
    }

    getChainId() {
      return this.activeChainId;
    }

    getLaunchContext() {
      return this._launchContext ? JSON.parse(JSON.stringify(this._launchContext)) : null;
    }

    getCapabilities() {
      return { ...this.caps };
    }

    setupMessageListener() {
      const handleMsg = (event) => {
        const data = event.data;
        if (!data || typeof data !== 'object') return;

        // Correlated JSON-RPC 2.0 resolution
        if (data.id && this.pendingRequests.has(data.id)) {
          const pending = this.pendingRequests.get(data.id);
          clearTimeout(pending.timer);
          this.pendingRequests.delete(data.id);
          this.activeRequestIds.delete(data.id);

          if (data.error || data.success === false) {
            const errObj = data.error || {};
            const code = errObj.code || -32603;
            const message = typeof errObj === 'string' ? errObj : (errObj.message || 'Host error');
            pending.reject(new ConsoleRuntimeError(message, code, errObj.data));
          } else {
            pending.resolve(data.result);
          }
          return;
        }

        // Host pushed events: Account change
        if (data.method === 'wallet.accountsChanged') {
          const newAddr = (data.params && data.params.accounts && data.params.accounts[0]) || null;
          this.activeAccount = newAddr;
          this.caps.wallet.address = newAddr;
          this.caps.wallet.connected = !!newAddr;
          this.caps.evm.write.available = !!newAddr;
          this.caps.signing = !!newAddr;
          this.caps.contractWrite = !!newAddr;
          CartridgeHost._emit('accountsChanged', newAddr);
          CartridgeHost._emit('capabilitiesChanged', this.getCapabilities());
        }
        // Host pushed events: Chain change
        else if (data.method === 'wallet.chainChanged') {
          const rawChain = data.params && data.params.chainId;
          if (rawChain) {
            this.activeChainId = normalizeChainId(rawChain);
            if (this.caps.evm) this.caps.evm.chainId = this.activeChainId;
            CartridgeHost._emit('chainChanged', this.activeChainId);
            CartridgeHost._emit('capabilitiesChanged', this.getCapabilities());
          }
        }
        // Host pushed events: Capability updates
        else if (data.method === 'runtime.capabilitiesChanged') {
          if (data.params && data.params.capabilities) {
            this.caps = { ...this.caps, ...data.params.capabilities };
            if (this.caps.wallet) this.activeAccount = this.caps.wallet.address;
            if (this.caps.evm && this.caps.evm.chainId) this.activeChainId = normalizeChainId(this.caps.evm.chainId);
            CartridgeHost._emit('capabilitiesChanged', this.getCapabilities());
          }
        }
      };

      if (this.port) {
        this.port.onmessage = handleMsg;
      } else if (typeof window !== 'undefined') {
        window.addEventListener('message', (evt) => {
          if (this.portAttached) return; // Drop global postMessage if MessagePort active
          handleMsg(evt);
        });
      }
    }

    _sendRequest(method, params = {}, timeoutMs = 15000) {
      return new Promise((resolve, reject) => {
        // Concurrency limit
        if (this.pendingRequests.size >= MAX_CONCURRENT_REQUESTS) {
          return reject(ConsoleRuntimeError.limitExceeded(`Max concurrent requests (${MAX_CONCURRENT_REQUESTS}) reached`));
        }

        // Rate limiting
        const now = Date.now();
        this.requestTimestamps = this.requestTimestamps.filter(t => now - t < RATE_LIMIT_WINDOW_MS);
        if (this.requestTimestamps.length >= MAX_REQUESTS_PER_WINDOW) {
          return reject(ConsoleRuntimeError.limitExceeded(`Request rate limit exceeded (${MAX_REQUESTS_PER_WINDOW}/sec)`));
        }
        this.requestTimestamps.push(now);

        // Unique ID check
        const id = generateSecureNonce('req_');
        if (this.activeRequestIds.has(id)) {
          return reject(ConsoleRuntimeError.duplicateRequestId(id));
        }
        this.activeRequestIds.add(id);

        const payload = { jsonrpc: '2.0', id, method, params };

        // Payload size check
        let serialized = '';
        try {
          serialized = JSON.stringify(payload);
          if (serialized.length > MAX_PAYLOAD_BYTES) {
            this.activeRequestIds.delete(id);
            return reject(ConsoleRuntimeError.payloadTooLarge(serialized.length, MAX_PAYLOAD_BYTES));
          }
        } catch (_) {
          this.activeRequestIds.delete(id);
          return reject(ConsoleRuntimeError.invalidRequest('Serialization error'));
        }

        const timer = setTimeout(() => {
          if (this.pendingRequests.has(id)) {
            this.pendingRequests.delete(id);
            this.activeRequestIds.delete(id);
            reject(ConsoleRuntimeError.requestTimeout(method));
          }
        }, timeoutMs);

        this.pendingRequests.set(id, { resolve, reject, timer, method });

        try {
          if (this.port) {
            this.port.postMessage(payload);
          } else if (typeof window !== 'undefined' && window.parent && window.parent !== window) {
            window.parent.postMessage(payload, '*');
          } else {
            clearTimeout(timer);
            this.pendingRequests.delete(id);
            this.activeRequestIds.delete(id);
            reject(ConsoleRuntimeError.transportUnavailable());
          }
        } catch (e) {
          clearTimeout(timer);
          this.pendingRequests.delete(id);
          this.activeRequestIds.delete(id);
          reject(e);
        }
      });
    }

    async requestAccounts() {
      return await this.connect();
    }

    async connect(options = {}) {
      const res = await this._sendRequest('wallet.connect', options, 30000);
      const accounts = Array.isArray(res) ? res : (res && res.accounts ? res.accounts : [res]);
      const addr = accounts[0] || null;
      if (addr) {
        this.activeAccount = addr;
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
      this.activeAccount = null;
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

    async getLogs(filter = {}) {
      if (typeof filter !== 'object' || filter === null) {
        throw ConsoleRuntimeError.invalidParams('Filter must be an object');
      }
      return await this._sendRequest('evm.logs', { ...filter, chainId: this.activeChainId }, 30000);
    }

    async writeContract({ to, data, gas, value }) {
      if (!this.activeAccount) {
        throw ConsoleRuntimeError.unauthorized('Cannot dispatch write: wallet not connected');
      }
      return await this._sendRequest('evm.write', { to, data, gas, value, chainId: this.activeChainId }, 60000);
    }

    async waitForReceipt(txHash, maxAttempts = 15) {
      return await this._sendRequest('evm.receipt', { txHash, maxAttempts }, 60000);
    }
  }

  // --- CartridgeLoader: Package Integrity Before Execution ---
  const CartridgeLoader = {
    /**
     * Verifies package bytes against manifest integrity hash before executing
     */
    verifyPackage(packageBytes, manifest, keccakFn) {
      if (!manifest || !manifest.integrity || !manifest.integrity.contentHash) {
        // If manifest doesn't declare integrity hash, proceed with warning (e.g. legacy development)
        return true;
      }
      if (!packageBytes) {
        throw ConsoleRuntimeError.invalidParams('Package bytes required for integrity verification');
      }

      const expected = manifest.integrity.contentHash.toLowerCase();
      let actual = '';

      if (typeof keccakFn === 'function') {
        actual = ('0x' + keccakFn(packageBytes)).toLowerCase();
      } else if (typeof require === 'function') {
        try {
          const { keccak256 } = require('js-sha3');
          actual = ('0x' + keccak256(packageBytes)).toLowerCase();
        } catch (_) {}
      }

      if (!actual) {
        throw ConsoleRuntimeError.integrityFailure(expected, 'unavailable');
      }

      if (actual !== expected) {
        throw ConsoleRuntimeError.integrityFailure(expected, actual);
      }
      return true;
    },

    /**
     * Mounts verified cartridge inside minimal sandbox iframe
     */
    mountCartridge(htmlContent, containerElement, options = {}) {
      if (typeof document === 'undefined') return null;

      // Smallest viable set: 'allow-scripts' by default
      const sandboxFlags = options.sandbox || 'allow-scripts';
      const iframe = document.createElement('iframe');
      iframe.setAttribute('sandbox', sandboxFlags);
      iframe.style.width = options.width || '100%';
      iframe.style.height = options.height || '100%';
      iframe.style.border = 'none';

      if (containerElement) {
        containerElement.appendChild(iframe);
      }

      if (options.src) {
        iframe.src = options.src;
      } else if (htmlContent) {
        iframe.srcdoc = htmlContent;
      }

      return iframe;
    }
  };

  // --- CartridgeHost Singleton Runtime ---
  const CartridgeHost = {
    version: '0.2.0',
    _adapter: null,
    _listeners: new Map(),
    _handshakeEstablished: false,

    init(adapter) {
      this._adapter = adapter || new DirectHostAdapter();
    },

    getAdapter() {
      if (!this._adapter) this._adapter = new DirectHostAdapter();
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

    getChainId() {
      return this.getAdapter().getChainId ? this.getAdapter().getChainId() : null;
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

    async getLogs(filter) {
      return await this.getAdapter().getLogs(filter);
    },

    async writeContract(params) {
      return await this.getAdapter().writeContract(params);
    },

    async waitForReceipt(txHash, maxAttempts) {
      return await this.getAdapter().waitForReceipt(txHash, maxAttempts);
    },

    getLaunchContext() {
      const adapter = this.getAdapter();
      return adapter && typeof adapter.getLaunchContext === 'function' ? adapter.getLaunchContext() : null;
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
    },

    initCartridgeHostNegotiation(options = {}) {
      if (this._handshakeEstablished) {
        console.warn('CartridgeHost: Handshake already established; ignoring duplicate attempt');
        return;
      }

      const cartridgeId = options.id || options.cartridge || 'generic-cartridge';
      if (typeof window === 'undefined' || !window.parent || window.parent === window) {
        return; // Standalone top-level execution
      }

      const channel = typeof MessageChannel !== 'undefined' ? new MessageChannel() : null;
      const handshakeNonce = generateSecureNonce('hs_');
      let handshakeResolved = false;

      const finishHandshake = (caps, port, launchContext) => {
        if (handshakeResolved) return;
        handshakeResolved = true;
        this._handshakeEstablished = true;
        const bridgeAdapter = new BridgeHostAdapter(port, caps, launchContext);
        CartridgeHost.setAdapter(bridgeAdapter);
        if (options.onAttached) options.onAttached(bridgeAdapter);
      };

      const handleAck = (event) => {
        const d = event.data;
        if (!d) return;
        const ackNonce = d.nonce || d.id;
        if (ackNonce !== handshakeNonce) return;
        if (d.type !== 'cartridge:handshake:ack' && d.type !== 'cartridge:handshake_ack') return;
        window.removeEventListener('message', handleAck);
        const port = (event.ports && event.ports[0]) || (channel ? channel.port1 : null);
        finishHandshake(d.capabilities, port, d.launchContext);
      };

      window.addEventListener('message', handleAck);

      try {
        const msg = {
          type: 'cartridge:handshake',
          id: handshakeNonce,
          version: '0.1.0',
          cartridge: cartridgeId
        };
        if (channel) {
          window.parent.postMessage(msg, '*', [channel.port2]);
        } else {
          window.parent.postMessage(msg, '*');
        }
      } catch (_) {}

      setTimeout(() => {
        if (!handshakeResolved) {
          window.removeEventListener('message', handleAck);
        }
      }, options.timeoutMs || 250);
    }
  };

  // Strict Manifest V1 Schema Validator
  function validateManifestV1(manifest) {
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
      throw new TypeError('Manifest must be a non-null object');
    }

    if (manifest.manifestVersion !== '1.0.0') {
      throw new Error(`Invalid manifestVersion: expected "1.0.0", got "${manifest.manifestVersion}"`);
    }

    if (typeof manifest.id !== 'string' || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(manifest.id)) {
      throw new Error(`Invalid id/slug: "${manifest.id}". Must be lowercase alphanumeric with hyphens.`);
    }

    if (typeof manifest.cartridgeId !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(manifest.cartridgeId)) {
      throw new Error(`Invalid cartridgeId: "${manifest.cartridgeId}". Must be 32-byte hex string (0x followed by 64 hex characters).`);
    }

    if (typeof manifest.name !== 'string' || manifest.name.trim().length === 0 || manifest.name.length > 100) {
      throw new Error('Invalid name: must be non-empty string under 100 characters.');
    }

    if (typeof manifest.version !== 'string' || !parseSemVer(manifest.version)) {
      throw new Error(`Invalid version: "${manifest.version}". Must be valid SemVer 2.0.0.`);
    }

    if (!manifest.runtime || typeof manifest.runtime !== 'object') {
      throw new Error('Manifest missing required "runtime" object.');
    }
    if (typeof manifest.runtime.version !== 'string') {
      throw new Error('Manifest runtime.version must be a string.');
    }

    if (!manifest.entry || typeof manifest.entry !== 'object') {
      throw new Error('Manifest missing required "entry" resource descriptor object.');
    }
    if (typeof manifest.entry.path !== 'string') {
      throw new Error('Manifest entry.path must be a string.');
    }
    if (typeof manifest.entry.mediaType !== 'string') {
      throw new Error('Manifest entry.mediaType must be a string.');
    }
    if (typeof manifest.entry.digest !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(manifest.entry.digest)) {
      throw new Error(`Invalid entry.digest: "${manifest.entry.digest}". Must be 32-byte hex string.`);
    }
    if (typeof manifest.entry.size !== 'number' || manifest.entry.size < 0) {
      throw new Error('Manifest entry.size must be a non-negative number.');
    }

    if (manifest.entry.encoding && manifest.entry.encoding !== 'identity' && manifest.entry.encoding !== 'deflate') {
      throw new Error(`Unsupported entry encoding: "${manifest.entry.encoding}". Only "identity" and "deflate" are supported.`);
    }
    if (manifest.entry.encoding === 'deflate') {
      if (!manifest.entry.decodedDigest || !/^0x[0-9a-fA-F]{64}$/.test(manifest.entry.decodedDigest)) {
        throw new Error('Deflate encoded entry requires 32-byte hex decodedDigest.');
      }
      if (typeof manifest.entry.decodedSize !== 'number' || manifest.entry.decodedSize < 0) {
        throw new Error('Deflate encoded entry requires non-negative decodedSize.');
      }
    }

    if (!manifest.permissions || typeof manifest.permissions !== 'object') {
      throw new Error('Manifest missing required "permissions" object.');
    }
    if (!Array.isArray(manifest.permissions.chains) || manifest.permissions.chains.length === 0) {
      throw new Error('Manifest permissions.chains must be a non-empty array of CAIP-2 chain identifiers.');
    }
    const caip2Regex = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/;
    for (const chain of manifest.permissions.chains) {
      if (typeof chain !== 'string' || !caip2Regex.test(chain)) {
        throw new Error(`Invalid CAIP-2 chain identifier: "${chain}".`);
      }
    }

    if (manifest.permissions.contracts) {
      if (!Array.isArray(manifest.permissions.contracts)) {
        throw new Error('Manifest permissions.contracts must be an array.');
      }
      const addrRegex = /^0x[0-9a-fA-F]{40}$/;
      const selRegex = /^0x[0-9a-fA-F]{8}$/;
      for (const contract of manifest.permissions.contracts) {
        if (!contract || typeof contract !== 'object') {
          throw new Error('Contract permission rule must be an object.');
        }
        if (typeof contract.address !== 'string' || !addrRegex.test(contract.address)) {
          throw new Error(`Invalid contract address: "${contract.address}".`);
        }
        if (contract.allowedSelectors) {
          if (!Array.isArray(contract.allowedSelectors)) {
            throw new Error('Contract allowedSelectors must be an array.');
          }
          for (const sel of contract.allowedSelectors) {
            if (typeof sel !== 'string' || !selRegex.test(sel)) {
              throw new Error(`Invalid selector: "${sel}". Must be 4-byte hex string.`);
            }
          }
        }
      }
    }

    return true;
  }

  CartridgeHost.init(new DirectHostAdapter());

  return {
    CartridgeHost,
    DirectHostAdapter,
    BridgeHostAdapter,
    ConsoleRuntimeError,
    PolicyEngine,
    ELEVATED_SELECTORS,
    CANONICAL_SIGNATURES,
    normalizeChainId,
    toCaip2ChainId,
    canonicalizeJson,
    parseSemVer,
    satisfiesSemVer,
    normalizeLog,
    normalizeLogs,
    CartridgeLoader,
    generateSecureNonce,
    validateManifestV1,
    CAIP19_REGEX,
    MAX_LAUNCH_CONTEXT_BYTES,
    parseCaip19,
    validateLaunchContext,
    sanitizeLaunchContext
  };
}));

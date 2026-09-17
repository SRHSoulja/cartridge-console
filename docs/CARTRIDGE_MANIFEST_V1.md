# Cartridge Manifest V1 Specification

**Status**: Specification  
**Version**: 1.0.0  
**Canonical Serialization**: RFC 8785 JSON Canonicalization Scheme (JCS)  

---

## 1. Abstract

The **Cartridge Manifest** is a deterministic JSON document describing the cartridge's identity, target runtime, entry point, cryptographic asset dependencies, and required contract permissions.

In Manifest V1, all manifests MUST adhere to **RFC 8785 JSON Canonicalization Scheme (JCS)** to guarantee that `keccak256(canonicalManifestBytes)` yields a bit-for-bit invariant cryptographic digest regardless of language, parser, or key order.

---

## 2. Canonical JSON Serialization (RFC 8785)

To guarantee bit-for-bit cryptographic determinism and prevent malleability:
- Object property keys are sorted strictly based on their UTF-16 code unit values in lexicographical order.
- Delimiters `:` and `,` MUST NOT be followed by whitespace.
- Strings are encoded with minimal escapes (only required control characters, `"`, and `\`).
- Unicode validation: Lone or unpaired UTF-16 surrogates (`0xD800` through `0xDFFF`) are strictly rejected.
- Numbers follow ECMAScript standard JSON stringification; `-0` is normalized to `0`. Non-finite numbers (`NaN`, `Infinity`, `-Infinity`) are strictly rejected.
- Non-serializable types (`undefined`, `BigInt`, `Symbol`, functions) are strictly rejected.

### Canonicalization Algorithm (JavaScript Reference)

```javascript
function canonicalizeJson(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError('JCS: non-finite numbers not supported');
    }
    if (Object.is(value, -0)) return '0';
    return JSON.stringify(value);
  }

  if (typeof value === 'string') {
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
    return '[' + value.map(canonicalizeJson).join(',') + ']';
  }

  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    const pairs = [];
    for (const key of keys) {
      const val = value[key];
      if (val === undefined || typeof val === 'symbol' || typeof val === 'function') {
        throw new TypeError(`JCS: invalid property type: ${typeof val}`);
      }
      pairs.push(canonicalizeJson(key) + ':' + canonicalizeJson(val));
    }
    return '{' + pairs.join(',') + '}';
  }

  throw new TypeError(`JCS: unsupported type: ${typeof value}`);
}
```

---

## 3. Manifest Schema

```json
{
  "manifestVersion": "1.0.0",
  "id": "hoodquest",
  "cartridgeId": "0x1111111111111111111111111111111111111111111111111111111111111111",
  "name": "HoodQuest: Sanctuary of the Falcon",
  "version": "1.0.0",
  "description": "On-chain retro tactical fantasy cartridge",
  "runtime": {
    "version": "^0.2.0"
  },
  "entry": {
    "path": "index.html",
    "mediaType": "text/html",
    "encoding": "deflate",
    "digest": "0x...",
    "size": 75120,
    "decodedDigest": "0x8a883ea5b9e8497de85abdd1007af9454d01c49e6594bd1743175de0ea0456c0",
    "decodedSize": 236246,
    "chunks": [
      "0x..."
    ]
  },
  "resources": [
    {
      "path": "assets/sprites.png",
      "mediaType": "image/png",
      "encoding": "identity",
      "digest": "0x...",
      "size": 4096
    }
  ],
  "dependencies": [
    {
      "name": "shared-sound-engine",
      "digest": "0x...",
      "version": "1.0.0"
    }
  ],
  "permissions": {
    "chains": [
      "eip155:11155111"
    ],
    "contracts": [
      {
        "address": "0xF75323518df7Ce90637e2b93cFd7f7d0627cc205",
        "name": "Outlaws",
        "writes": true,
        "allowedSelectors": [
          "0xf59dfdfb",
          "0x9dac653f"
        ],
        "allowNativeValue": false,
        "isElevated": false,
        "argumentConstraints": {
          "allowedSpenders": []
        }
      }
    ]
  }
}
```

---

## 4. Field Definitions

### Top-Level Properties
- `manifestVersion`: String semver indicating manifest schema version (`"1.0.0"`).
- `id`: Human-readable identifier/slug.
- `cartridgeId`: Explicit 32-byte hex string identifier (`0x...`) registered in `CartridgeRegistry`.
- `name`: Human-readable cartridge title.
- `version`: Cartridge release version adhering strictly to SemVer 2.0.0.
- `runtime.version`: Semantic version range of the Console Runtime required (e.g. `"^0.2.0"`).

### Resource Descriptor Model (`entry`, `resources`)
- `path`: Resource path.
- `mediaType`: MIME media type (e.g. `"text/html"`, `"application/octet-stream"`, `"application/wasm"`).
- `encoding`: Content encoding/compression scheme (`"identity"` or `"deflate"`).
- `digest`: `keccak256` digest of the stored payload (as stored on-chain in `ContentStore`).
- `size`: Byte count of the stored payload.
- `decodedDigest`: When `encoding` is compressed (e.g. `"deflate"`), the `keccak256` digest of the uncompressed payload.
- `decodedSize`: When `encoding` is compressed, the byte count of the uncompressed payload.
- `chunks`: Array of chunk digests stored in `ContentStore`.

### Permissions Block (`permissions`)
- `chains`: Array of CAIP-2 blockchain identifiers (e.g. `["eip155:11155111"]`).
- `contracts`: Array of permission rules declaring allowed contracts, write permissions, explicit 4-byte function selectors, and native value rules.

---

## 5. Registry & Publication Boundary Semantics

- **Immutable Version Labels**: Once a version string (e.g. `"1.0.0"`) is published for a `cartridgeId`, that version label is permanently immutable. Republishing the same version label reverts with `VersionAlreadyPublished`.
- **Publisher Commitment**: Publishing a release records the publisher's cryptographic commitment to `manifestDigest`.
- **Storage-Backend Agnostic**: The registry deliberately does not enforce synchronous on-chain validation of content chunk availability at publication time, decoupling registration from storage backends. Retrievability and integrity are validated by the host resolver prior to sandbox execution.

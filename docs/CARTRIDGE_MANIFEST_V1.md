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

To prevent malleability:
- Object property keys are sorted in lexicographical Unicode code point order.
- Delimiters `:` and `,` MUST NOT be followed by whitespace.
- Strings are encoded with minimal escapes (only required control characters, `"` and `\`).
- Numbers follow ECMAScript standard JSON stringification without trailing zeros or scientific notation quirks.

### Canonicalization Algorithm (JavaScript Reference)

```javascript
function canonicalizeJson(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalizeJson).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  const pairs = keys
    .filter(k => obj[k] !== undefined)
    .map(k => JSON.stringify(k) + ':' + canonicalizeJson(obj[k]));
  return '{' + pairs.join(',') + '}';
}
```

---

## 3. Manifest Schema

```json
{
  "manifestVersion": "1.0.0",
  "id": "hoodquest",
  "name": "HoodQuest: Sanctuary of the Falcon",
  "version": "1.0.0",
  "description": "On-chain retro tactical fantasy cartridge",
  "runtime": {
    "version": "^0.2.0"
  },
  "entry": {
    "path": "index.html",
    "digest": "0x8a883ea5b9e8497de85abdd1007af9454d01c49e6594bd1743175de0ea0456c0",
    "size": 236246,
    "mediaType": "text/html",
    "chunks": [
      "0x..."
    ]
  },
  "resources": [
    {
      "path": "assets/sprites.png",
      "digest": "0x...",
      "size": 4096,
      "mediaType": "image/png"
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
- `id`: Lowercase alphanumeric identifier/slug.
- `name`: Human-readable cartridge title.
- `version`: Cartridge release version.
- `runtime.version`: Semantic version range of the Console Runtime required (e.g. `"^0.2.0"`).

### Entry Descriptor (`entry`)
- `path`: Primary entry document (typically `"index.html"`).
- `digest`: `keccak256` of the uncompressed or canonical entry file.
- `size`: Byte count.
- `mediaType`: MIME type (`"text/html"`).
- `chunks`: Optional array of sequential chunk digests stored in `ContentStore`.

### Permissions Block (`permissions`)
- `chains`: Array of CAIP-2 blockchain identifiers (e.g. `["eip155:11155111"]`).
- `contracts`: Array of permission rules declaring allowed contracts, write permissions, explicit 4-byte function selectors, and native value rules.

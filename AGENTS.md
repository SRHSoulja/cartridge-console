# Cartridge Console — Agent Boundaries & Repository Ownership

## Ownership Scope

### OWNS:
- Console Protocol (V0.1, V0.2, and future iterations)
- Cartridge Protocol (V0.1 and future iterations)
- Generic runtime client (`runtime/cartridge_host_runtime.js`)
- Generic host controller, UI, and bridge (`host/`)
- Developer SDK, template, and client tooling (`cartridge-template/`)
- ContentStore storage substrate (`src/protocol/ContentStore.sol`)
- CartridgeRegistry release and channel registry (`src/protocol/CartridgeRegistry.sol`)
- Manifest V1 schema and RFC 8785 JSON canonicalization specifications
- Generic reference and test cartridges (`runtime-test-cartridge`, `adversarial-cartridge`)
- Generic test harness and protocol suites

### DOES NOT OWN:
- HoodQuest game logic, contracts, or assets (`../hoodquest`)
- MARKS mechanics, contracts, or lineages (`../marks-targets`)
- TARGETS mechanics, contracts, or lineups (`../marks-targets`)
- Project Vegas logic, state machines, or contracts (`../project-vegas`)
- Unrelated Robinhood Chain applications

Adjacent repositories in `RH/` are strictly read-only context unless the task explicitly authorizes changes.
Platform changes and protocol iterations are developed and tested here.

---

## Repository Visibility Policy

| Repository | Visibility | Disclosure Requirement |
| :--- | :--- | :--- |
| `SRHSoulja/cartridge-console` | **PUBLIC** | Open-source platform substrate, protocol, runtime, host, SDK, tests |
| `SRHSoulja/hoodquest` | **PUBLIC** | Open application, on-chain cartridge #0001 |
| `SRHSoulja/robinhood-chain-tools` | **PUBLIC** | Developer and token distribution tools |
| `SRHSoulja/marks-targets` | **PRIVATE** | Surprise-sensitive, unreleased mechanics, art, launch plans |
| `SRHSoulja/project-vegas` | **PRIVATE** | Preserved project visibility |
| `SRHSoulja/project-vegas-research` | **PRIVATE** | Preserved research visibility |

### Cross-Repository Privacy Rule
A public Console commit must never accidentally include private MARKS/TARGETS source, assets, manifests, ABI details that reveal unreleased mechanics, screenshots, design documents, or test fixtures copied from its private repository.

Public platform development and private application development must remain cleanly separated.
When private cartridges are tested for generic compatibility, only the generic protocol primitive exposed (e.g. `evm.logs`) may be described in public documentation or tests.

---

## Provenance
Originated from `SRHSoulja/hoodquest` at checkpoint commit:
`f1e528e0350465db652032751063050b9d59c52f`

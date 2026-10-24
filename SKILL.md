---
name: cctp-utils
description: Circle CCTP utilities for Rust — depositForBurn encoding and Iris attestation verification.
---

# cctp-utils

cctp-utils implements the two hard parts of Circle's Cross-Chain Transfer Protocol: ABI-encoding depositForBurn calls and fetching/verifying attestations from the Circle Iris API. Use it to move USDC across chains without a bridge token.

## When to use

Implementing native USDC bridging in Rust, verifying Iris attestations, or building CCTP-aware routing.

## Install

```
cargo add cctp-utils
```

## Links

- Repository: https://github.com/orkid-labs/cctp-utils
- Package: https://crates.io/crates/cctp-utils
- Documentation: https://docs.rs/cctp-utils
- Orkid Labs: https://orkidlabs.xyz

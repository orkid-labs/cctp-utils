# CCTP Utils

CCTP (Cross-Chain Transfer Protocol) utilities for Rust - depositForBurn encoding and Circle Iris attestation verification.

## Features

- CCTP depositForBurn calldata encoding
- Circle Iris attestation polling
- ECDSA signature verification
- Attestation freshness validation
- Cross-chain transfer protocol utilities

## Usage

```rust
use cctp_utils::{encode_deposit_for_burn, poll_iris_attestation, parse_and_verify_attestation};

// Encode CCTP depositForBurn calldata
let calldata = encode_deposit_for_burn(
    amount,
    destination_domain,
    mint_recipient,
    burn_token,
    destination_caller,
    hook_data
);

// Poll Circle Iris for attestation
let attestation = poll_iris_attestation(&client, base_url, message_hash, timeout).await?;

// Verify attestation signature and freshness
let valid = parse_and_verify_attestation(attestation_json, max_latency_secs)?;
```

## License

MIT

---

## Part of Orkid Labs

**cctp-utils** — Circle CCTP utilities for Rust — depositForBurn encoding and Iris attestation verification.

- Install: `cargo add cctp-utils`
- Package: https://crates.io/crates/cctp-utils
- API docs: https://docs.rs/cctp-utils
- Docs: https://docs.orkidlabs.xyz/packages/cctp-utils

Related Orkid projects: [defi-core](https://github.com/orkid-labs/defi-core), [orkid-bridge-mcp](https://github.com/orkid-labs/orkid-bridge-mcp)

Orkid Labs builds gasless, MEV-protected swap routing and agent-native DeFi infrastructure — [orkidlabs.xyz](https://orkidlabs.xyz) · [@orkid-labs on npm](https://www.npmjs.com/org/orkid-labs) · [github.com/orkid-labs](https://github.com/orkid-labs)

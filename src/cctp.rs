use alloy_primitives::{Address as AlloyAddress, Bytes as AlloyBytes, U256 as AlloyU256};
use ethers::abi::Token;
use ethers::types as ethers_types;

/// Minimal helper to build depositForBurn calldata for TokenMessengerV2
/// ABI: depositForBurn(uint256 amount, uint32 destinationDomain, bytes32 mintRecipient, address burnToken, bytes32 destinationCaller, bytes hookData)

pub fn encode_deposit_for_burn(
    amount: AlloyU256,
    destination_domain: u32,
    mint_recipient: [u8; 32],
    burn_token: AlloyAddress,
    destination_caller: [u8; 32],
    hook_data: AlloyBytes,
) -> Vec<u8> {
    // Convert Alloy types to ethers types so we can reuse ethers::abi encoding
    // Convert amount via decimal string to avoid depending on internal representations
    let amount_dec = amount.to_string();
    let amount_eth = ethers_types::U256::from_dec_str(&amount_dec)
        .unwrap_or_else(|_| ethers_types::U256::zero());

    // Convert address: try to get raw bytes via debug/hex formatting
    // We format the Alloy address as hex and strip 0x if present.
    let burn_hex = format!("{:x}", burn_token);
    let burn_hex_str = burn_hex.trim_start_matches("0x");
    let burn_bytes = hex::decode(burn_hex_str).unwrap_or_else(|_| vec![0u8; 20]);
    let burn_addr = if burn_bytes.len() >= 20 {
        let slice = &burn_bytes[burn_bytes.len() - 20..];
        ethers_types::Address::from_slice(slice)
    } else {
        ethers_types::Address::zero()
    };

    let hook_vec = hook_data.0.to_vec();

    // Build tokens array corresponding to Solidity function inputs
    let tokens = vec![
        Token::Uint(amount_eth),
        Token::Uint(ethers_types::U256::from(destination_domain as u64)),
        Token::FixedBytes(mint_recipient.to_vec()),
        Token::Address(burn_addr),
        Token::FixedBytes(destination_caller.to_vec()),
        Token::Bytes(hook_vec),
    ];

    // Function selector for depositForBurn
    let selector =
        ethers::utils::id("depositForBurn(uint256,uint32,bytes32,address,bytes32,bytes)")[0..4]
            .to_vec();
    let encoded = ethers::abi::encode(&tokens);
    [selector, encoded].concat()
}

/// Neutral helper that accepts primitive types (dec string for amount, raw address bytes, and hook bytes)
/// This avoids depending on alloy_primitives in callers and provides an alloy-agnostic boundary.
pub fn encode_deposit_for_burn_raw(
    amount_dec: &str,
    destination_domain: u32,
    mint_recipient: [u8; 32],
    burn_token_bytes: [u8; 20],
    destination_caller: [u8; 32],
    hook_data: &[u8],
) -> Vec<u8> {
    let amount_eth =
        ethers_types::U256::from_dec_str(amount_dec).unwrap_or_else(|_| ethers_types::U256::zero());
    let burn_addr = ethers_types::Address::from_slice(&burn_token_bytes);
    let hook_vec = hook_data.to_vec();

    let tokens = vec![
        Token::Uint(amount_eth),
        Token::Uint(ethers_types::U256::from(destination_domain as u64)),
        Token::FixedBytes(mint_recipient.to_vec()),
        Token::Address(burn_addr),
        Token::FixedBytes(destination_caller.to_vec()),
        Token::Bytes(hook_vec),
    ];
    let selector =
        ethers::utils::id("depositForBurn(uint256,uint32,bytes32,address,bytes32,bytes)")[0..4]
            .to_vec();
    let encoded = ethers::abi::encode(&tokens);
    [selector, encoded].concat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address as AlloyAddress, Bytes as AlloyBytes, U256 as AlloyU256};

    #[test]
    fn test_encode_deposit_for_burn_len() {
        let amount = AlloyU256::from(1000u64);
        let dest = 60u32;
        let mint = [0u8; 32];
        let burn = AlloyAddress::repeat_byte(0);
        let caller = [1u8; 32];
        let hook = AlloyBytes::from(vec![1, 2, 3]);
        let data = encode_deposit_for_burn(amount, dest, mint, burn, caller, hook);
        assert!(data.len() > 4);
    }
}

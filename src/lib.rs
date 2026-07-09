//! CCTP (Cross-Chain Transfer Protocol) utilities for Rust
//!
//! Provides depositForBurn encoding for Circle's CCTP and Circle Iris attestation verification.

pub mod cctp;
pub mod iris;

pub use cctp::*;
pub use iris::*;

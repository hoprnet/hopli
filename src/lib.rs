//! `hopli_lib` contains the core command implementations and utilities used by
//! the `hopli` CLI.
//!
//! Main modules:
//! - `identity`: create/read/update node identity files
//! - `faucet`: distribute native/HOPR tokens to nodes
//! - `safe_module`: create and operate Safe + module setups
//! - `win_prob`: manage winning probability parameters

pub mod constants;
pub mod environment_config;
pub mod faucet;
pub mod identity;
pub mod key_pair;
pub mod methods;
pub mod payloads;
pub mod safe_module;
#[allow(clippy::too_many_arguments)]
pub mod utils;
pub mod win_prob;

pub mod exports {
    pub use hopr_bindings::exports::alloy;
}

pub use hopr_bindings::exports::alloy::primitives::Address;

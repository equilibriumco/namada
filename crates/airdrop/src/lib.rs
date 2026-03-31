//! Airdrop functionality

pub mod storage;
pub mod storage_key;
pub mod vp;

use namada_core::address::{Address, InternalAddress};

/// The Airdrop internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::Airdrop);

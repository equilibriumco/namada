//! Airdrop functionality

pub mod storage;
pub mod vp;

mod storage_key;

use namada_core::address::{Address, InternalAddress};

/// The Airdrop internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::Airdrop);

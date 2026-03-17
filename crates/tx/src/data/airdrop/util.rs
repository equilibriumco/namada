//! Airdrop utility functions.

/// Helper function for reversing a byte array.
fn reverse_bytes<const N: usize>(input: &[u8; N]) -> [u8; N] {
    let mut tmp = *input;
    tmp.reverse();
    tmp
}

/// Helper function for encoding and reversing a hex string, used for displaying
/// airdrop nullifiers.
///
/// # Returns
///
/// * `String`: The reversed hex string.
pub fn reversed_hex_encode<const N: usize>(input: &[u8; N]) -> String {
    let reversed = reverse_bytes(input);
    hex::encode(reversed)
}

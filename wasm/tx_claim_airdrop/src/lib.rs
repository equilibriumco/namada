//! A tx for a user to claim airdrop rewards from Zcash.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let claim = transaction::airdrop::AirdropClaim::try_from_slice(&data[..])
        .wrap_err("Failed to decode AirdropClaim value")?;

    ctx.mint_token(&claim.target, &claim.token, &claim.amount)
        .wrap_err("Failed to claim airdrop")?;

    Ok(())
}

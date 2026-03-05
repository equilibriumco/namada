//! A tx for a user to claim airdrop rewards.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let claim = transaction::airdrop::ClaimAirdrop::try_from_slice(&data[..])
        .wrap_err("Failed to decode ClaimAirdrop value")?;

    ctx.claim_airdrop(
        &claim.target,
        &claim.token,
        claim.amount,
        claim.claim_data,
    )
    .wrap_err("Failed to claim airdrop")?;

    Ok(())
}

//! `otp.outcome`: after a fill, the extension reports how the site's 2FA step went. The agent
//! keeps a short per-site history and answers with `skips_2fa`.

use serde::Deserialize;
use serde_json::json;

use super::{ErrorCode, RpcError, RpcResult};
use crate::otp_history::OtpOutcome;
use crate::Agent;

#[derive(Deserialize)]
pub(super) struct OutcomeParams {
    url: String,
    outcome: String,
}

impl Agent {
    pub(super) fn rpc_otp_outcome(&self, p: OutcomeParams) -> RpcResult {
        let outcome = OtpOutcome::parse(&p.outcome).ok_or_else(|| {
            RpcError::new(
                ErrorCode::InvalidParams,
                "outcome must be \"asked\", \"skipped\" or \"used\"",
            )
        })?;
        let recorded = self.otp_outcome(&p.url, outcome);
        Ok(json!({ "recorded": recorded, "skips_2fa": self.skips_2fa(&p.url) }))
    }
}

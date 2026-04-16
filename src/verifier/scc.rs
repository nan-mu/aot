//! Missing types: BpfSccVisit, BpfVerifierEnv, BpfSccCallchain, BpfSccInfo

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, callchain))]
pub fn scc_visit_alloc(env: &mut BpfVerifierEnv, callchain: &BpfSccCallchain) -> Result<&mut BpfSccVisit> {
    let _ = Some(callchain).context("scc_visit_alloc callchain is required")?;
    let scc = callchain.scc as usize;
    let num_visits = env.scc_info[scc].as_ref().map(|i| i.num_visits).unwrap_or(0);

    let info = env.scc_info[scc].get_or_insert_with(BpfSccInfo::default);
    info.visits.push(BpfSccVisit::default());
    info.num_visits = num_visits + 1;

    let visit = info
        .visits
        .last_mut()
        .ok_or_else(|| anyhow!("scc_visit_alloc failed"))?;
    visit.callchain = *callchain;
    Ok(visit)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, callchain))]
pub fn scc_visit_lookup(env: &mut BpfVerifierEnv, callchain: &BpfSccCallchain) -> Result<&mut BpfSccVisit> {
    let _ = Some(callchain).context("scc_visit_lookup callchain is required")?;
    let scc = callchain.scc as usize;
    let info = env
        .scc_info[scc]
        .as_mut()
        .ok_or_else(|| anyhow!("scc_visit_lookup failed"))?;

    for i in 0..info.num_visits as usize {
        if info.visits[i].callchain == *callchain {
            return Ok(&mut info.visits[i]);
        }
    }

    Err(anyhow!("scc_visit_lookup failed"))
}

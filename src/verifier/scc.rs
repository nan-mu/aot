//! Missing types: BpfSccVisit, BpfVerifierEnv, BpfSccCallchain, BpfSccInfo

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, callchain))]
pub fn scc_visit_alloc(env: &mut BpfVerifierEnv, callchain: &BpfSccCallchain) -> Result<Option<&mut BpfSccVisit>> {
    let scc = callchain.scc as usize;
    let num_visits = env.scc_info[scc].as_ref().map(|i| i.num_visits).unwrap_or(0);

    let info = env.scc_info[scc].get_or_insert_with(BpfSccInfo::default);
    info.visits.push(BpfSccVisit::default());
    info.num_visits = num_visits + 1;

    let visit = info.visits.last_mut();
    if let Some(v) = visit {
        v.callchain = *callchain;
    }

    Ok(visit)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, callchain))]
pub fn scc_visit_lookup(env: &mut BpfVerifierEnv, callchain: &BpfSccCallchain) -> Result<Option<&mut BpfSccVisit>> {
    let scc = callchain.scc as usize;
    let info = match env.scc_info[scc].as_mut() {
        Some(i) => i,
        None => return Ok(None),
    };

    for i in 0..info.num_visits as usize {
        if info.visits[i].callchain == *callchain {
            return Ok(Some(&mut info.visits[i]));
        }
    }

    Ok(None)
}

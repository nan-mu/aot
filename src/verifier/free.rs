//! Missing types: BpfSccVisit, BpfSccBackedge, BpfFuncState, BpfVerifierEnv, BpfVerifierStateList, ListHead, BpfSccInfo, BpfVerifierState

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(visit))]
pub fn free_backedges(visit: &mut BpfSccVisit) -> Result<()> {
    let mut cur = visit.backedges.take();
    while let Some(mut backedge) = cur {
        free_verifier_state(&mut backedge.state, false)?;
        cur = backedge.next.take();
    }
    visit.backedges = None;
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(state))]
pub fn free_func_state(state: &mut Option<Box<BpfFuncState>>) -> Result<()> {
    if let Some(s) = state.as_mut() {
        s.stack = Vec::new();
    }
    *state = None;
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn free_states(env: &mut BpfVerifierEnv) -> Result<()> {
    if env.cur_state.is_some() {
        free_verifier_state(env.cur_state.as_mut().unwrap(), true)?;
    }
    env.cur_state = None;

    while pop_stack(env, None, None, false) {}

    for sl in env.free_list.iter_mut() {
        free_verifier_state(&mut sl.state, false)?;
    }
    env.free_list.clear();

    for i in 0..env.scc_cnt as usize {
        if let Some(info) = env.scc_info[i].as_mut() {
            for j in 0..info.num_visits as usize {
                free_backedges(&mut info.visits[j])?;
            }
        }
        env.scc_info[i] = None;
    }

    if env.explored_states.is_empty() {
        return Ok(());
    }

    for head in env.explored_states.iter_mut() {
        for sl in head.iter_mut() {
            free_verifier_state(&mut sl.state, false)?;
        }
        head.clear();
    }

    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(state))]
pub fn free_verifier_state(state: &mut BpfVerifierState, free_self: bool) -> Result<()> {
    for i in 0..=state.curframe as usize {
        let mut slot = state.frame[i].take();
        free_func_state(&mut slot)?;
        state.frame[i] = None;
    }
    state.refs.clear();
    clear_jmp_history(state)?;
    if free_self {
        state.cleaned = true;
    }
    Ok(())
}

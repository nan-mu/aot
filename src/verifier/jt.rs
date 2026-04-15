//! Missing types: BpfIArray, BpfMap, BpfVerifierEnv

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(map))]
pub fn jt_from_map(map: &BpfMap) -> Result<Box<BpfIArray>> {
    let mut jt = iarray_realloc(None, map.max_entries as usize)?;

    let n = copy_insn_array_uniq(map, 0, map.max_entries - 1, &mut jt.items)?;
    if n <= 0 {
        return Err(anyhow!("jt_from_map failed"));
    }
    jt.cnt = n as usize;
    Ok(jt)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn jt_from_subprog(
    env: &mut BpfVerifierEnv,
    subprog_start: i32,
    subprog_end: i32,
) -> Result<Box<BpfIArray>> {
    let mut jt: Option<Box<BpfIArray>> = None;

    for i in 0..env.insn_array_map_cnt as usize {
        let map = env.insn_array_maps[i];
        let jt_cur = jt_from_map(map)?;

        /* This is enough to check one element. The full table is
         * checked to fit inside the subprog later in create_jt()
         */
        if jt_cur.items[0] >= subprog_start as u32 && jt_cur.items[0] < subprog_end as u32 {
            let old_cnt = jt.as_ref().map(|x| x.cnt).unwrap_or(0);
            let mut new_jt = iarray_realloc(jt, old_cnt + jt_cur.cnt)?;
            new_jt.items[old_cnt..old_cnt + jt_cur.cnt].copy_from_slice(&jt_cur.items[..jt_cur.cnt]);
            jt = Some(new_jt);
        }
    }

    if jt.is_none() {
        verbose(
            env,
            format!("no jump tables found for subprog starting at {}\n", subprog_start),
        );
        return Err(anyhow!("jt_from_subprog failed"));
    }

    let mut jt = jt.unwrap();
    jt.cnt = sort_insn_array_uniq(&mut jt.items, jt.cnt)? as usize;
    Ok(jt)
}

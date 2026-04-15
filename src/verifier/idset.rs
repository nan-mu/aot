//! Missing types: BpfIdset

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(idset))]
pub fn idset_cnt_get(idset: &BpfIdset, id: u32) -> Result<u32> {
    for i in 0..idset.num_ids as usize {
        if idset.entries[i].id == id {
            return Ok(idset.entries[i].cnt);
        }
    }
    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(idset))]
pub fn idset_cnt_inc(idset: &mut BpfIdset, id: u32) -> Result<()> {
    for i in 0..idset.num_ids as usize {
        if idset.entries[i].id == id {
            idset.entries[i].cnt += 1;
            return Ok(());
        }
    }

    /* New id */
    if idset.num_ids < BPF_ID_MAP_SIZE as u32 {
        let n = idset.num_ids as usize;
        idset.entries[n].id = id;
        idset.entries[n].cnt = 1;
        idset.num_ids += 1;
    }

    Ok(())
}

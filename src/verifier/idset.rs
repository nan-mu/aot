// Extracted from /Users/nan/bs/aot/src/verifier.c
static u32 idset_cnt_get(struct bpf_idset *idset, u32 id)
{
	u32 i;

	for (i = 0; i < idset->num_ids; i++) {
		if (idset->entries[i].id == id)
			return idset->entries[i].cnt;
	}
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void idset_cnt_inc(struct bpf_idset *idset, u32 id)
{
	u32 i;

	for (i = 0; i < idset->num_ids; i++) {
		if (idset->entries[i].id == id) {
			idset->entries[i].cnt++;
			return;
		}
	}
	/* New id */
	if (idset->num_ids < BPF_ID_MAP_SIZE) {
		idset->entries[idset->num_ids].id = id;
		idset->entries[idset->num_ids].cnt = 1;
		idset->num_ids++;
	}
}



// Extracted from /Users/nan/bs/aot/src/verifier.c
static int specialize_kfunc(struct bpf_verifier_env *env, struct bpf_kfunc_desc *desc, int insn_idx)
{
	struct bpf_prog *prog = env->prog;
	bool seen_direct_write;
	void *xdp_kfunc;
	bool is_rdonly;
	u32 func_id = desc->func_id;
	u16 offset = desc->offset;
	unsigned long addr = desc->addr;

	if (offset) /* return if module BTF is used */
		return 0;

	if (bpf_dev_bound_kfunc_id(func_id)) {
		xdp_kfunc = bpf_dev_bound_resolve_kfunc(prog, func_id);
		if (xdp_kfunc)
			addr = (unsigned long)xdp_kfunc;
		/* fallback to default kfunc when not supported by netdev */
	} else if (func_id == special_kfunc_list[KF_bpf_dynptr_from_skb]) {
		seen_direct_write = env->seen_direct_write;
		is_rdonly = !may_access_direct_pkt_data(env, NULL, BPF_WRITE);

		if (is_rdonly)
			addr = (unsigned long)bpf_dynptr_from_skb_rdonly;

		/* restore env->seen_direct_write to its original value, since
		 * may_access_direct_pkt_data mutates it
		 */
		env->seen_direct_write = seen_direct_write;
	} else if (func_id == special_kfunc_list[KF_bpf_set_dentry_xattr]) {
		if (bpf_lsm_has_d_inode_locked(prog))
			addr = (unsigned long)bpf_set_dentry_xattr_locked;
	} else if (func_id == special_kfunc_list[KF_bpf_remove_dentry_xattr]) {
		if (bpf_lsm_has_d_inode_locked(prog))
			addr = (unsigned long)bpf_remove_dentry_xattr_locked;
	} else if (func_id == special_kfunc_list[KF_bpf_dynptr_from_file]) {
		if (!env->insn_aux_data[insn_idx].non_sleepable)
			addr = (unsigned long)bpf_dynptr_from_file_sleepable;
	} else if (func_id == special_kfunc_list[KF_bpf_arena_alloc_pages]) {
		if (env->insn_aux_data[insn_idx].non_sleepable)
			addr = (unsigned long)bpf_arena_alloc_pages_non_sleepable;
	} else if (func_id == special_kfunc_list[KF_bpf_arena_free_pages]) {
		if (env->insn_aux_data[insn_idx].non_sleepable)
			addr = (unsigned long)bpf_arena_free_pages_non_sleepable;
	}
	desc->addr = addr;
	return 0;
}



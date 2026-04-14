// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool refsafe(struct bpf_verifier_state *old, struct bpf_verifier_state *cur,
		    struct bpf_idmap *idmap)
{
	int i;

	if (old->acquired_refs != cur->acquired_refs)
		return false;

	if (old->active_locks != cur->active_locks)
		return false;

	if (old->active_preempt_locks != cur->active_preempt_locks)
		return false;

	if (old->active_rcu_locks != cur->active_rcu_locks)
		return false;

	if (!check_ids(old->active_irq_id, cur->active_irq_id, idmap))
		return false;

	if (!check_ids(old->active_lock_id, cur->active_lock_id, idmap) ||
	    old->active_lock_ptr != cur->active_lock_ptr)
		return false;

	for (i = 0; i < old->acquired_refs; i++) {
		if (!check_ids(old->refs[i].id, cur->refs[i].id, idmap) ||
		    old->refs[i].type != cur->refs[i].type)
			return false;
		switch (old->refs[i].type) {
		case REF_TYPE_PTR:
		case REF_TYPE_IRQ:
			break;
		case REF_TYPE_LOCK:
		case REF_TYPE_RES_LOCK:
		case REF_TYPE_RES_LOCK_IRQ:
			if (old->refs[i].ptr != cur->refs[i].ptr)
				return false;
			break;
		default:
			WARN_ONCE(1, "Unhandled enum type for reference state: %d\n", old->refs[i].type);
			return false;
		}
	}

	return true;
}



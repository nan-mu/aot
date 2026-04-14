// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_scc_visit *scc_visit_alloc(struct bpf_verifier_env *env,
					     struct bpf_scc_callchain *callchain)
{
	struct bpf_scc_visit *visit;
	struct bpf_scc_info *info;
	u32 scc, num_visits;
	u64 new_sz;

	scc = callchain->scc;
	info = env->scc_info[scc];
	num_visits = info ? info->num_visits : 0;
	new_sz = sizeof(*info) + sizeof(struct bpf_scc_visit) * (num_visits + 1);
	info = kvrealloc(env->scc_info[scc], new_sz, GFP_KERNEL_ACCOUNT);
	if (!info)
		return NULL;
	env->scc_info[scc] = info;
	info->num_visits = num_visits + 1;
	visit = &info->visits[num_visits];
	memset(visit, 0, sizeof(*visit));
	memcpy(&visit->callchain, callchain, sizeof(*callchain));
	return visit;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_scc_visit *scc_visit_lookup(struct bpf_verifier_env *env,
					      struct bpf_scc_callchain *callchain)
{
	struct bpf_scc_info *info = env->scc_info[callchain->scc];
	struct bpf_scc_visit *visits = info->visits;
	u32 i;

	if (!info)
		return NULL;
	for (i = 0; i < info->num_visits; i++)
		if (memcmp(callchain, &visits[i].callchain, sizeof(*callchain)) == 0)
			return &visits[i];
	return NULL;
}



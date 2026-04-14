// Extracted from /Users/nan/bs/aot/src/verifier.c
static void compute_insn_live_regs(struct bpf_verifier_env *env,
				   struct bpf_insn *insn,
				   struct insn_live_regs *info)
{
	struct call_summary cs;
	u8 class = BPF_CLASS(insn->code);
	u8 code = BPF_OP(insn->code);
	u8 mode = BPF_MODE(insn->code);
	u16 src = BIT(insn->src_reg);
	u16 dst = BIT(insn->dst_reg);
	u16 r0  = BIT(0);
	u16 def = 0;
	u16 use = 0xffff;

	switch (class) {
	case BPF_LD:
		switch (mode) {
		case BPF_IMM:
			if (BPF_SIZE(insn->code) == BPF_DW) {
				def = dst;
				use = 0;
			}
			break;
		case BPF_LD | BPF_ABS:
		case BPF_LD | BPF_IND:
			/* stick with defaults */
			break;
		}
		break;
	case BPF_LDX:
		switch (mode) {
		case BPF_MEM:
		case BPF_MEMSX:
			def = dst;
			use = src;
			break;
		}
		break;
	case BPF_ST:
		switch (mode) {
		case BPF_MEM:
			def = 0;
			use = dst;
			break;
		}
		break;
	case BPF_STX:
		switch (mode) {
		case BPF_MEM:
			def = 0;
			use = dst | src;
			break;
		case BPF_ATOMIC:
			switch (insn->imm) {
			case BPF_CMPXCHG:
				use = r0 | dst | src;
				def = r0;
				break;
			case BPF_LOAD_ACQ:
				def = dst;
				use = src;
				break;
			case BPF_STORE_REL:
				def = 0;
				use = dst | src;
				break;
			default:
				use = dst | src;
				if (insn->imm & BPF_FETCH)
					def = src;
				else
					def = 0;
			}
			break;
		}
		break;
	case BPF_ALU:
	case BPF_ALU64:
		switch (code) {
		case BPF_END:
			use = dst;
			def = dst;
			break;
		case BPF_MOV:
			def = dst;
			if (BPF_SRC(insn->code) == BPF_K)
				use = 0;
			else
				use = src;
			break;
		default:
			def = dst;
			if (BPF_SRC(insn->code) == BPF_K)
				use = dst;
			else
				use = dst | src;
		}
		break;
	case BPF_JMP:
	case BPF_JMP32:
		switch (code) {
		case BPF_JA:
			def = 0;
			if (BPF_SRC(insn->code) == BPF_X)
				use = dst;
			else
				use = 0;
			break;
		case BPF_JCOND:
			def = 0;
			use = 0;
			break;
		case BPF_EXIT:
			def = 0;
			use = r0;
			break;
		case BPF_CALL:
			def = ALL_CALLER_SAVED_REGS;
			use = def & ~BIT(BPF_REG_0);
			if (get_call_summary(env, insn, &cs))
				use = GENMASK(cs.num_params, 1);
			break;
		default:
			def = 0;
			if (BPF_SRC(insn->code) == BPF_K)
				use = dst;
			else
				use = dst | src;
		}
		break;
	}

	info->def = def;
	info->use = use;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int compute_live_registers(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *insn_aux = env->insn_aux_data;
	struct bpf_insn *insns = env->prog->insnsi;
	struct insn_live_regs *state;
	int insn_cnt = env->prog->len;
	int err = 0, i, j;
	bool changed;

	/* Use the following algorithm:
	 * - define the following:
	 *   - I.use : a set of all registers read by instruction I;
	 *   - I.def : a set of all registers written by instruction I;
	 *   - I.in  : a set of all registers that may be alive before I execution;
	 *   - I.out : a set of all registers that may be alive after I execution;
	 *   - insn_successors(I): a set of instructions S that might immediately
	 *                         follow I for some program execution;
	 * - associate separate empty sets 'I.in' and 'I.out' with each instruction;
	 * - visit each instruction in a postorder and update
	 *   state[i].in, state[i].out as follows:
	 *
	 *       state[i].out = U [state[s].in for S in insn_successors(i)]
	 *       state[i].in  = (state[i].out / state[i].def) U state[i].use
	 *
	 *   (where U stands for set union, / stands for set difference)
	 * - repeat the computation while {in,out} fields changes for
	 *   any instruction.
	 */
	state = kvzalloc_objs(*state, insn_cnt, GFP_KERNEL_ACCOUNT);
	if (!state) {
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < insn_cnt; ++i)
		compute_insn_live_regs(env, &insns[i], &state[i]);

	changed = true;
	while (changed) {
		changed = false;
		for (i = 0; i < env->cfg.cur_postorder; ++i) {
			int insn_idx = env->cfg.insn_postorder[i];
			struct insn_live_regs *live = &state[insn_idx];
			struct bpf_iarray *succ;
			u16 new_out = 0;
			u16 new_in = 0;

			succ = bpf_insn_successors(env, insn_idx);
			for (int s = 0; s < succ->cnt; ++s)
				new_out |= state[succ->items[s]].in;
			new_in = (new_out & ~live->def) | live->use;
			if (new_out != live->out || new_in != live->in) {
				live->in = new_in;
				live->out = new_out;
				changed = true;
			}
		}
	}

	for (i = 0; i < insn_cnt; ++i)
		insn_aux[i].live_regs_before = state[i].in;

	if (env->log.level & BPF_LOG_LEVEL2) {
		verbose(env, "Live regs before insn:\n");
		for (i = 0; i < insn_cnt; ++i) {
			if (env->insn_aux_data[i].scc)
				verbose(env, "%3d ", env->insn_aux_data[i].scc);
			else
				verbose(env, "    ");
			verbose(env, "%3d: ", i);
			for (j = BPF_REG_0; j < BPF_REG_10; ++j)
				if (insn_aux[i].live_regs_before & BIT(j))
					verbose(env, "%d", j);
				else
					verbose(env, ".");
			verbose(env, " ");
			verbose_insn(env, &insns[i]);
			if (bpf_is_ldimm64(&insns[i]))
				i++;
		}
	}

out:
	kvfree(state);
	return err;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int compute_postorder(struct bpf_verifier_env *env)
{
	u32 cur_postorder, i, top, stack_sz, s;
	int *stack = NULL, *postorder = NULL, *state = NULL;
	struct bpf_iarray *succ;

	postorder = kvzalloc_objs(int, env->prog->len, GFP_KERNEL_ACCOUNT);
	state = kvzalloc_objs(int, env->prog->len, GFP_KERNEL_ACCOUNT);
	stack = kvzalloc_objs(int, env->prog->len, GFP_KERNEL_ACCOUNT);
	if (!postorder || !state || !stack) {
		kvfree(postorder);
		kvfree(state);
		kvfree(stack);
		return -ENOMEM;
	}
	cur_postorder = 0;
	for (i = 0; i < env->subprog_cnt; i++) {
		env->subprog_info[i].postorder_start = cur_postorder;
		stack[0] = env->subprog_info[i].start;
		stack_sz = 1;
		do {
			top = stack[stack_sz - 1];
			state[top] |= DISCOVERED;
			if (state[top] & EXPLORED) {
				postorder[cur_postorder++] = top;
				stack_sz--;
				continue;
			}
			succ = bpf_insn_successors(env, top);
			for (s = 0; s < succ->cnt; ++s) {
				if (!state[succ->items[s]]) {
					stack[stack_sz++] = succ->items[s];
					state[succ->items[s]] |= DISCOVERED;
				}
			}
			state[top] |= EXPLORED;
		} while (stack_sz);
	}
	env->subprog_info[i].postorder_start = cur_postorder;
	env->cfg.insn_postorder = postorder;
	env->cfg.cur_postorder = cur_postorder;
	kvfree(stack);
	kvfree(state);
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int compute_scc(struct bpf_verifier_env *env)
{
	const u32 NOT_ON_STACK = U32_MAX;

	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	const u32 insn_cnt = env->prog->len;
	int stack_sz, dfs_sz, err = 0;
	u32 *stack, *pre, *low, *dfs;
	u32 i, j, t, w;
	u32 next_preorder_num;
	u32 next_scc_id;
	bool assign_scc;
	struct bpf_iarray *succ;

	next_preorder_num = 1;
	next_scc_id = 1;
	/*
	 * - 'stack' accumulates vertices in DFS order, see invariant comment below;
	 * - 'pre[t] == p' => preorder number of vertex 't' is 'p';
	 * - 'low[t] == n' => smallest preorder number of the vertex reachable from 't' is 'n';
	 * - 'dfs' DFS traversal stack, used to emulate explicit recursion.
	 */
	stack = kvcalloc(insn_cnt, sizeof(int), GFP_KERNEL_ACCOUNT);
	pre = kvcalloc(insn_cnt, sizeof(int), GFP_KERNEL_ACCOUNT);
	low = kvcalloc(insn_cnt, sizeof(int), GFP_KERNEL_ACCOUNT);
	dfs = kvcalloc(insn_cnt, sizeof(*dfs), GFP_KERNEL_ACCOUNT);
	if (!stack || !pre || !low || !dfs) {
		err = -ENOMEM;
		goto exit;
	}
	/*
	 * References:
	 * [1] R. Tarjan "Depth-First Search and Linear Graph Algorithms"
	 * [2] D. J. Pearce "A Space-Efficient Algorithm for Finding Strongly Connected Components"
	 *
	 * The algorithm maintains the following invariant:
	 * - suppose there is a path 'u' ~> 'v', such that 'pre[v] < pre[u]';
	 * - then, vertex 'u' remains on stack while vertex 'v' is on stack.
	 *
	 * Consequently:
	 * - If 'low[v] < pre[v]', there is a path from 'v' to some vertex 'u',
	 *   such that 'pre[u] == low[v]'; vertex 'u' is currently on the stack,
	 *   and thus there is an SCC (loop) containing both 'u' and 'v'.
	 * - If 'low[v] == pre[v]', loops containing 'v' have been explored,
	 *   and 'v' can be considered the root of some SCC.
	 *
	 * Here is a pseudo-code for an explicitly recursive version of the algorithm:
	 *
	 *    NOT_ON_STACK = insn_cnt + 1
	 *    pre = [0] * insn_cnt
	 *    low = [0] * insn_cnt
	 *    scc = [0] * insn_cnt
	 *    stack = []
	 *
	 *    next_preorder_num = 1
	 *    next_scc_id = 1
	 *
	 *    def recur(w):
	 *        nonlocal next_preorder_num
	 *        nonlocal next_scc_id
	 *
	 *        pre[w] = next_preorder_num
	 *        low[w] = next_preorder_num
	 *        next_preorder_num += 1
	 *        stack.append(w)
	 *        for s in successors(w):
	 *            # Note: for classic algorithm the block below should look as:
	 *            #
	 *            # if pre[s] == 0:
	 *            #     recur(s)
	 *            #	    low[w] = min(low[w], low[s])
	 *            # elif low[s] != NOT_ON_STACK:
	 *            #     low[w] = min(low[w], pre[s])
	 *            #
	 *            # But replacing both 'min' instructions with 'low[w] = min(low[w], low[s])'
	 *            # does not break the invariant and makes itartive version of the algorithm
	 *            # simpler. See 'Algorithm #3' from [2].
	 *
	 *            # 's' not yet visited
	 *            if pre[s] == 0:
	 *                recur(s)
	 *            # if 's' is on stack, pick lowest reachable preorder number from it;
	 *            # if 's' is not on stack 'low[s] == NOT_ON_STACK > low[w]',
	 *            # so 'min' would be a noop.
	 *            low[w] = min(low[w], low[s])
	 *
	 *        if low[w] == pre[w]:
	 *            # 'w' is the root of an SCC, pop all vertices
	 *            # below 'w' on stack and assign same SCC to them.
	 *            while True:
	 *                t = stack.pop()
	 *                low[t] = NOT_ON_STACK
	 *                scc[t] = next_scc_id
	 *                if t == w:
	 *                    break
	 *            next_scc_id += 1
	 *
	 *    for i in range(0, insn_cnt):
	 *        if pre[i] == 0:
	 *            recur(i)
	 *
	 * Below implementation replaces explicit recursion with array 'dfs'.
	 */
	for (i = 0; i < insn_cnt; i++) {
		if (pre[i])
			continue;
		stack_sz = 0;
		dfs_sz = 1;
		dfs[0] = i;
dfs_continue:
		while (dfs_sz) {
			w = dfs[dfs_sz - 1];
			if (pre[w] == 0) {
				low[w] = next_preorder_num;
				pre[w] = next_preorder_num;
				next_preorder_num++;
				stack[stack_sz++] = w;
			}
			/* Visit 'w' successors */
			succ = bpf_insn_successors(env, w);
			for (j = 0; j < succ->cnt; ++j) {
				if (pre[succ->items[j]]) {
					low[w] = min(low[w], low[succ->items[j]]);
				} else {
					dfs[dfs_sz++] = succ->items[j];
					goto dfs_continue;
				}
			}
			/*
			 * Preserve the invariant: if some vertex above in the stack
			 * is reachable from 'w', keep 'w' on the stack.
			 */
			if (low[w] < pre[w]) {
				dfs_sz--;
				goto dfs_continue;
			}
			/*
			 * Assign SCC number only if component has two or more elements,
			 * or if component has a self reference, or if instruction is a
			 * callback calling function (implicit loop).
			 */
			assign_scc = stack[stack_sz - 1] != w;	/* two or more elements? */
			for (j = 0; j < succ->cnt; ++j) {	/* self reference? */
				if (succ->items[j] == w) {
					assign_scc = true;
					break;
				}
			}
			if (bpf_calls_callback(env, w)) /* implicit loop? */
				assign_scc = true;
			/* Pop component elements from stack */
			do {
				t = stack[--stack_sz];
				low[t] = NOT_ON_STACK;
				if (assign_scc)
					aux[t].scc = next_scc_id;
			} while (t != w);
			if (assign_scc)
				next_scc_id++;
			dfs_sz--;
		}
	}
	env->scc_info = kvzalloc_objs(*env->scc_info, next_scc_id,
				      GFP_KERNEL_ACCOUNT);
	if (!env->scc_info) {
		err = -ENOMEM;
		goto exit;
	}
	env->scc_cnt = next_scc_id;
exit:
	kvfree(stack);
	kvfree(pre);
	kvfree(low);
	kvfree(dfs);
	return err;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool compute_scc_callchain(struct bpf_verifier_env *env,
				  struct bpf_verifier_state *st,
				  struct bpf_scc_callchain *callchain)
{
	u32 i, scc, insn_idx;

	memset(callchain, 0, sizeof(*callchain));
	for (i = 0; i <= st->curframe; i++) {
		insn_idx = frame_insn_idx(st, i);
		scc = env->insn_aux_data[insn_idx].scc;
		if (scc) {
			callchain->scc = scc;
			break;
		} else if (i < st->curframe) {
			callchain->callsites[i] = insn_idx;
		} else {
			return false;
		}
	}
	return true;
}



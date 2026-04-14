//! Missing types: BpfVerifierEnv, BpfMap, Btf, BpfSubprogInfo, BpfProg, BpfInsn, BpfKfuncBtfTab, BtfFuncModel, BpfKfuncDescTab, BpfProgAux, BpfKfuncMeta, BpfKfuncDesc, BpfSccBackedge, BpfVerifierState, BpfSccCallchain, BpfSccVisit

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

#[instrument(skip(env))]
pub fn add_fd_from_fd_array(env: &mut BpfVerifierEnv, fd: i32) -> Result<i32> {
    let f = fd;

    let map = __bpf_map_get(f);
    if !is_err(map) {
        inner_add_used_map(env, map).context("inner_add_used_map failed")?;
        return Ok(0);
    }

    let btf = __btf_get_by_fd(f);
    if !is_err(btf) {
        btf_get(btf);
        return inner_add_used_btf(env, btf).context("inner_add_used_btf failed");
    }

    verbose(env, format!("fd {fd} is not pointing to valid bpf_map or btf\n"));
    Err(anyhow!("PTR_ERR(map): invalid map/btf fd"))
}

#[instrument(skip(env, patch))]
pub fn add_hidden_subprog(env: &mut BpfVerifierEnv, patch: &[BpfInsn], len: i32) -> Result<i32> {
    let cnt = env.subprog_cnt;

    if env.hidden_subprog_cnt != 0 {
        verifier_bug(env, "only one hidden subprog supported");
        return Err(anyhow!("-EFAULT: only one hidden subprog supported"));
    }

    let prog = bpf_patch_insn_data(env, env.prog.len - 1, patch, len)
        .ok_or_else(|| anyhow!("-ENOMEM: bpf_patch_insn_data failed"))?;

    env.prog = prog;

    let info: &mut [BpfSubprogInfo] = env.subprog_info;
    info[(cnt + 1) as usize].start = info[cnt as usize].start;
    info[cnt as usize].start = env.prog.len - len + 1;
    env.subprog_cnt += 1;
    env.hidden_subprog_cnt += 1;
    Ok(0)
}

#[instrument(skip(env))]
pub fn add_kfunc_call(env: &mut BpfVerifierEnv, func_id: u32, offset: i16) -> Result<i32> {
    let prog_aux: &mut BpfProgAux = env.prog.aux;

    if prog_aux.kfunc_tab.is_none() {
        if !btf_vmlinux() {
            verbose(
                env,
                "calling kernel function is not supported without CONFIG_DEBUG_INFO_BTF\n",
            );
            return Err(anyhow!("-ENOTSUPP: CONFIG_DEBUG_INFO_BTF is required"));
        }

        if !env.prog.jit_requested {
            verbose(env, "JIT is required for calling kernel function\n");
            return Err(anyhow!("-ENOTSUPP: JIT is required"));
        }

        if !bpf_jit_supports_kfunc_call() {
            verbose(env, "JIT does not support calling kernel function\n");
            return Err(anyhow!("-ENOTSUPP: JIT does not support kfunc call"));
        }

        if !env.prog.gpl_compatible {
            verbose(
                env,
                "cannot call kernel function from non-GPL compatible program\n",
            );
            return Err(anyhow!("-EINVAL: non-GPL compatible program"));
        }

        prog_aux.kfunc_tab = Some(BpfKfuncDescTab::default());
    }

    if func_id == 0 && offset == 0 {
        return Ok(0);
    }

    if prog_aux.kfunc_btf_tab.is_none() && offset != 0 {
        prog_aux.kfunc_btf_tab = Some(BpfKfuncBtfTab::default());
    }

    if find_kfunc_desc(env.prog, func_id, offset).is_some() {
        return Ok(0);
    }

    let tab = prog_aux
        .kfunc_tab
        .as_mut()
        .ok_or_else(|| anyhow!("missing kfunc_tab"))?;

    if tab.nr_descs == MAX_KFUNC_DESCS {
        verbose(env, "too many different kernel function calls\n");
        return Err(anyhow!("-E2BIG: too many different kernel function calls"));
    }

    let mut kfunc = BpfKfuncMeta::default();
    fetch_kfunc_meta(env, func_id, offset, &mut kfunc).context("fetch_kfunc_meta failed")?;

    let addr = kallsyms_lookup_name(kfunc.name);
    if addr == 0 {
        verbose(
            env,
            format!("cannot find address for kernel function {}\n", kfunc.name),
        );
        return Err(anyhow!("-EINVAL: kernel function address not found"));
    }

    if bpf_dev_bound_kfunc_id(func_id) {
        bpf_dev_bound_kfunc_check(&env.log, prog_aux).context("bpf_dev_bound_kfunc_check failed")?;
    }

    let mut func_model = BtfFuncModel::default();
    btf_distill_func_proto(&env.log, kfunc.btf, kfunc.proto, kfunc.name, &mut func_model)
        .context("btf_distill_func_proto failed")?;

    let desc: &mut BpfKfuncDesc = &mut tab.descs[tab.nr_descs as usize];
    tab.nr_descs += 1;
    desc.func_id = func_id;
    desc.offset = offset;
    desc.addr = addr;
    desc.func_model = func_model;

    sort(
        &mut tab.descs,
        tab.nr_descs,
        core::mem::size_of::<BpfKfuncDesc>(),
        kfunc_desc_cmp_by_id_off,
        None,
    );
    Ok(0)
}

#[instrument(skip(env, insns))]
pub fn add_kfunc_in_insns(env: &mut BpfVerifierEnv, insns: &[BpfInsn], cnt: usize) -> Result<i32> {
    for insn in insns.iter().take(cnt) {
        if bpf_pseudo_kfunc_call(insn) {
            add_kfunc_call(env, insn.imm as u32, insn.off)
                .context("add_kfunc_call failed while scanning insns")?;
        }
    }
    Ok(0)
}

#[instrument(skip(env, st, backedge))]
pub fn add_scc_backedge(
    env: &mut BpfVerifierEnv,
    st: &BpfVerifierState,
    backedge: &mut BpfSccBackedge,
) -> Result<i32> {
    let callchain: &mut BpfSccCallchain = &mut env.callchain_buf;

    if !compute_scc_callchain(env, st, callchain) {
        verifier_bug(
            env,
            format!(
                "add backedge: no SCC in verification path, insn_idx {}",
                st.insn_idx
            ),
        );
        return Err(anyhow!("-EFAULT: no SCC in verification path"));
    }

    let visit: &mut BpfSccVisit = scc_visit_lookup(env, callchain)
        .ok_or_else(|| anyhow!("-EFAULT: no visit info for call chain"))?;

    if env.log.level & BPF_LOG_LEVEL2 != 0 {
        verbose(env, format!("SCC backedge {}\n", format_callchain(env, callchain)));
    }

    backedge.next = visit.backedges;
    visit.backedges = Some(backedge.clone());
    visit.num_backedges += 1;
    env.num_backedges += 1;
    update_peak_states(env);
    Ok(0)
}

#[instrument(skip(env))]
pub fn add_subprog(env: &mut BpfVerifierEnv, off: i32) -> Result<i32> {
    let insn_cnt = env.prog.len;

    if off >= insn_cnt || off < 0 {
        verbose(env, "call to invalid destination\n");
        return Err(anyhow!("-EINVAL: call to invalid destination"));
    }

    let ret = find_subprog(env, off);
    if ret >= 0 {
        return Ok(ret);
    }

    if env.subprog_cnt >= BPF_MAX_SUBPROGS {
        verbose(env, "too many subprograms\n");
        return Err(anyhow!("-E2BIG: too many subprograms"));
    }

    env.subprog_info[env.subprog_cnt as usize].start = off;
    env.subprog_cnt += 1;

    sort(
        &mut env.subprog_info,
        env.subprog_cnt,
        core::mem::size_of::<BpfSubprogInfo>(),
        cmp_subprogs,
        None,
    );

    Ok(env.subprog_cnt - 1)
}

#[instrument(skip(env))]
pub fn add_subprog_and_kfunc(env: &mut BpfVerifierEnv) -> Result<i32> {
    add_subprog(env, 0).context("failed to add entry subprog")?;

    let insns = env.prog.insnsi.clone();
    let insn_cnt = env.prog.len;

    for (i, insn) in insns.iter().enumerate().take(insn_cnt as usize) {
        if !bpf_pseudo_func(insn) && !bpf_pseudo_call(insn) && !bpf_pseudo_kfunc_call(insn) {
            continue;
        }

        if !env.bpf_capable {
            verbose(
                env,
                "loading/calling other bpf or kernel functions are allowed for CAP_BPF and CAP_SYS_ADMIN\n",
            );
            return Err(anyhow!("-EPERM: requires CAP_BPF and CAP_SYS_ADMIN"));
        }

        if bpf_pseudo_func(insn) || bpf_pseudo_call(insn) {
            add_subprog(env, i as i32 + insn.imm + 1)?;
        } else {
            add_kfunc_call(env, insn.imm as u32, insn.off)?;
        }
    }

    let ex_cb_insn = bpf_find_exception_callback_insn_off(env)
        .context("bpf_find_exception_callback_insn_off failed")?;

    if ex_cb_insn != 0 {
        add_subprog(env, ex_cb_insn)?;
        for i in 1..env.subprog_cnt as usize {
            if env.subprog_info[i].start != ex_cb_insn {
                continue;
            }
            env.exception_callback_subprog = i as i32;
            mark_subprog_exc_cb(env, i as i32);
            break;
        }
    }

    env.subprog_info[env.subprog_cnt as usize].start = insn_cnt;

    if env.log.level & BPF_LOG_LEVEL2 != 0 {
        for i in 0..env.subprog_cnt as usize {
            verbose(env, format!("func#{} @{}\n", i, env.subprog_info[i].start));
        }
    }

    Ok(0)
}

#[instrument(skip(env))]
pub fn add_used_map(env: &mut BpfVerifierEnv, fd: i32) -> Result<i32> {
    let f = fd;
    let map = __bpf_map_get(f);

    if is_err(map) {
        verbose(env, format!("fd {fd} is not pointing to valid bpf_map\n"));
        return Err(anyhow!("PTR_ERR(map): invalid bpf_map fd"));
    }

    inner_add_used_map(env, map).context("inner_add_used_map failed")
}

static int inner_add_used_btf(struct bpf_verifier_env *env, struct btf *btf)
{
	struct btf_mod_pair *btf_mod;
	int ret = 0;
	int i;

	/* check whether we recorded this BTF (and maybe module) already */
	for (i = 0; i < env->used_btf_cnt; i++)
		if (env->used_btfs[i].btf == btf)
			goto ret_put;

	if (env->used_btf_cnt >= MAX_USED_BTFS) {
		verbose(env, "The total number of btfs per program has reached the limit of %u\n",
			MAX_USED_BTFS);
		ret = -E2BIG;
		goto ret_put;
	}

	btf_mod = &env->used_btfs[env->used_btf_cnt];
	btf_mod->btf = btf;
	btf_mod->module = NULL;

	/* if we reference variables from kernel module, bump its refcount */
	if (btf_is_module(btf)) {
		btf_mod->module = btf_try_get_module(btf);
		if (!btf_mod->module) {
			ret = -ENXIO;
			goto ret_put;
		}
	}

	env->used_btf_cnt++;
	return 0;

ret_put:
	/* Either error or this BTF was already added */
	btf_put(btf);
	return ret;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int inner_add_used_map(struct bpf_verifier_env *env, struct bpf_map *map)
{
	int i, err;

	/* check whether we recorded this map already */
	for (i = 0; i < env->used_map_cnt; i++)
		if (env->used_maps[i] == map)
			return i;

	if (env->used_map_cnt >= MAX_USED_MAPS) {
		verbose(env, "The total number of maps per program has reached the limit of %u\n",
			MAX_USED_MAPS);
		return -E2BIG;
	}

	err = check_map_prog_compatibility(env, map, env->prog);
	if (err)
		return err;

	if (env->prog->sleepable)
		atomic64_inc(&map->sleepable_refcnt);

	/* hold the map. If the program is rejected by verifier,
	 * the map will be released by release_maps() or it
	 * will be used by the valid program until it's unloaded
	 * and all maps are released in bpf_free_used_maps()
	 */
	bpf_map_inc(map);

	env->used_maps[env->used_map_cnt++] = map;

	if (map->map_type == BPF_MAP_TYPE_INSN_ARRAY) {
		err = bpf_insn_array_init(map, env->prog);
		if (err) {
			verbose(env, "Failed to properly initialize insn array\n");
			return err;
		}
		env->insn_array_maps[env->insn_array_map_cnt++] = map;
	}

	return env->used_map_cnt - 1;
}

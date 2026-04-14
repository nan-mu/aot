// Extracted from /Users/nan/bs/aot/src/verifier.c
static char *format_callchain(struct bpf_verifier_env *env, struct bpf_scc_callchain *callchain)
{
	char *buf = env->tmp_str_buf;
	int i, delta = 0;

	delta += snprintf(buf + delta, TMP_STR_BUF_LEN - delta, "(");
	for (i = 0; i < ARRAY_SIZE(callchain->callsites); i++) {
		if (!callchain->callsites[i])
			break;
		delta += snprintf(buf + delta, TMP_STR_BUF_LEN - delta, "%u,",
				  callchain->callsites[i]);
	}
	delta += snprintf(buf + delta, TMP_STR_BUF_LEN - delta, "%u)", callchain->scc);
	return env->tmp_str_buf;
}



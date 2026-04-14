// Extracted from /Users/nan/bs/aot/src/verifier.c
static void fmt_reg_mask(char *buf, ssize_t buf_sz, u32 reg_mask)
{
	DECLARE_BITMAP(mask, 64);
	bool first = true;
	int i, n;

	buf[0] = '\0';

	bitmap_from_u64(mask, reg_mask);
	for_each_set_bit(i, mask, 32) {
		n = snprintf(buf, buf_sz, "%sr%d", first ? "" : ",", i);
		first = false;
		buf += n;
		buf_sz -= n;
		if (buf_sz < 0)
			break;
	}
}



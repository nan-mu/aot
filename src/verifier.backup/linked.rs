// Extracted from /Users/nan/bs/aot/src/verifier.c
static u64 linked_regs_pack(struct linked_regs *s)
{
	u64 val = 0;
	int i;

	for (i = 0; i < s->cnt; ++i) {
		struct linked_reg *e = &s->entries[i];
		u64 tmp = 0;

		tmp |= e->frameno;
		tmp |= e->spi << LR_SPI_OFF;
		tmp |= (e->is_reg ? 1 : 0) << LR_IS_REG_OFF;

		val <<= LR_ENTRY_BITS;
		val |= tmp;
	}
	val <<= LR_SIZE_BITS;
	val |= s->cnt;
	return val;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct linked_reg *linked_regs_push(struct linked_regs *s)
{
	if (s->cnt < LINKED_REGS_MAX)
		return &s->entries[s->cnt++];

	return NULL;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void linked_regs_unpack(u64 val, struct linked_regs *s)
{
	int i;

	s->cnt = val & LR_SIZE_MASK;
	val >>= LR_SIZE_BITS;

	for (i = 0; i < s->cnt; ++i) {
		struct linked_reg *e = &s->entries[i];

		e->frameno =  val & LR_FRAMENO_MASK;
		e->spi     = (val >> LR_SPI_OFF) & LR_SPI_MASK;
		e->is_reg  = (val >> LR_IS_REG_OFF) & 0x1;
		val >>= LR_ENTRY_BITS;
	}
}



// Extracted from /Users/nan/bs/aot/src/verifier.c
static inline void bt_clear_frame_reg(struct backtrack_state *bt, u32 frame, u32 reg)
{
	bt->reg_masks[frame] &= ~(1 << reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static inline void bt_clear_frame_slot(struct backtrack_state *bt, u32 frame, u32 slot)
{
	bt->stack_masks[frame] &= ~(1ull << slot);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static inline void bt_clear_reg(struct backtrack_state *bt, u32 reg)
{
	bt_clear_frame_reg(bt, bt->frame, reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static inline u32 bt_empty(struct backtrack_state *bt)
{
	u64 mask = 0;
	int i;

	for (i = 0; i <= bt->frame; i++)
		mask |= bt->reg_masks[i] | bt->stack_masks[i];

	return mask == 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static inline u32 bt_frame_reg_mask(struct backtrack_state *bt, u32 frame)
{
	return bt->reg_masks[frame];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static inline u64 bt_frame_stack_mask(struct backtrack_state *bt, u32 frame)
{
	return bt->stack_masks[frame];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static inline void bt_init(struct backtrack_state *bt, u32 frame)
{
	bt->frame = frame;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static inline bool bt_is_frame_reg_set(struct backtrack_state *bt, u32 frame, u32 reg)
{
	return bt->reg_masks[frame] & (1 << reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static inline bool bt_is_frame_slot_set(struct backtrack_state *bt, u32 frame, u32 slot)
{
	return bt->stack_masks[frame] & (1ull << slot);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static inline bool bt_is_reg_set(struct backtrack_state *bt, u32 reg)
{
	return bt->reg_masks[bt->frame] & (1 << reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static inline u32 bt_reg_mask(struct backtrack_state *bt)
{
	return bt->reg_masks[bt->frame];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static inline void bt_reset(struct backtrack_state *bt)
{
	struct bpf_verifier_env *env = bt->env;

	memset(bt, 0, sizeof(*bt));
	bt->env = env;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static inline void bt_set_frame_reg(struct backtrack_state *bt, u32 frame, u32 reg)
{
	bt->reg_masks[frame] |= 1 << reg;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static inline void bt_set_frame_slot(struct backtrack_state *bt, u32 frame, u32 slot)
{
	bt->stack_masks[frame] |= 1ull << slot;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static inline void bt_set_reg(struct backtrack_state *bt, u32 reg)
{
	bt_set_frame_reg(bt, bt->frame, reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static inline u64 bt_stack_mask(struct backtrack_state *bt)
{
	return bt->stack_masks[bt->frame];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static inline int bt_subprog_enter(struct backtrack_state *bt)
{
	if (bt->frame == MAX_CALL_FRAMES - 1) {
		verifier_bug(bt->env, "subprog enter from frame %d", bt->frame);
		return -EFAULT;
	}
	bt->frame++;
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static inline int bt_subprog_exit(struct backtrack_state *bt)
{
	if (bt->frame == 0) {
		verifier_bug(bt->env, "subprog exit from frame 0");
		return -EFAULT;
	}
	bt->frame--;
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void bt_sync_linked_regs(struct backtrack_state *bt, struct bpf_jmp_history_entry *hist)
{
	struct linked_regs linked_regs;
	bool some_precise = false;
	int i;

	if (!hist || hist->linked_regs == 0)
		return;

	linked_regs_unpack(hist->linked_regs, &linked_regs);
	for (i = 0; i < linked_regs.cnt; ++i) {
		struct linked_reg *e = &linked_regs.entries[i];

		if ((e->is_reg && bt_is_frame_reg_set(bt, e->frameno, e->regno)) ||
		    (!e->is_reg && bt_is_frame_slot_set(bt, e->frameno, e->spi))) {
			some_precise = true;
			break;
		}
	}

	if (!some_precise)
		return;

	for (i = 0; i < linked_regs.cnt; ++i) {
		struct linked_reg *e = &linked_regs.entries[i];

		if (e->is_reg)
			bt_set_frame_reg(bt, e->frameno, e->regno);
		else
			bt_set_frame_slot(bt, e->frameno, e->spi);
	}
}



// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool try_match_pkt_pointers(const struct bpf_insn *insn,
				   struct bpf_reg_state *dst_reg,
				   struct bpf_reg_state *src_reg,
				   struct bpf_verifier_state *this_branch,
				   struct bpf_verifier_state *other_branch)
{
	if (BPF_SRC(insn->code) != BPF_X)
		return false;

	/* Pointers are always 64-bit. */
	if (BPF_CLASS(insn->code) == BPF_JMP32)
		return false;

	switch (BPF_OP(insn->code)) {
	case BPF_JGT:
		if ((dst_reg->type == PTR_TO_PACKET &&
		     src_reg->type == PTR_TO_PACKET_END) ||
		    (dst_reg->type == PTR_TO_PACKET_META &&
		     reg_is_init_pkt_pointer(src_reg, PTR_TO_PACKET))) {
			/* pkt_data' > pkt_end, pkt_meta' > pkt_data */
			find_good_pkt_pointers(this_branch, dst_reg,
					       dst_reg->type, false);
			mark_pkt_end(other_branch, insn->dst_reg, true);
		} else if ((dst_reg->type == PTR_TO_PACKET_END &&
			    src_reg->type == PTR_TO_PACKET) ||
			   (reg_is_init_pkt_pointer(dst_reg, PTR_TO_PACKET) &&
			    src_reg->type == PTR_TO_PACKET_META)) {
			/* pkt_end > pkt_data', pkt_data > pkt_meta' */
			find_good_pkt_pointers(other_branch, src_reg,
					       src_reg->type, true);
			mark_pkt_end(this_branch, insn->src_reg, false);
		} else {
			return false;
		}
		break;
	case BPF_JLT:
		if ((dst_reg->type == PTR_TO_PACKET &&
		     src_reg->type == PTR_TO_PACKET_END) ||
		    (dst_reg->type == PTR_TO_PACKET_META &&
		     reg_is_init_pkt_pointer(src_reg, PTR_TO_PACKET))) {
			/* pkt_data' < pkt_end, pkt_meta' < pkt_data */
			find_good_pkt_pointers(other_branch, dst_reg,
					       dst_reg->type, true);
			mark_pkt_end(this_branch, insn->dst_reg, false);
		} else if ((dst_reg->type == PTR_TO_PACKET_END &&
			    src_reg->type == PTR_TO_PACKET) ||
			   (reg_is_init_pkt_pointer(dst_reg, PTR_TO_PACKET) &&
			    src_reg->type == PTR_TO_PACKET_META)) {
			/* pkt_end < pkt_data', pkt_data > pkt_meta' */
			find_good_pkt_pointers(this_branch, src_reg,
					       src_reg->type, false);
			mark_pkt_end(other_branch, insn->src_reg, true);
		} else {
			return false;
		}
		break;
	case BPF_JGE:
		if ((dst_reg->type == PTR_TO_PACKET &&
		     src_reg->type == PTR_TO_PACKET_END) ||
		    (dst_reg->type == PTR_TO_PACKET_META &&
		     reg_is_init_pkt_pointer(src_reg, PTR_TO_PACKET))) {
			/* pkt_data' >= pkt_end, pkt_meta' >= pkt_data */
			find_good_pkt_pointers(this_branch, dst_reg,
					       dst_reg->type, true);
			mark_pkt_end(other_branch, insn->dst_reg, false);
		} else if ((dst_reg->type == PTR_TO_PACKET_END &&
			    src_reg->type == PTR_TO_PACKET) ||
			   (reg_is_init_pkt_pointer(dst_reg, PTR_TO_PACKET) &&
			    src_reg->type == PTR_TO_PACKET_META)) {
			/* pkt_end >= pkt_data', pkt_data >= pkt_meta' */
			find_good_pkt_pointers(other_branch, src_reg,
					       src_reg->type, false);
			mark_pkt_end(this_branch, insn->src_reg, true);
		} else {
			return false;
		}
		break;
	case BPF_JLE:
		if ((dst_reg->type == PTR_TO_PACKET &&
		     src_reg->type == PTR_TO_PACKET_END) ||
		    (dst_reg->type == PTR_TO_PACKET_META &&
		     reg_is_init_pkt_pointer(src_reg, PTR_TO_PACKET))) {
			/* pkt_data' <= pkt_end, pkt_meta' <= pkt_data */
			find_good_pkt_pointers(other_branch, dst_reg,
					       dst_reg->type, false);
			mark_pkt_end(this_branch, insn->dst_reg, true);
		} else if ((dst_reg->type == PTR_TO_PACKET_END &&
			    src_reg->type == PTR_TO_PACKET) ||
			   (reg_is_init_pkt_pointer(dst_reg, PTR_TO_PACKET) &&
			    src_reg->type == PTR_TO_PACKET_META)) {
			/* pkt_end <= pkt_data', pkt_data <= pkt_meta' */
			find_good_pkt_pointers(this_branch, src_reg,
					       src_reg->type, true);
			mark_pkt_end(other_branch, insn->src_reg, false);
		} else {
			return false;
		}
		break;
	default:
		return false;
	}

	return true;
}



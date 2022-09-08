#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static const u8 one = 1;
pid_t target_pid = 0;
#define MAP_SHIFT (12 + 9)
#define MIXED_NODES -1
#define MIXED_MEM -1

struct region_stat {
  u16 accesses;
  s8 mem_type; /* NON_ANON, ANON */
  s8 node_id;
};

struct heatmap_outer {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 1000000);
  __type(key, u64);
  __type(value, struct region_stat);
} heatmap SEC(".maps");

int probe(unsigned int nid, unsigned long addr, unsigned long len, bool anon) {
  u64 map_key = addr >> MAP_SHIFT;
  struct region_stat *region = bpf_map_lookup_elem(&heatmap, &map_key);
  int err;
  struct region_stat to_insert;

  if (!region) {
    to_insert.accesses = len;
    to_insert.mem_type = anon;
    to_insert.node_id = nid;
    err = bpf_map_update_elem(&heatmap, &map_key, &to_insert, BPF_NOEXIST);
    if (err) {
      return err;
    }
  } else {
    region->accesses += len;
    if (region->node_id != (int)nid) {
      region->node_id = MIXED_NODES;
		}
		if (region->mem_type != anon) {
			region->mem_type = MIXED_MEM;
		}
		err = bpf_map_update_elem(&heatmap, &map_key, region, BPF_EXIST);
		if (err) {
			return err;
		}
	}
	return 0;
}

SEC("fentry/mglru_pte_probe")
int BPF_PROG(fentry_mglru_pte_probe, pid_t pid, unsigned int nid,
             unsigned long addr, unsigned long len, bool anon) {
  int err;
	if (pid != target_pid)
		return 0;
	err = probe(nid, addr, len, anon);
	if (err)
		bpf_printk("PTE called addr:0x%lx len:%lu error:%ld", addr, len, err);
	return 0;
}

SEC("fentry/mglru_pmd_probe")
int BPF_PROG(fentry_mglru_pmd_probe, pid_t pid, unsigned int nid,
             unsigned long addr, unsigned long len, bool anon) {
  int err;
  if (pid != target_pid)
		return 0;
  err = probe(nid, addr, len, anon);
	if (err)
		bpf_printk("PMD called addr:0x%lx len:%lu error:%ld", addr, len, err);
  return 0;
}

extern void bpf_set_skip_mm(
    struct bpf_mglru_should_skip_mm_control *should_skip) __ksym;

SEC("fentry/bpf_mglru_should_skip_mm")
int BPF_PROG(bpf_mglru_should_skip_mm,
             struct bpf_mglru_should_skip_mm_control *ctl) {
  if (ctl->pid != target_pid) {
				bpf_printk("aging wrong pid");
    bpf_set_skip_mm(ctl);
	}
  return 0;
}

extern int bpf_run_aging(int memcg_id, bool can_swap, bool force_scan) __ksym;

struct args {
  int memcg_id;
};

SEC("syscall")
int memcg_run_aging(struct args *ctx) {
  int err;

  err = bpf_run_aging(ctx->memcg_id, true, true);

  if (err != 0) {
    bpf_printk("aging failed for memcg %ld with error %ld", ctx->memcg_id, err);
    return 0;
  }

  bpf_printk("aging succeeded for memcg %ld", ctx->memcg_id);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";

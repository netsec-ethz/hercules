 .section ".rodata"

# load bpf_prgm_pass babf5a391b02f9eb4a185cd89f1c743c
 .globl bpf_prgm_pass
 .type bpf_prgm_pass, STT_OBJECT
 .globl bpf_prgm_pass_size
 .type bpf_prgm_pass_size, STT_OBJECT
bpf_prgm_pass:
 .incbin "bpf_prgm/pass.o"
 .byte 0
 .size bpf_prgm_pass, .-bpf_prgm_pass
bpf_prgm_pass_size:
 .int (.-bpf_prgm_pass-1)

# load bpf_prgm_redirect_userspace f87c1728a3f6dd56bee8331074f2ff10
 .globl bpf_prgm_redirect_userspace
 .type bpf_prgm_redirect_userspace, STT_OBJECT
 .globl bpf_prgm_redirect_userspace_size
 .type bpf_prgm_redirect_userspace_size, STT_OBJECT
bpf_prgm_redirect_userspace:
 .incbin "bpf_prgm/redirect_userspace.o"
 .byte 0
 .size bpf_prgm_redirect_userspace, .-bpf_prgm_redirect_userspace
bpf_prgm_redirect_userspace_size:
 .int (.-bpf_prgm_redirect_userspace-1)

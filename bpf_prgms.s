 .section ".rodata"

# load bpf_prgm_pass 2020-09-22 13:03:39
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

# load bpf_prgm_redirect_userspace 2020-09-22 14:47:59
 .globl bpf_prgm_redirect_userspace
 .type bpf_prgm_redirect_userspace, STT_OBJECT
 .globl bpf_prgm_redirect_userspace_size
 .type bpf_prgm_redirect_userspace_size, STT_OBJECT
bpf_prgm_redirect_userspace:
 .incbin "bpf_prgm/redirect_userspace.o" # content hash
 .byte 0
 .size bpf_prgm_redirect_userspace, .-bpf_prgm_redirect_userspace
bpf_prgm_redirect_userspace_size:
 .int (.-bpf_prgm_redirect_userspace-1)

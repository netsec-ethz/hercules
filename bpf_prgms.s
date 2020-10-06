 .section ".rodata"

# load bpf_prgm_pass 35ed2864c814f692a0c7aa875af3039f
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

# load bpf_prgm_redirect_userspace ae18bda83dc928658656cc53de4cb90f
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

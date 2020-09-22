#ifndef HERCULES_BPF_PRGMS_H
#define HERCULES_BPF_PRGMS_H

// these programs get loaded in bpf_prgms.s

/* Dummy BPF passing all packets to the traditional network stack */
extern const char bpf_prgm_pass[];
extern u32 bpf_prgm_pass_size;

/* The BPF program to parse packets and redirect Hercules packets to user space */
extern const char bpf_prgm_redirect_userspace[];
extern u32 bpf_prgm_redirect_userspace_size;

#endif //HERCULES_BPF_PRGMS_H

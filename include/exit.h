#pragma once

#include <linux/types.h>
#include "cpu.h"

/*
*   vm-exit context containing exit information
*/
struct vmexit_ctx {
    struct gp_regs *regs;
    
    // exit information from vmcs
    VMX_VMEXIT_REASON exit_reason;
    u64 exit_qualification;
    u64 guest_rip;
    u64 guest_rsp;
    u64 guest_rflags;
    u64 guest_physical_addr;
    u32 instruction_length;
    u32 instruction_info;
    
    // exit behavior flags
    bool should_advance_rip;
    bool should_exit_vmx;
};

/*
*   main vm-exit handler called from assembly
*   returns 0 to continue guest execution, non-zero to exit vmx
*/
int vmexit_handler(struct cpu_ctx *cpu, struct gp_regs *regs);

/*
*   handle vm-exit failure (vmresume failed)
*/
void vmexit_failure_handler(struct cpu_ctx *cpu, struct gp_regs *regs);

/*
*   individual exit handlers
*/
int vmexit_handle_cpuid(struct cpu_ctx *cpu, struct vmexit_ctx *ctx);
int vmexit_handle_msr_read(struct cpu_ctx *cpu, struct vmexit_ctx *ctx);
int vmexit_handle_msr_write(struct cpu_ctx *cpu, struct vmexit_ctx *ctx);
int vmexit_handle_mov_cr(struct cpu_ctx *cpu, struct vmexit_ctx *ctx);
int vmexit_handle_vmcall(struct cpu_ctx *cpu, struct vmexit_ctx *ctx);
int vmexit_handle_ept_violation(struct cpu_ctx *cpu, struct vmexit_ctx *ctx);
int vmexit_handle_ept_misconfig(struct cpu_ctx *cpu, struct vmexit_ctx *ctx);
int vmexit_handle_xsetbv(struct cpu_ctx *cpu, struct vmexit_ctx *ctx);
int vmexit_handle_invd(struct cpu_ctx *cpu, struct vmexit_ctx *ctx);

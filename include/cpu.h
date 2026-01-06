#pragma once

#include <linux/types.h>
#include "ia32/ia32_wrapper.h"
#include "arch.h"

#define VMX_HOST_STACK_SIZE (PAGE_SIZE * 4)

struct vmm_ctx;

/*
*   host stack region with cpu context pointer at top
*   stack grows downward so cpu pointer is at highest address
*/
struct host_stack {
    u8 stack[VMX_HOST_STACK_SIZE - sizeof(void *)];
    struct cpu_ctx *cpu;
} __aligned(PAGE_SIZE);

/*
*   per-cpu vmx context
*/
struct cpu_ctx {
    struct vmm_ctx *vmm;
    unsigned int cpu_id;
    
    bool virtualized;
    bool failed;
    bool nested;
    
    // vmxon region (4kb aligned)
    VMXON *vmxon;
    phys_addr_t vmxon_phys;
    
    // vmcs region (4kb aligned)
    VMCS *vmcs;
    phys_addr_t vmcs_phys;
    
    // msr bitmap (4kb)
    VMX_MSR_BITMAP *msr_bitmap;
    phys_addr_t msr_bitmap_phys;
    
    // host stack for vm-exit handling
    struct host_stack *host_stack;
    
    // original cr0/cr4 before vmx modifications
    CR0 orig_cr0;
    CR4 orig_cr4;
    
    // captured cpu state at virtualization
    struct hv_cpu_state state;
    
    // guest resume state
    u64 guest_rsp;
    u64 guest_rip;
    u64 guest_rflags;
    
    // vm-exit handler entry point
    void *vmexit_handler;
    
    // ept pointer for this cpu
    EPT_POINTER eptp;
};

/*
*   register state saved on vm-exit
*   must match assembly layout
*/
struct gp_regs {
    u64 r15;
    u64 r14;
    u64 r13;
    u64 r12;
    u64 r11;
    u64 r10;
    u64 r9;
    u64 r8;
    u64 rdi;
    u64 rsi;
    u64 rdx;
    u64 rcx;
    u64 rbx;
    u64 rax;
    u64 _pad;   // placeholder for rsp (read from vmcs)
    u64 rbp;
} __aligned(16);

/*
*   cpu context functions
*/
int cpu_ctx_init(struct cpu_ctx *cpu, struct vmm_ctx *vmm, unsigned int cpu_id);
void cpu_ctx_destroy(struct cpu_ctx *cpu);
int cpu_virtualize(struct cpu_ctx *cpu);
void cpu_devirtualize(struct cpu_ctx *cpu);

/*
*   called from assembly after saving register state
*/
void cpu_vmx_init_from_guest(struct vmm_ctx *vmm, u64 guest_rsp, u64 guest_rip, u64 guest_rflags);
void cpu_vmx_init(struct cpu_ctx *cpu, u64 guest_rsp, u64 guest_rip, u64 guest_rflags);

/*
*   assembly entry points (vmxasm.S)
*/
extern void vmx_launch_guest(void *vmm_ctx);
extern void vmx_vmexit_handler(void);
extern void vmx_guest_resume(void);
extern void vmx_detach_guest(struct gp_regs *regs);

#pragma once

#include <linux/types.h>
#include "ia32/ia32_wrapper.h"
#include "cpu.h"

#define VMXON_SIZE PAGE_SIZE
#define VMCS_SIZE  PAGE_SIZE

enum vmx_error {
    VMX_OK = 0,
    VMX_ERROR_WITH_STATUS = 1,
    VMX_ERROR_WITHOUT_STATUS = 2,
};

/*
*   allocate and initialize vmxon region
*/
VMXON *vmx_alloc_vmxon(struct cpu_ctx *cpu);

/*
*   allocate and initialize vmcs region
*/
VMCS *vmx_alloc_vmcs(struct cpu_ctx *cpu);

/*
*   allocate msr bitmap
*/
VMX_MSR_BITMAP *vmx_alloc_msr_bitmap(void);

/*
*   enter vmx root operation (vmxon)
*/
int vmx_enter_root(struct cpu_ctx *cpu);

/*
*   exit vmx root operation (vmxoff)
*/
int vmx_exit_root(struct cpu_ctx *cpu);

/*
*   setup and configure vmcs
*/
int vmx_setup_vmcs(struct cpu_ctx *cpu);

/*
*   launch the virtual machine (vmlaunch)
*/
int vmx_launch(struct cpu_ctx *cpu);

/*
*   set cr0/cr4 fixed bits required for vmx operation
*/
void vmx_set_fixed_bits(struct cpu_ctx *cpu);

/*
*   restore original cr0/cr4 values
*/
void vmx_restore_fixed_bits(struct cpu_ctx *cpu);

/*
*   read vmx instruction error from vmcs
*/
u64 vmx_get_error(void);

/*
*   configure msr bitmap for specific msr interception
*/
void vmx_set_msr_intercept(VMX_MSR_BITMAP *bitmap, u32 msr, bool read, bool write);

/*
*   invvpid types per intel sdm
*/
#define INVVPID_INDIVIDUAL_ADDRESS      0
#define INVVPID_SINGLE_CONTEXT          1
#define INVVPID_ALL_CONTEXT             2
#define INVVPID_SINGLE_CONTEXT_RETAINING_GLOBALS 3

/*
*   invvpid descriptor
*/
struct invvpid_desc {
    u64 vpid;
    u64 linear_addr;
};

/*
*   execute invvpid instruction
*/
static inline void vmx_invvpid(u64 type, u16 vpid, u64 linear_addr)
{
    struct invvpid_desc desc = {
        .vpid = vpid,
        .linear_addr = linear_addr
    };
    
    asm volatile("invvpid %1, %0"
                 :
                 : "r"(type), "m"(desc)
                 : "cc", "memory");
}

/*
*   invalidate all vpid contexts
*/
static inline void vmx_invvpid_all(void)
{
    vmx_invvpid(INVVPID_ALL_CONTEXT, 0, 0);
}

/*
*   invalidate single vpid context
*/
static inline void vmx_invvpid_single(u16 vpid)
{
    vmx_invvpid(INVVPID_SINGLE_CONTEXT, vpid, 0);
}

/*
*   invalidate single vpid context retaining global translations
*/
static inline void vmx_invvpid_single_retain_globals(u16 vpid)
{
    vmx_invvpid(INVVPID_SINGLE_CONTEXT_RETAINING_GLOBALS, vpid, 0);
}

/*
*   invalidate individual address in vpid context
*/
static inline void invvpid_individual_address(u16 vpid, u64 linear_addr)
{
    vmx_invvpid(INVVPID_INDIVIDUAL_ADDRESS, vpid, linear_addr);
}

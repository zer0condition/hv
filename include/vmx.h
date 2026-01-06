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

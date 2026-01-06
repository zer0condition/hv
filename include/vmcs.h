#pragma once

#include <linux/types.h>
#include "ia32/ia32_wrapper.h"
#include "cpu.h"

/*
*   initialize the vmcs for the given cpu
*/
int vmcs_init(struct cpu_ctx *cpu);

/*
*   setup vmcs guest state area
*/
int vmcs_setup_guest(struct cpu_ctx *cpu);

/*
*   setup vmcs host state area
*/
int vmcs_setup_host(struct cpu_ctx *cpu);

/*
*   setup vmcs control fields
*/
int vmcs_setup_controls(struct cpu_ctx *cpu);

/*
*   validate vmcs configuration
*/
int vmcs_validate(struct cpu_ctx *cpu);

/*
*   helper to encode "must be" bits for vm execution controls
*/
static inline u32 vmcs_encode_controls(u32 desired, u64 msr_value)
{
    u32 allowed_0 = (u32)msr_value;
    u32 allowed_1 = (u32)(msr_value >> 32);
    return (desired | allowed_0) & allowed_1;
}

/*
*   helper to setup segment access rights for vmcs
*/
static inline u32 vmcs_segment_access_rights(u32 access_rights)
{
    VMX_SEGMENT_ACCESS_RIGHTS ar = {.AsUInt = access_rights};
    if (ar.Unusable)
        return access_rights;
    return access_rights;
}

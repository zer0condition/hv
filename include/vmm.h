#pragma once

#include <linux/types.h>
#include "ia32/ia32_wrapper.h"
#include "cpu.h"
#include "ept.h"

struct cpu_ctx;
struct ept_state;

/*
*   global vmm context shared across all cpus
*/
struct vmm_ctx {
    unsigned int num_cpus;
    unsigned int num_virtualized;
    
    // per-cpu contexts array
    struct cpu_ctx *cpu_ctxs;
    
    // vmx capabilities from ia32_vmx_basic
    IA32_VMX_BASIC_REGISTER vmx_caps;
    
    // ept state (shared across cpus)
    struct ept_state *ept;
    
    // mtrr configuration for ept memory types
    struct {
        u64 default_type;
        unsigned int num_ranges;
        struct {
            u64 base;
            u64 end;
            u8 type;
        } ranges[16];
    } mtrr;
};

/*
*   vmm lifecycle functions
*/
struct vmm_ctx *vmm_init(void);
void vmm_shutdown(struct vmm_ctx *vmm);
int vmm_start(struct vmm_ctx *vmm);
void vmm_stop(struct vmm_ctx *vmm);

/*
*   utility functions
*/
bool vmm_check_vmx_support(void);

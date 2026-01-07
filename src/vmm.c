/*
*   vmm.c - virtual machine monitor initialization and control
*/

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/atomic.h>
#include <linux/delay.h>
#include "vmm.h"
#include "cpu.h"
#include "vmx.h"
#include "ept.h"
#include "arch.h"
#include "hv.h"

/*
*   check if system supports vmx
*/
bool vmm_check_vmx_support(void)
{
    if (!arch_cpu_has_vmx()) {
        hv_log(err, "cpu does not support vmx\n");
        return false;
    }
    
    if (!arch_vmx_enabled_by_bios()) {
        hv_log(err, "vmx not enabled in bios\n");
        return false;
    }
    
    return true;
}

/*
*   read mtrr configuration for ept memory types
*/
static void vmm_read_mtrr(struct vmm_ctx *vmm)
{
    IA32_MTRR_DEF_TYPE_REGISTER def_type;
    IA32_MTRR_CAPABILITIES_REGISTER mtrr_cap;
    unsigned int i;
    
    def_type.AsUInt = native_read_msr(IA32_MTRR_DEF_TYPE);
    vmm->mtrr.default_type = def_type.DefaultMemoryType;
    
    if (!def_type.MtrrEnable) {
        hv_log(info, "mtrrs disabled, using default type %llu\n",
               vmm->mtrr.default_type);
        vmm->mtrr.num_ranges = 0;
        return;
    }
    
    mtrr_cap.AsUInt = native_read_msr(IA32_MTRR_CAPABILITIES);
    
    vmm->mtrr.num_ranges = 0;
    for (i = 0; i < mtrr_cap.VariableRangeCount && i < 16; i++) {
        IA32_MTRR_PHYSBASE_REGISTER base;
        IA32_MTRR_PHYSMASK_REGISTER mask;
        u64 range_base, range_size, range_end;
        
        base.AsUInt = native_read_msr(IA32_MTRR_PHYSBASE0 + i * 2);
        mask.AsUInt = native_read_msr(IA32_MTRR_PHYSMASK0 + i * 2);
        
        if (!mask.Valid)
            continue;
        
        if (vmm->mtrr.num_ranges >= 16) {
            hv_log(warn, "max mtrr ranges (%u) reached, ignoring additional ranges\n", 16);
            break;
        }
        
        range_base = base.PageFrameNumber << 12;
        range_size = (~(mask.PageFrameNumber << 12) + 1) & HV_PHYS_ADDR_MASK;
        range_end = range_base + range_size - 1;
        
        vmm->mtrr.ranges[vmm->mtrr.num_ranges].base = range_base;
        vmm->mtrr.ranges[vmm->mtrr.num_ranges].end = range_end;
        vmm->mtrr.ranges[vmm->mtrr.num_ranges].type = base.Type;
        vmm->mtrr.num_ranges++;
        
        hv_log(debug, "mtrr range %u: 0x%llx-0x%llx type=%u\n",
               i, range_base, range_end, base.Type);
    }
}

/*
*   per-cpu initialization callback
*/
static void vmm_cpu_init(void *data)
{
    struct vmm_ctx *vmm = data;
    unsigned int cpu_id = smp_processor_id();
    struct cpu_ctx *cpu = &vmm->cpu_ctxs[cpu_id];
    
    hv_cpu_log(info, "initializing virtualization\n");
    
    if (cpu_virtualize(cpu) == 0) {
        atomic_inc(&vmm->num_virtualized);
        hv_cpu_log(info, "successfully virtualized\n");
    } else {
        cpu->failed = true;
        hv_cpu_log(err, "failed to virtualize\n");
    }
}

/*
*   initialize vmm context
*/
struct vmm_ctx *vmm_init(void)
{
    struct vmm_ctx *vmm;
    unsigned int i;
    
    if (!vmm_check_vmx_support())
        return NULL;
    
    vmm = kzalloc(sizeof(*vmm), GFP_KERNEL);
    if (!vmm) {
        hv_log(err, "failed to allocate vmm context\n");
        return NULL;
    }
    
    vmm->num_cpus = num_online_cpus();
    atomic_set(&vmm->num_virtualized, 0);
    vmm->should_exit = false;
    vmm->vmx_caps.AsUInt = native_read_msr(IA32_VMX_BASIC);
    
    hv_log(info, "vmx capabilities:\n");
    hv_log(info, "  vmcs revision: %u\n", vmm->vmx_caps.VmcsRevisionId);
    hv_log(info, "  vmcs size: %u bytes\n", (unsigned int)vmm->vmx_caps.VmcsSizeInBytes);
    hv_log(info, "  true controls: %s\n", 
           vmm->vmx_caps.VmxControls ? "yes" : "no");
    
    vmm_read_mtrr(vmm);
    
    vmm->cpu_ctxs = kzalloc(sizeof(struct cpu_ctx) * vmm->num_cpus, GFP_KERNEL);
    if (!vmm->cpu_ctxs) {
        hv_log(err, "failed to allocate cpu contexts\n");
        kfree(vmm);
        return NULL;
    }
    
    for (i = 0; i < vmm->num_cpus; i++) {
        if (cpu_ctx_init(&vmm->cpu_ctxs[i], vmm, i) != 0) {
            hv_log(err, "failed to initialize cpu %u context\n", i);
            goto fail;
        }
    }
    
    vmm->ept = ept_init(vmm);
    if (!vmm->ept) {
        hv_log(err, "failed to initialize ept\n");
        goto fail;
    }
    
    return vmm;

fail:
    for (i = 0; i < vmm->num_cpus; i++)
        cpu_ctx_destroy(&vmm->cpu_ctxs[i]);
    kfree(vmm->cpu_ctxs);
    kfree(vmm);
    return NULL;
}

/*
*   start hypervisor on all cpus
*/
int vmm_start(struct vmm_ctx *vmm)
{
    hv_log(info, "starting hypervisor on %u cpus\n", vmm->num_cpus);
    
    on_each_cpu(vmm_cpu_init, vmm, 1);
    
    if (atomic_read(&vmm->num_virtualized) != vmm->num_cpus) {
        hv_log(err, "only %d/%u cpus virtualized\n",
               atomic_read(&vmm->num_virtualized), vmm->num_cpus);
        return -1;
    }
    
    hv_log(info, "hypervisor started successfully\n");
    return 0;
}

/*
*   stop hypervisor on all cpus
*   uses flag-based approach to avoid IPI corruption
*/
void vmm_stop(struct vmm_ctx *vmm)
{
    unsigned int i;
    int timeout;
    
    hv_log(info, "stopping hypervisor\n");
    
    WRITE_ONCE(vmm->should_exit, true);
    
    kick_all_cpus_sync();
    
    timeout = 1000;
    while (timeout > 0) {
        bool all_done = true;
        for (i = 0; i < vmm->num_cpus; i++) {
            if (vmm->cpu_ctxs[i].virtualized) {
                all_done = false;
                break;
            }
        }
        if (all_done)
            break;
        msleep(1);
        timeout--;
    }
    
    if (timeout == 0) {
        hv_log(warn, "timeout waiting for CPUs to devirtualize\n");
    }
    
    hv_log(info, "hypervisor stopped\n");
}

/*
*   shutdown and free vmm
*/
void vmm_shutdown(struct vmm_ctx *vmm)
{
    unsigned int i;
    
    if (!vmm)
        return;
    
    vmm_stop(vmm);
    
    if (vmm->ept)
        ept_destroy(vmm->ept);
    
    for (i = 0; i < vmm->num_cpus; i++)
        cpu_ctx_destroy(&vmm->cpu_ctxs[i]);
    
    kfree(vmm->cpu_ctxs);
    kfree(vmm);
}

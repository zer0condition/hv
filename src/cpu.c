/*
*   cpu.c - per-cpu virtualization context management
*/

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/io.h>

#include "cpu.h"
#include "vmm.h"
#include "vmx.h"
#include "vmcs.h"
#include "arch.h"
#include "exit.h"
#include "hv.h"

/*
*   initialize per-cpu context
*/
int cpu_ctx_init(struct cpu_ctx *cpu, struct vmm_ctx *vmm, unsigned int cpu_id)
{
    cpu->vmm = vmm;
    cpu->cpu_id = cpu_id;
    cpu->virtualized = false;
    cpu->failed = false;
    cpu->vmexit_handler = vmx_vmexit_handler;
    
    // allocate vmxon region
    cpu->vmxon = vmx_alloc_vmxon(cpu);
    if (!cpu->vmxon) {
        hv_cpu_log(err, "failed to allocate vmxon region\n");
        return -ENOMEM;
    }
    cpu->vmxon_phys = virt_to_phys(cpu->vmxon);
    
    // allocate vmcs
    cpu->vmcs = vmx_alloc_vmcs(cpu);
    if (!cpu->vmcs) {
        hv_cpu_log(err, "failed to allocate vmcs region\n");
        goto fail_vmcs;
    }
    cpu->vmcs_phys = virt_to_phys(cpu->vmcs);
    
    // allocate msr bitmap
    cpu->msr_bitmap = vmx_alloc_msr_bitmap();
    if (!cpu->msr_bitmap) {
        hv_cpu_log(err, "failed to allocate msr bitmap\n");
        goto fail_msr;
    }
    cpu->msr_bitmap_phys = virt_to_phys(cpu->msr_bitmap);
    
    // allocate host stack
    cpu->host_stack = (struct host_stack *)__get_free_pages(GFP_KERNEL, 
                                          get_order(VMX_HOST_STACK_SIZE));
    if (!cpu->host_stack) {
        hv_cpu_log(err, "failed to allocate host stack\n");
        goto fail_stack;
    }
    memset(cpu->host_stack, 0, VMX_HOST_STACK_SIZE);
    cpu->host_stack->cpu = cpu;
    
    hv_log(debug, "CPU %u: vmxon=0x%llx vmcs=0x%llx msr_bmp=0x%llx\n",
           cpu_id, cpu->vmxon_phys, cpu->vmcs_phys, cpu->msr_bitmap_phys);
    
    return 0;

fail_stack:
    free_pages_exact(cpu->msr_bitmap, PAGE_SIZE);
fail_msr:
    free_pages_exact(cpu->vmcs, PAGE_SIZE);
fail_vmcs:
    free_pages_exact(cpu->vmxon, PAGE_SIZE);
    return -ENOMEM;
}

/*
*   destroy per-cpu context
*/
void cpu_ctx_destroy(struct cpu_ctx *cpu)
{
    if (!cpu)
        return;
    
    if (cpu->host_stack)
        free_pages((unsigned long)cpu->host_stack, get_order(VMX_HOST_STACK_SIZE));
    
    if (cpu->msr_bitmap)
        free_pages_exact(cpu->msr_bitmap, PAGE_SIZE);
    
    if (cpu->vmcs)
        free_pages_exact(cpu->vmcs, PAGE_SIZE);
    
    if (cpu->vmxon)
        free_pages_exact(cpu->vmxon, PAGE_SIZE);
}

/*
*   called from assembly after saving register state
*   wrapper that accepts vmm_ctx and extracts current cpu's context
*/
void cpu_vmx_init_from_guest(struct vmm_ctx *vmm, u64 guest_rsp, u64 guest_rip, u64 guest_rflags)
{
    unsigned int cpu_id = smp_processor_id();
    struct cpu_ctx *cpu = &vmm->cpu_ctxs[cpu_id];
    cpu_vmx_init(cpu, guest_rsp, guest_rip, guest_rflags);
}

/*
*   called from assembly after saving register state
*   this is called from vmx_launch_guest after guest registers are saved
*/
void cpu_vmx_init(struct cpu_ctx *cpu, u64 guest_rsp, u64 guest_rip, u64 guest_rflags)
{
    int ret;
    
    hv_cpu_log(debug, "vmx init: rsp=0x%llx rip=0x%llx rflags=0x%llx\n",
               guest_rsp, guest_rip, guest_rflags);
    
    // save guest resume state
    cpu->guest_rsp = guest_rsp;
    cpu->guest_rip = guest_rip;
    cpu->guest_rflags = guest_rflags;
    
    // capture current cpu state
    arch_capture_cpu_state(&cpu->state);
    
    // enter vmx root operation
    ret = vmx_enter_root(cpu);
    if (ret != 0) {
        hv_cpu_log(err, "failed to enter vmx root: %d\n", ret);
        cpu->failed = true;
        return;
    }
    
    // setup vmcs
    ret = vmx_setup_vmcs(cpu);
    if (ret != 0) {
        hv_cpu_log(err, "failed to setup vmcs: %d\n", ret);
        vmx_exit_root(cpu);
        cpu->failed = true;
        return;
    }
    
    // launch the vm - this should not return on success
    hv_cpu_log(info, "launching vm...\n");
    ret = vmx_launch(cpu);
    
    // if we get here, vmlaunch failed
    hv_cpu_log(err, "vmlaunch failed: error=%llu\n", vmx_get_error());
    vmx_exit_root(cpu);
    cpu->failed = true;
}

/*
*   virtualize current cpu
*/
int cpu_virtualize(struct cpu_ctx *cpu)
{
    // use assembly entry point to save registers and call cpu_vmx_init
    vmx_launch_guest(cpu->vmm);
    
    // if we return here, check if virtualization succeeded
    if (cpu->failed)
        return -1;
    
    cpu->virtualized = true;
    return 0;
}

/*
*   devirtualize current cpu
*   called via cpuid with magic leaf to exit vmx
*/
void cpu_devirtualize(struct cpu_ctx *cpu)
{
    u32 regs[4];
    
    if (!cpu->virtualized)
        return;
    
    // issue magic cpuid to trigger hypervisor exit
    cpuid_count(HV_CPUID_MAGIC_LEAF, HV_CPUID_MAGIC_SUBLEAF,
                &regs[0], &regs[1], &regs[2], &regs[3]);
    
    cpu->virtualized = false;
}

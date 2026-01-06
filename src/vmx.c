/*
*   vmx.c - vmx operations (vmxon, vmcs management, etc.)
*/

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm/msr.h>
#include <asm/frame.h>

#include "vmx.h"
#include "vmm.h"
#include "vmcs.h"
#include "arch.h"
#include "hv.h"

/* Assembly entry points */
extern void vmx_launch_guest(void *vmm_ctx);
extern void vmx_vmexit_handler(void);
extern void vmx_do_detach(void);
extern void vmx_guest_resume_label(void);

/* VMX assembly entry points use non-standard stack frames */
STACK_FRAME_NON_STANDARD(vmx_launch_guest);
STACK_FRAME_NON_STANDARD(vmx_vmexit_handler);
STACK_FRAME_NON_STANDARD(vmx_do_detach);
STACK_FRAME_NON_STANDARD(vmx_guest_resume_label);

/*
*   allocate vmxon region
*/
VMXON *vmx_alloc_vmxon(struct cpu_ctx *cpu)
{
    VMXON *vmxon;
    
    vmxon = alloc_pages_exact(PAGE_SIZE, GFP_KERNEL);
    if (!vmxon)
        return NULL;
    
    memset(vmxon, 0, PAGE_SIZE);
    
    // write vmcs revision id to first 31 bits (bit 31 must be 0)
    vmxon->RevisionId = cpu->vmm->vmx_caps.VmcsRevisionId;
    
    return vmxon;
}

/*
*   allocate vmcs region
*/
VMCS *vmx_alloc_vmcs(struct cpu_ctx *cpu)
{
    VMCS *vmcs;
    
    vmcs = alloc_pages_exact(PAGE_SIZE, GFP_KERNEL);
    if (!vmcs)
        return NULL;
    
    memset(vmcs, 0, PAGE_SIZE);
    
    vmcs->RevisionId = cpu->vmm->vmx_caps.VmcsRevisionId;
    vmcs->ShadowVmcsIndicator = 0;
    
    return vmcs;
}

/*
*   allocate msr bitmap
*/
VMX_MSR_BITMAP *vmx_alloc_msr_bitmap(void)
{
    VMX_MSR_BITMAP *bitmap;
    
    bitmap = alloc_pages_exact(PAGE_SIZE, GFP_KERNEL);
    if (!bitmap)
        return NULL;
    
    // initialize to all zeros (no msr interception)
    memset(bitmap, 0, PAGE_SIZE);
    
    return bitmap;
}

/*
*   set fixed cr0/cr4 bits required for vmx
*/
void vmx_set_fixed_bits(struct cpu_ctx *cpu)
{
    u64 cr0, cr4;
    u64 fixed0, fixed1;
    
    // save original values
    cpu->orig_cr0.AsUInt = read_cr0();
    cpu->orig_cr4.AsUInt = __read_cr4();
    
    // apply cr0 fixed bits
    cr0 = cpu->orig_cr0.AsUInt;
    fixed0 = native_read_msr(IA32_VMX_CR0_FIXED0);
    fixed1 = native_read_msr(IA32_VMX_CR0_FIXED1);
    cr0 |= fixed0;
    cr0 &= fixed1;
    write_cr0(cr0);
    
    // apply cr4 fixed bits
    cr4 = cpu->orig_cr4.AsUInt;
    fixed0 = native_read_msr(IA32_VMX_CR4_FIXED0);
    fixed1 = native_read_msr(IA32_VMX_CR4_FIXED1);
    cr4 |= fixed0;
    cr4 &= fixed1;
    __write_cr4(cr4);
}

/*
*   restore original cr0/cr4 values
*/
void vmx_restore_fixed_bits(struct cpu_ctx *cpu)
{
    write_cr0(cpu->orig_cr0.AsUInt);
    __write_cr4(cpu->orig_cr4.AsUInt);
}

/*
*   enter vmx root operation
*/
int vmx_enter_root(struct cpu_ctx *cpu)
{
    CR4 cr4;
    int ret;
    
    // check if vmx is already enabled
    cr4.AsUInt = __read_cr4();
    if (cr4.VmxEnable) {
        hv_cpu_log(err, "vmx already enabled (another hypervisor??)\n");
        return -EBUSY;
    }
    
    // set required fixed bits in cr0/cr4
    vmx_set_fixed_bits(cpu);
    
    // enable vmx operation (set cr4.vmxe)
    arch_enable_vmxe();
    
    // execute vmxon
    ret = arch_vmxon(cpu->vmxon_phys);
    if (ret != 0) {
        hv_cpu_log(err, "vmxon failed\n");
        arch_disable_vmxe();
        vmx_restore_fixed_bits(cpu);
        return ret;
    }
    
    // clear vmcs
    ret = arch_vmclear(cpu->vmcs_phys);
    if (ret != 0) {
        hv_cpu_log(err, "vmclear failed\n");
        arch_vmxoff();
        arch_disable_vmxe();
        vmx_restore_fixed_bits(cpu);
        return ret;
    }
    
    // load vmcs pointer
    ret = arch_vmptrld(cpu->vmcs_phys);
    if (ret != 0) {
        hv_cpu_log(err, "vmptrld failed\n");
        arch_vmxoff();
        arch_disable_vmxe();
        vmx_restore_fixed_bits(cpu);
        return ret;
    }
    
    hv_cpu_log(debug, "entered vmx root operation\n");
    return 0;
}

/*
*   exit vmx root operation
*/
int vmx_exit_root(struct cpu_ctx *cpu)
{
    int ret;
    
    // clear vmcs before vmxoff
    ret = arch_vmclear(cpu->vmcs_phys);
    if (ret != 0)
        hv_cpu_log(err, "vmclear failed during exit\n");
    
    // exit vmx operation
    ret = arch_vmxoff();
    if (ret != 0)
        hv_cpu_log(err, "vmxoff failed\n");
    
    // disable vmxe and restore cr bits
    arch_disable_vmxe();
    vmx_restore_fixed_bits(cpu);
    
    hv_cpu_log(debug, "exited vmx root operation\n");
    return 0;
}

/*
*   setup vmcs for guest execution
*/
int vmx_setup_vmcs(struct cpu_ctx *cpu)
{
    return vmcs_init(cpu);
}

/*
*   launch virtual machine
*/
int vmx_launch(struct cpu_ctx *cpu)
{
    (void)cpu;
    return arch_vmlaunch();
}

/*
*   get vmx instruction error code
*/
u64 vmx_get_error(void)
{
    return arch_vmread(VMCS_VM_INSTRUCTION_ERROR);
}

/*
*   set msr interception in bitmap
*/
void vmx_set_msr_intercept(VMX_MSR_BITMAP *bitmap, u32 msr, bool read, bool write)
{
    u8 *read_low  = (u8 *)bitmap + 0x000;
    u8 *read_high = (u8 *)bitmap + 0x400;
    u8 *write_low = (u8 *)bitmap + 0x800;
    u8 *write_high = (u8 *)bitmap + 0xC00;
    u32 bit;
    
    if (msr <= 0x1FFF) {
        bit = msr;
        if (read)
            read_low[bit / 8] |= (1 << (bit % 8));
        if (write)
            write_low[bit / 8] |= (1 << (bit % 8));
    } else if (msr >= 0xC0000000 && msr <= 0xC0001FFF) {
        bit = msr - 0xC0000000;
        if (read)
            read_high[bit / 8] |= (1 << (bit % 8));
        if (write)
            write_high[bit / 8] |= (1 << (bit % 8));
    }
}

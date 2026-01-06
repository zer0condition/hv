/*
*   arch.c - architecture-specific cpu operations
*/

#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/desc.h>
#include <asm/special_insns.h>

#include "arch.h"
#include "vmx.h"
#include "hv.h"

/*
*   check if running inside a vm using cpuid hypervisor bit
*/
bool arch_running_in_vm(void)
{
    u32 ecx;
    ecx = cpuid_ecx(CPUID_VERSION_INFO);
    return HV_BIT_TEST(ecx, 31);  // bit 31 = hypervisor present
}

/*
*   check if cpu supports vmx
*/
bool arch_cpu_has_vmx(void)
{
    u32 ecx;
    ecx = cpuid_ecx(CPUID_VERSION_INFO);
    return HV_BIT_TEST(ecx, CPUID_VMX_BIT);
}

/*
*   check if bios has enabled vmx
*/
bool arch_vmx_enabled_by_bios(void)
{
    IA32_FEATURE_CONTROL_REGISTER feature;
    
    feature.AsUInt = native_read_msr(IA32_FEATURE_CONTROL);
    
    // must be locked and vmx enabled outside smx
    if (!feature.LockBit) {
        hv_log(err, "ia32_feature_control is not locked\n");
        return false;
    }
    
    if (!feature.EnableVmxOutsideSmx) {
        hv_log(err, "vmx is disabled outside smx in bios\n");
        return false;
    }
    
    return true;
}

/*
*   enable vmx operation by setting cr4.vmxe
*/
void arch_enable_vmxe(void)
{
    arch_set_cr4_bits(CR4_VMX_ENABLE_FLAG, 0);
}

/*
*   disable vmx operation by clearing cr4.vmxe
*/
void arch_disable_vmxe(void)
{
    arch_set_cr4_bits(0, CR4_VMX_ENABLE_FLAG);
}

/*
*   read segment descriptor from gdt
*/
static void read_segment_descriptor(struct hv_segment_descriptor *desc, u16 selector)
{
    struct desc_struct *gdt;
    struct desc_struct *entry;
    u64 base;
    u32 limit;
    
    desc->selector = selector;
    
    // null selector
    if (selector == 0) {
        desc->base = 0;
        desc->limit = 0;
        desc->access_rights = 0x10000;  // unusable
        return;
    }
    
    // get gdt base
    gdt = get_cpu_gdt_rw(smp_processor_id());
    entry = &gdt[selector >> 3];
    
    // calculate base address
    base = get_desc_base(entry);
    
    // for tss/ldt (system segments in 64-bit mode), read upper 32 bits of base
    if (entry->s == 0) {
        struct {
            u64 low;
            u64 high;
        } *sys_desc = (void *)entry;
        base |= (u64)(sys_desc->high & 0xFFFFFFFF) << 32;
    }
    
    // calculate limit
    limit = get_desc_limit(entry);
    if (entry->g)
        limit = (limit << 12) | 0xFFF;
    
    desc->base = base;
    desc->limit = limit;
    
    // build access rights from descriptor
    VMX_SEGMENT_ACCESS_RIGHTS ar = {0};
    ar.Type = entry->type;
    ar.DescriptorType = entry->s;
    ar.DescriptorPrivilegeLevel = entry->dpl;
    ar.Present = entry->p;
    ar.AvailableBit = entry->avl;
    ar.LongMode = entry->l;
    ar.DefaultBig = entry->d;
    ar.Granularity = entry->g;
    ar.Unusable = 0;
    
    desc->access_rights = ar.AsUInt;
}

/*
*   capture current cpu state for vmx
*/
void arch_capture_cpu_state(struct hv_cpu_state *state)
{
    struct desc_ptr gdtr, idtr;
    
    // control registers
    state->cr0.AsUInt = read_cr0();
    state->cr2 = native_read_cr2();
    state->cr3.AsUInt = __read_cr3();
    state->cr4.AsUInt = __read_cr4();
    
    // debug registers
    get_debugreg(state->dr7.AsUInt, 7);
    
    // descriptor tables
    native_store_gdt(&gdtr);
    state->gdtr.base = gdtr.address;
    state->gdtr.limit = gdtr.size;
    
    store_idt(&idtr);
    state->idtr.base = idtr.address;
    state->idtr.limit = idtr.size;
    
    // segment registers
    u16 cs, ds, es, ss, fs, gs, tr, ldtr;
    
    asm volatile("mov %%cs, %0" : "=r"(cs));
    asm volatile("mov %%ds, %0" : "=r"(ds));
    asm volatile("mov %%es, %0" : "=r"(es));
    asm volatile("mov %%ss, %0" : "=r"(ss));
    asm volatile("mov %%fs, %0" : "=r"(fs));
    asm volatile("mov %%gs, %0" : "=r"(gs));
    asm volatile("str %0" : "=r"(tr));
    asm volatile("sldt %0" : "=r"(ldtr));
    
    read_segment_descriptor(&state->cs, cs);
    read_segment_descriptor(&state->ds, ds);
    read_segment_descriptor(&state->es, es);
    read_segment_descriptor(&state->ss, ss);
    read_segment_descriptor(&state->fs, fs);
    read_segment_descriptor(&state->gs, gs);
    read_segment_descriptor(&state->tr, tr);
    read_segment_descriptor(&state->ldtr, ldtr);
    
    // fs/gs bases
    state->fs_base = native_read_msr(IA32_FS_BASE);
    state->gs_base = native_read_msr(IA32_GS_BASE);
    state->kernel_gs_base = native_read_msr(IA32_KERNEL_GS_BASE);
    
    // msrs
    state->debugctl = native_read_msr(IA32_DEBUGCTL);
    state->sysenter_cs = native_read_msr(IA32_SYSENTER_CS);
    state->sysenter_esp = native_read_msr(IA32_SYSENTER_ESP);
    state->sysenter_eip = native_read_msr(IA32_SYSENTER_EIP);
    state->efer = native_read_msr(IA32_EFER);
    state->pat = native_read_msr(IA32_PAT);
    
    // system call msrs (long mode)
    state->star = native_read_msr(IA32_STAR);
    state->lstar = native_read_msr(IA32_LSTAR);
    state->cstar = native_read_msr(IA32_CSTAR);
    state->sfmask = native_read_msr(IA32_FMASK);
}

/*
*   vmx instruction wrappers with proper error handling
*/

int arch_vmxon(phys_addr_t vmxon_phys)
{
    u8 error;
    
    asm volatile(
        "vmxon %[addr]\n\t"
        "setc %[err]\n\t"
        : [err] "=rm" (error)
        : [addr] "m" (vmxon_phys)
        : "cc", "memory"
    );
    
    return error ? -1 : 0;
}

int arch_vmxoff(void)
{
    u8 cf, zf;
    
    asm volatile(
        "vmxoff\n\t"
        "setc %[cf]\n\t"
        "setz %[zf]\n\t"
        : [cf] "=rm" (cf), [zf] "=rm" (zf)
        :
        : "cc", "memory"
    );
    
    return (cf || zf) ? -1 : 0;
}

int arch_vmclear(phys_addr_t vmcs_phys)
{
    u8 error;
    
    asm volatile(
        "vmclear %[addr]\n\t"
        "setc %[err]\n\t"
        : [err] "=rm" (error)
        : [addr] "m" (vmcs_phys)
        : "cc", "memory"
    );
    
    return error ? -1 : 0;
}

int arch_vmptrld(phys_addr_t vmcs_phys)
{
    u8 error;
    
    asm volatile(
        "vmptrld %[addr]\n\t"
        "setc %[err]\n\t"
        : [err] "=rm" (error)
        : [addr] "m" (vmcs_phys)
        : "cc", "memory"
    );
    
    return error ? -1 : 0;
}

int arch_vmlaunch(void)
{
    u8 error;
    
    asm volatile(
        "vmlaunch\n\t"
        "setc %[err]\n\t"
        : [err] "=rm" (error)
        :
        : "cc", "memory"
    );
    
    return error ? VMX_ERROR_WITH_STATUS : VMX_ERROR_WITHOUT_STATUS;
}

u64 arch_vmread(u64 field)
{
    u64 value;
    
    asm volatile(
        "vmread %[field], %[value]\n\t"
        : [value] "=r" (value)
        : [field] "r" (field)
        : "cc"
    );
    
    return value;
}

int arch_vmwrite(u64 field, u64 value)
{
    u8 error;
    
    asm volatile(
        "vmwrite %[value], %[field]\n\t"
        "setc %[err]\n\t"
        : [err] "=rm" (error)
        : [value] "r" (value), [field] "r" (field)
        : "cc"
    );
    
    return error ? -1 : 0;
}

/*
*   vmcs.c - vmcs (virtual machine control structure) configuration
*/

#include <linux/kernel.h>
#include <asm/msr.h>

#include "vmcs.h"
#include "vmm.h"
#include "vmx.h"
#include "arch.h"
#include "ept.h"
#include "exit.h"
#include "hv.h"

/*
*   setup pin-based vm-execution controls
*/
static u32 vmcs_setup_pinbased_controls(struct cpu_ctx *cpu)
{
    IA32_VMX_PINBASED_CTLS_REGISTER desired = {0};
    u64 msr;
    
    // no pin-based controls needed for basic operation
    
    if (cpu->vmm->vmx_caps.VmxControls)
        msr = native_read_msr(IA32_VMX_TRUE_PINBASED_CTLS);
    else
        msr = native_read_msr(IA32_VMX_PINBASED_CTLS);
    
    return vmcs_encode_controls(desired.AsUInt, msr);
}

/*
*   setup processor-based vm-execution controls
*/
static u32 vmcs_setup_procbased_controls(struct cpu_ctx *cpu)
{
    IA32_VMX_PROCBASED_CTLS_REGISTER desired = {0};
    u64 msr;
    
    // enable secondary controls
    desired.ActivateSecondaryControls = 1;
    
    // use msr bitmaps to avoid unnecessary msr exits
    desired.UseMsrBitmaps = 1;
    
    if (cpu->vmm->vmx_caps.VmxControls)
        msr = native_read_msr(IA32_VMX_TRUE_PROCBASED_CTLS);
    else
        msr = native_read_msr(IA32_VMX_PROCBASED_CTLS);
    
    return vmcs_encode_controls(desired.AsUInt, msr);
}

/*
*   setup secondary processor-based vm-execution controls
*/
static u32 vmcs_setup_procbased2_controls(struct cpu_ctx *cpu)
{
    IA32_VMX_PROCBASED_CTLS2_REGISTER desired = {0};
    u64 msr;
    
    // enable ept
    desired.EnableEpt = 1;
    
    // enable rdtscp (required by linux)
    desired.EnableRdtscp = 1;
    
    // enable vpid for tlb performance
    desired.EnableVpid = 1;
    
    // enable invpcid (if supported)
    desired.EnableInvpcid = 1;
    
    // enable xsaves/xrstors
    desired.EnableXsaves = 1;
    
    msr = native_read_msr(IA32_VMX_PROCBASED_CTLS2);
    
    return vmcs_encode_controls(desired.AsUInt, msr);
}

/*
*   setup vm-exit controls
*/
static u32 vmcs_setup_exit_controls(struct cpu_ctx *cpu)
{
    IA32_VMX_EXIT_CTLS_REGISTER desired = {0};
    u64 msr;
    
    // host is in 64-bit mode
    desired.HostAddressSpaceSize = 1;
    
    // load ia32_efer on vm-exit (required for 64-bit host)
    desired.LoadIa32Efer = 1;
    
    // save/load ia32_pat
    desired.SaveIa32Pat = 1;
    desired.LoadIa32Pat = 1;
    
    if (cpu->vmm->vmx_caps.VmxControls)
        msr = native_read_msr(IA32_VMX_TRUE_EXIT_CTLS);
    else
        msr = native_read_msr(IA32_VMX_EXIT_CTLS);
    
    return vmcs_encode_controls(desired.AsUInt, msr);
}

/*
*   setup vm-entry controls
*/
static u32 vmcs_setup_entry_controls(struct cpu_ctx *cpu)
{
    IA32_VMX_ENTRY_CTLS_REGISTER desired = {0};
    u64 msr;
    
    // guest is in 64-bit mode (ia-32e)
    desired.Ia32EModeGuest = 1;
    
    // load ia32_efer on vm-entry (required for 64-bit guest)
    desired.LoadIa32Efer = 1;
    
    // load ia32_pat on vm-entry
    desired.LoadIa32Pat = 1;
    
    if (cpu->vmm->vmx_caps.VmxControls)
        msr = native_read_msr(IA32_VMX_TRUE_ENTRY_CTLS);
    else
        msr = native_read_msr(IA32_VMX_ENTRY_CTLS);
    
    return vmcs_encode_controls(desired.AsUInt, msr);
}

/*
*   setup vmcs control fields
*/
int vmcs_setup_controls(struct cpu_ctx *cpu)
{
    int err = 0;
    
    // pin-based controls
    err |= arch_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS,
                        vmcs_setup_pinbased_controls(cpu));
    
    // processor-based controls
    err |= arch_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                        vmcs_setup_procbased_controls(cpu));
    
    // secondary processor-based controls
    err |= arch_vmwrite(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                        vmcs_setup_procbased2_controls(cpu));
    
    // vm-exit controls
    err |= arch_vmwrite(VMCS_CTRL_PRIMARY_VMEXIT_CONTROLS,
                        vmcs_setup_exit_controls(cpu));
    
    // vm-entry controls
    err |= arch_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS,
                        vmcs_setup_entry_controls(cpu));
    
    // exception bitmap - no exceptions cause vm-exit
    err |= arch_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, 0);
    
    // page fault error code mask/match
    err |= arch_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, 0);
    err |= arch_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, 0);
    
    // cr3 target count - all cr3 writes cause vm-exit if count is 0
    err |= arch_vmwrite(VMCS_CTRL_CR3_TARGET_COUNT, 0);
    
    // msr bitmap address
    err |= arch_vmwrite(VMCS_CTRL_MSR_BITMAP_ADDRESS, cpu->msr_bitmap_phys);
    
    // no msr load/store on vm-exit/entry
    err |= arch_vmwrite(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);
    err |= arch_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);
    err |= arch_vmwrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
    
    // no event injection on vm-entry
    err |= arch_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);
    err |= arch_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, 0);
    
    // ept pointer
    err |= arch_vmwrite(VMCS_CTRL_EPT_POINTER, cpu->vmm->ept->eptp.AsUInt);
    
    // vpid (must be non-zero if vpid is enabled)
    err |= arch_vmwrite(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER, cpu->cpu_id + 1);
    
    // xss exiting bitmap - required when EnableXsaves is set
    // set to 0 to not cause any xsaves/xrstors vm-exits
    err |= arch_vmwrite(VMCS_CTRL_XSS_EXITING_BITMAP, 0);
    
    // cr0/cr4 guest/host masks - let guest control all bits
    err |= arch_vmwrite(VMCS_CTRL_CR0_GUEST_HOST_MASK, 0);
    err |= arch_vmwrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, 0);
    err |= arch_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, cpu->state.cr0.AsUInt);
    err |= arch_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, cpu->state.cr4.AsUInt);
    
    return err ? -1 : 0;
}

/*
*   setup vmcs host state area
*/
int vmcs_setup_host(struct cpu_ctx *cpu)
{
    struct hv_cpu_state *state = &cpu->state;
    u64 host_rsp;
    u64 host_cr0, host_cr4;
    int err = 0;
    
    // control registers - must use current values (after vmx fixed bits applied)
    host_cr0 = read_cr0();
    host_cr4 = __read_cr4();
    
    err |= arch_vmwrite(VMCS_HOST_CR0, host_cr0);
    err |= arch_vmwrite(VMCS_HOST_CR3, state->cr3.AsUInt);
    err |= arch_vmwrite(VMCS_HOST_CR4, host_cr4);
    
    // host rsp/rip - vm-exit entry point
    host_rsp = (u64)&cpu->host_stack->cpu;  // top of stack
    err |= arch_vmwrite(VMCS_HOST_RSP, host_rsp);
    err |= arch_vmwrite(VMCS_HOST_RIP, (u64)cpu->vmexit_handler);
    
    // segment selectors (rpl must be 0 for host)
    err |= arch_vmwrite(VMCS_HOST_CS_SELECTOR, state->cs.selector & 0xF8);
    err |= arch_vmwrite(VMCS_HOST_SS_SELECTOR, state->ss.selector & 0xF8);
    err |= arch_vmwrite(VMCS_HOST_DS_SELECTOR, state->ds.selector & 0xF8);
    err |= arch_vmwrite(VMCS_HOST_ES_SELECTOR, state->es.selector & 0xF8);
    err |= arch_vmwrite(VMCS_HOST_FS_SELECTOR, state->fs.selector & 0xF8);
    err |= arch_vmwrite(VMCS_HOST_GS_SELECTOR, state->gs.selector & 0xF8);
    err |= arch_vmwrite(VMCS_HOST_TR_SELECTOR, state->tr.selector & 0xF8);
    
    // segment bases
    err |= arch_vmwrite(VMCS_HOST_FS_BASE, state->fs_base);
    err |= arch_vmwrite(VMCS_HOST_GS_BASE, state->gs_base);
    err |= arch_vmwrite(VMCS_HOST_TR_BASE, state->tr.base);
    err |= arch_vmwrite(VMCS_HOST_GDTR_BASE, state->gdtr.base);
    err |= arch_vmwrite(VMCS_HOST_IDTR_BASE, state->idtr.base);
    
    // msrs
    err |= arch_vmwrite(VMCS_HOST_SYSENTER_CS, state->sysenter_cs);
    err |= arch_vmwrite(VMCS_HOST_SYSENTER_ESP, state->sysenter_esp);
    err |= arch_vmwrite(VMCS_HOST_SYSENTER_EIP, state->sysenter_eip);
    
    // efer and pat (may be required by fixed bits)
    err |= arch_vmwrite(VMCS_HOST_EFER, state->efer);
    err |= arch_vmwrite(VMCS_HOST_PAT, state->pat);
    
    return err ? -1 : 0;
}

/*
*   setup vmcs guest state area
*/
int vmcs_setup_guest(struct cpu_ctx *cpu)
{
    struct hv_cpu_state *state = &cpu->state;
    int err = 0;
    
    // control registers
    err |= arch_vmwrite(VMCS_GUEST_CR0, state->cr0.AsUInt);
    err |= arch_vmwrite(VMCS_GUEST_CR3, state->cr3.AsUInt);
    err |= arch_vmwrite(VMCS_GUEST_CR4, state->cr4.AsUInt);
    err |= arch_vmwrite(VMCS_GUEST_DR7, state->dr7.AsUInt);
    
    // rsp/rip/rflags
    err |= arch_vmwrite(VMCS_GUEST_RSP, cpu->guest_rsp);
    err |= arch_vmwrite(VMCS_GUEST_RIP, cpu->guest_rip);
    err |= arch_vmwrite(VMCS_GUEST_RFLAGS, cpu->guest_rflags);
    
    // cs segment
    err |= arch_vmwrite(VMCS_GUEST_CS_SELECTOR, state->cs.selector);
    err |= arch_vmwrite(VMCS_GUEST_CS_BASE, state->cs.base);
    err |= arch_vmwrite(VMCS_GUEST_CS_LIMIT, state->cs.limit);
    err |= arch_vmwrite(VMCS_GUEST_CS_ACCESS_RIGHTS, state->cs.access_rights);
    
    // ss segment
    err |= arch_vmwrite(VMCS_GUEST_SS_SELECTOR, state->ss.selector);
    err |= arch_vmwrite(VMCS_GUEST_SS_BASE, state->ss.base);
    err |= arch_vmwrite(VMCS_GUEST_SS_LIMIT, state->ss.limit);
    err |= arch_vmwrite(VMCS_GUEST_SS_ACCESS_RIGHTS, state->ss.access_rights);
    
    // ds segment
    err |= arch_vmwrite(VMCS_GUEST_DS_SELECTOR, state->ds.selector);
    err |= arch_vmwrite(VMCS_GUEST_DS_BASE, state->ds.base);
    err |= arch_vmwrite(VMCS_GUEST_DS_LIMIT, state->ds.limit);
    err |= arch_vmwrite(VMCS_GUEST_DS_ACCESS_RIGHTS, state->ds.access_rights);
    
    // es segment
    err |= arch_vmwrite(VMCS_GUEST_ES_SELECTOR, state->es.selector);
    err |= arch_vmwrite(VMCS_GUEST_ES_BASE, state->es.base);
    err |= arch_vmwrite(VMCS_GUEST_ES_LIMIT, state->es.limit);
    err |= arch_vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS, state->es.access_rights);
    
    // fs segment
    err |= arch_vmwrite(VMCS_GUEST_FS_SELECTOR, state->fs.selector);
    err |= arch_vmwrite(VMCS_GUEST_FS_BASE, state->fs_base);
    err |= arch_vmwrite(VMCS_GUEST_FS_LIMIT, state->fs.limit);
    err |= arch_vmwrite(VMCS_GUEST_FS_ACCESS_RIGHTS, state->fs.access_rights);
    
    // gs segment
    err |= arch_vmwrite(VMCS_GUEST_GS_SELECTOR, state->gs.selector);
    err |= arch_vmwrite(VMCS_GUEST_GS_BASE, state->gs_base);
    err |= arch_vmwrite(VMCS_GUEST_GS_LIMIT, state->gs.limit);
    err |= arch_vmwrite(VMCS_GUEST_GS_ACCESS_RIGHTS, state->gs.access_rights);
    
    // ldtr
    err |= arch_vmwrite(VMCS_GUEST_LDTR_SELECTOR, state->ldtr.selector);
    err |= arch_vmwrite(VMCS_GUEST_LDTR_BASE, state->ldtr.base);
    err |= arch_vmwrite(VMCS_GUEST_LDTR_LIMIT, state->ldtr.limit);
    err |= arch_vmwrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, state->ldtr.access_rights);
    
    // tr
    err |= arch_vmwrite(VMCS_GUEST_TR_SELECTOR, state->tr.selector);
    err |= arch_vmwrite(VMCS_GUEST_TR_BASE, state->tr.base);
    err |= arch_vmwrite(VMCS_GUEST_TR_LIMIT, state->tr.limit);
    err |= arch_vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS, state->tr.access_rights);
    
    // gdtr/idtr
    err |= arch_vmwrite(VMCS_GUEST_GDTR_BASE, state->gdtr.base);
    err |= arch_vmwrite(VMCS_GUEST_GDTR_LIMIT, state->gdtr.limit);
    err |= arch_vmwrite(VMCS_GUEST_IDTR_BASE, state->idtr.base);
    err |= arch_vmwrite(VMCS_GUEST_IDTR_LIMIT, state->idtr.limit);
    
    // msrs
    err |= arch_vmwrite(VMCS_GUEST_DEBUGCTL, state->debugctl);
    err |= arch_vmwrite(VMCS_GUEST_SYSENTER_CS, state->sysenter_cs);
    err |= arch_vmwrite(VMCS_GUEST_SYSENTER_ESP, state->sysenter_esp);
    err |= arch_vmwrite(VMCS_GUEST_SYSENTER_EIP, state->sysenter_eip);
    err |= arch_vmwrite(VMCS_GUEST_EFER, state->efer);
    err |= arch_vmwrite(VMCS_GUEST_PAT, state->pat);
    
    // guest non-register state
    err |= arch_vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0);  // active
    err |= arch_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, 0);
    err |= arch_vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, 0);
    err |= arch_vmwrite(VMCS_GUEST_VMCS_LINK_POINTER, ~0ULL);
    
    return err ? -1 : 0;
}

/*
*   initialize vmcs
*/
int vmcs_init(struct cpu_ctx *cpu)
{
    int err;
    
    // setup guest state
    err = vmcs_setup_guest(cpu);
    if (err) {
        hv_cpu_log(err, "failed to setup vmcs guest state\n");
        return err;
    }
    
    // setup host state
    err = vmcs_setup_host(cpu);
    if (err) {
        hv_cpu_log(err, "failed to setup vmcs host state\n");
        return err;
    }
    
    // setup control fields
    err = vmcs_setup_controls(cpu);
    if (err) {
        hv_cpu_log(err, "failed to setup vmcs controls\n");
        return err;
    }
    
    hv_cpu_log(debug, "vmcs initialized\n");
    return 0;
}

/*
*   validate vmcs configuration
*/
int vmcs_validate(struct cpu_ctx *cpu)
{
    int err = 0;
    u64 val;
    u64 expected;
    IA32_VMX_PINBASED_CTLS_REGISTER pin_desired = {0};
    IA32_VMX_PROCBASED_CTLS_REGISTER pb_desired = {0};
    IA32_VMX_PROCBASED_CTLS2_REGISTER pb2_desired = {0};
    IA32_VMX_EXIT_CTLS_REGISTER exit_desired = {0};
    IA32_VMX_ENTRY_CTLS_REGISTER entry_desired = {0};
    u64 host_rsp, host_rip, guest_rsp, guest_rip;
    u64 host_fs, host_gs, guest_fs, guest_gs;
    u16 host_cs, host_ss, host_tr;
    u64 msr;
    u64 fixed0, fixed1;
    
    /* recompute control encodings */
    if (cpu->vmm->vmx_caps.VmxControls)
        msr = native_read_msr(IA32_VMX_TRUE_PINBASED_CTLS);
    else
        msr = native_read_msr(IA32_VMX_PINBASED_CTLS);
    expected = vmcs_encode_controls(pin_desired.AsUInt, msr);
    val = arch_vmread(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS);
    if (val != expected) {
        hv_cpu_log(err, "pinbased controls mismatch vmcs=0x%llx expected=0x%llx\n",
                   val, expected);
        err = -EINVAL;
    }
    
    pb_desired.ActivateSecondaryControls = 1;
    pb_desired.UseMsrBitmaps = 1;
    if (cpu->vmm->vmx_caps.VmxControls)
        msr = native_read_msr(IA32_VMX_TRUE_PROCBASED_CTLS);
    else
        msr = native_read_msr(IA32_VMX_PROCBASED_CTLS);
    expected = vmcs_encode_controls(pb_desired.AsUInt, msr);
    val = arch_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
    if (val != expected) {
        hv_cpu_log(err, "procbased controls mismatch vmcs=0x%llx expected=0x%llx\n",
                   val, expected);
        err = -EINVAL;
    }
    
    pb2_desired.EnableEpt = 1;
    pb2_desired.EnableRdtscp = 1;
    pb2_desired.EnableVpid = 1;
    pb2_desired.EnableInvpcid = 1;
    pb2_desired.EnableXsaves = 1;
    msr = native_read_msr(IA32_VMX_PROCBASED_CTLS2);
    expected = vmcs_encode_controls(pb2_desired.AsUInt, msr);
    val = arch_vmread(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
    if (val != expected) {
        hv_cpu_log(err, "procbased2 controls mismatch vmcs=0x%llx expected=0x%llx\n",
                   val, expected);
        err = -EINVAL;
    }
    
    exit_desired.HostAddressSpaceSize = 1;
    exit_desired.LoadIa32Efer = 1;
    exit_desired.SaveIa32Pat = 1;
    exit_desired.LoadIa32Pat = 1;
    if (cpu->vmm->vmx_caps.VmxControls)
        msr = native_read_msr(IA32_VMX_TRUE_EXIT_CTLS);
    else
        msr = native_read_msr(IA32_VMX_EXIT_CTLS);
    expected = vmcs_encode_controls(exit_desired.AsUInt, msr);
    val = arch_vmread(VMCS_CTRL_PRIMARY_VMEXIT_CONTROLS);
    if (val != expected) {
        hv_cpu_log(err, "vmexit controls mismatch vmcs=0x%llx expected=0x%llx\n",
                   val, expected);
        err = -EINVAL;
    }
    
    entry_desired.Ia32EModeGuest = 1;
    entry_desired.LoadIa32Efer = 1;
    entry_desired.LoadIa32Pat = 1;
    if (cpu->vmm->vmx_caps.VmxControls)
        msr = native_read_msr(IA32_VMX_TRUE_ENTRY_CTLS);
    else
        msr = native_read_msr(IA32_VMX_ENTRY_CTLS);
    expected = vmcs_encode_controls(entry_desired.AsUInt, msr);
    val = arch_vmread(VMCS_CTRL_VMENTRY_CONTROLS);
    if (val != expected) {
        hv_cpu_log(err, "vmentry controls mismatch vmcs=0x%llx expected=0x%llx\n",
                   val, expected);
        err = -EINVAL;
    }
    
    /* EPTP */
    val = arch_vmread(VMCS_CTRL_EPT_POINTER);
    if (val != cpu->vmm->ept->eptp.AsUInt) {
        hv_cpu_log(err, "vmcs eptp mismatch: vmcs=0x%llx expected=0x%llx\n",
                   val, cpu->vmm->ept->eptp.AsUInt);
        err = -EINVAL;
    } else {
        EPT_POINTER decoded = {.AsUInt = val};
        if (decoded.MemoryType != EPT_MEMORY_TYPE_WB || decoded.PageWalkLength != 3) {
            hv_cpu_log(err, "eptp fields invalid: type=%u pwl=%u\n",
                       decoded.MemoryType, decoded.PageWalkLength);
            err = -EINVAL;
        }
    }
    
    /* VPID */
    val = arch_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER);
    if (val == 0) {
        hv_cpu_log(err, "vpid is zero (invalid)\n");
        err = -EINVAL;
    }
    
    /* MSR bitmap */
    val = arch_vmread(VMCS_CTRL_MSR_BITMAP_ADDRESS);
    if (val == 0 || (val & (PAGE_SIZE - 1))) {
        hv_cpu_log(err, "msr bitmap address invalid (0x%llx)\n", val);
        err = -EINVAL;
    }
    
    /* Host pointers canonical and non-zero */
    host_rsp = arch_vmread(VMCS_HOST_RSP);
    host_rip = arch_vmread(VMCS_HOST_RIP);
    host_fs = arch_vmread(VMCS_HOST_FS_BASE);
    host_gs = arch_vmread(VMCS_HOST_GS_BASE);
    if (!arch_is_canonical(host_rsp) || host_rsp == 0) {
        hv_cpu_log(err, "host rsp not canonical/zero: 0x%llx\n", host_rsp);
        err = -EINVAL;
    }
    if (!arch_is_canonical(host_rip) || host_rip == 0) {
        hv_cpu_log(err, "host rip not canonical/zero: 0x%llx\n", host_rip);
        err = -EINVAL;
    }
    if (!arch_is_canonical(host_fs) || !arch_is_canonical(host_gs)) {
        hv_cpu_log(err, "host fs/gs base not canonical: fs=0x%llx gs=0x%llx\n",
                   host_fs, host_gs);
        err = -EINVAL;
    }
    
    /* Guest pointers canonical */
    guest_rsp = arch_vmread(VMCS_GUEST_RSP);
    guest_rip = arch_vmread(VMCS_GUEST_RIP);
    guest_fs = arch_vmread(VMCS_GUEST_FS_BASE);
    guest_gs = arch_vmread(VMCS_GUEST_GS_BASE);
    if (!arch_is_canonical(guest_rsp)) {
        hv_cpu_log(err, "guest rsp not canonical: 0x%llx\n", guest_rsp);
        err = -EINVAL;
    }
    if (!arch_is_canonical(guest_rip)) {
        hv_cpu_log(err, "guest rip not canonical: 0x%llx\n", guest_rip);
        err = -EINVAL;
    }
    if (!arch_is_canonical(guest_fs) || !arch_is_canonical(guest_gs)) {
        hv_cpu_log(err, "guest fs/gs base not canonical: fs=0x%llx gs=0x%llx\n",
                   guest_fs, guest_gs);
        err = -EINVAL;
    }
    if (guest_rip == 0) {
        hv_cpu_log(warn, "guest rip is zero; guest may reboot immediately\n");
    }
    
    /* Host selectors RPL=0 and TR present */
    host_cs = (u16)arch_vmread(VMCS_HOST_CS_SELECTOR);
    host_ss = (u16)arch_vmread(VMCS_HOST_SS_SELECTOR);
    host_tr = (u16)arch_vmread(VMCS_HOST_TR_SELECTOR);
    if ((host_cs & 0x3) || (host_ss & 0x3) || (host_tr & 0x3) || host_tr == 0) {
        hv_cpu_log(err, "host selectors invalid: cs=0x%x ss=0x%x tr=0x%x\n",
                   host_cs, host_ss, host_tr);
        err = -EINVAL;
    }
    val = arch_vmread(VMCS_HOST_TR_BASE);
    if (!arch_is_canonical(val)) {
        hv_cpu_log(err, "host tr base not canonical: 0x%llx\n", val);
        err = -EINVAL;
    }
    
    /* CR0/CR4 fixed bits for host and guest */
    fixed0 = native_read_msr(IA32_VMX_CR0_FIXED0);
    fixed1 = native_read_msr(IA32_VMX_CR0_FIXED1);
    val = arch_vmread(VMCS_HOST_CR0);
    if (((val & fixed0) != fixed0) || (val & ~fixed1)) {
        hv_cpu_log(err, "host cr0 violates fixed bits (0x%llx)\n", val);
        err = -EINVAL;
    }
    val = arch_vmread(VMCS_GUEST_CR0);
    if (((val & fixed0) != fixed0) || (val & ~fixed1)) {
        hv_cpu_log(err, "guest cr0 violates fixed bits (0x%llx)\n", val);
        err = -EINVAL;
    }
    fixed0 = native_read_msr(IA32_VMX_CR4_FIXED0);
    fixed1 = native_read_msr(IA32_VMX_CR4_FIXED1);
    val = arch_vmread(VMCS_HOST_CR4);
    if (((val & fixed0) != fixed0) || (val & ~fixed1)) {
        hv_cpu_log(err, "host cr4 violates fixed bits (0x%llx)\n", val);
        err = -EINVAL;
    }
    val = arch_vmread(VMCS_GUEST_CR4);
    if (((val & fixed0) != fixed0) || (val & ~fixed1)) {
        hv_cpu_log(err, "guest cr4 violates fixed bits (0x%llx)\n", val);
        err = -EINVAL;
    }
    
    /* Activity/link */
    val = arch_vmread(VMCS_GUEST_ACTIVITY_STATE);
    if (val != 0) {
        hv_cpu_log(err, "guest activity state not active: %llu\n", val);
        err = -EINVAL;
    }
    val = arch_vmread(VMCS_GUEST_VMCS_LINK_POINTER);
    if (val != ~0ULL) {
        hv_cpu_log(err, "vmcs link pointer not ~0: 0x%llx\n", val);
        err = -EINVAL;
    }
    
    return err;
}

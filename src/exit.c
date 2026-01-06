/*
*   exit.c - vm-exit handling
*/

#include <linux/kernel.h>
#include <asm/msr.h>

#include "exit.h"
#include "cpu.h"
#include "vmx.h"
#include "ept.h"
#include "arch.h"
#include "hv.h"

/*
*   initialize exit context from vmcs
*/
static void vmexit_init_context(struct vmexit_ctx *ctx, struct gp_regs *regs)
{
    ctx->regs = regs;
    ctx->exit_reason.AsUInt = arch_vmread(VMCS_EXIT_REASON);
    ctx->exit_qualification = arch_vmread(VMCS_EXIT_QUALIFICATION);
    ctx->guest_rip = arch_vmread(VMCS_GUEST_RIP);
    ctx->guest_rsp = arch_vmread(VMCS_GUEST_RSP);
    ctx->guest_rflags = arch_vmread(VMCS_GUEST_RFLAGS);
    ctx->guest_physical_addr = arch_vmread(VMCS_GUEST_PHYSICAL_ADDRESS);
    ctx->instruction_length = arch_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH);
    ctx->instruction_info = arch_vmread(VMCS_VMEXIT_INSTRUCTION_INFO);
    
    ctx->should_advance_rip = true;
    ctx->should_exit_vmx = false;
}

/*
*   advance guest rip past the faulting instruction
*   per intel sdm, must clear blocking by mov-ss and sti
*/
static void vmexit_advance_rip(struct vmexit_ctx *ctx)
{
    u64 interruptibility;
    
    // clear interrupt blocking by mov-ss and sti per intel sdm
    interruptibility = arch_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE);
    interruptibility &= ~(VMX_INTERRUPTIBILITY_STATE_BLOCKING_BY_STI_FLAG | 
                          VMX_INTERRUPTIBILITY_STATE_BLOCKING_BY_MOV_SS_FLAG);
    arch_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, interruptibility);
    
    arch_vmwrite(VMCS_GUEST_RIP, ctx->guest_rip + ctx->instruction_length);
}

/*
*   inject exception into guest
*   vector: exception number (e.g., 6 for #UD, 13 for #GP)
*   has_error_code: whether exception pushes error code
*   error_code: error code value if applicable
*/
static void vmexit_inject_exception(u8 vector, bool has_error_code, u32 error_code)
{
    VMENTRY_INTERRUPT_INFORMATION info = {0};
    
    info.Vector = vector;
    info.InterruptionType = HardwareException;
    info.DeliverErrorCode = has_error_code ? 1 : 0;
    info.Valid = 1;
    
    arch_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, info.AsUInt);
    if (has_error_code)
        arch_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, error_code);
}

/*
*   inject #ud (invalid opcode) exception
*/
static void vmexit_inject_ud(void)
{
    vmexit_inject_exception(6, false, 0);  // #UD = vector 6, no error code
}

/*
*   inject #gp (general protection) exception
*/
static void vmexit_inject_gp(u32 error_code)
{
    vmexit_inject_exception(13, true, error_code);  // #GP = vector 13, has error code
}

/*
*   handle cpuid vm-exit
*/
int vmexit_handle_cpuid(struct cpu_ctx *cpu, struct vmexit_ctx *ctx)
{
    u32 leaf = (u32)ctx->regs->rax;
    u32 subleaf = (u32)ctx->regs->rcx;
    u32 eax, ebx, ecx, edx;
    
    // check for hypervisor detach request
    if (leaf == HV_CPUID_MAGIC_LEAF && subleaf == HV_CPUID_MAGIC_SUBLEAF) {
        hv_cpu_log(info, "received detach request via cpuid\n");
        ctx->should_exit_vmx = true;
        ctx->should_advance_rip = true;
        return 0;
    }
    
    // execute actual cpuid
    cpuid_count(leaf, subleaf, &eax, &ebx, &ecx, &edx);
    
    // modify cpuid results for stealth
    if (leaf == CPUID_VERSION_INFO) {
        // hide vmx capability (bit 5) to prevent nested vmx attempts
        ecx = HV_BIT_CLEAR(ecx, CPUID_VMX_BIT);
        // hide hypervisor present bit (bit 31) to appear as native hardware
        ecx = HV_BIT_CLEAR(ecx, 31);
    }
    
    ctx->regs->rax = eax;
    ctx->regs->rbx = ebx;
    ctx->regs->rcx = ecx;
    ctx->regs->rdx = edx;
    
    return 0;
}

/*
*   check if msr is in valid range per intel sdm
*   valid ranges: 0x0-0x1fff, 0xc0000000-0xc0001fff
*/
static bool msr_is_valid(u32 msr)
{
    // low range: 0x0 - 0x1fff
    if (msr <= 0x1fff)
        return true;
    
    // high range: 0xc0000000 - 0xc0001fff
    if (msr >= 0xc0000000 && msr <= 0xc0001fff)
        return true;
    
    return false;
}

/*
*   safe msr read - returns true on success, false on #gp
*/
static bool safe_rdmsr(u32 msr, u64 *value)
{
    u32 low, high;
    
    // use rdmsr_safe which returns non-zero on #gp
    if (rdmsr_safe(msr, &low, &high) != 0)
        return false;
    
    *value = ((u64)high << 32) | low;
    return true;
}

/*
*   safe msr write - returns true on success, false on #gp
*/
static bool safe_wrmsr(u32 msr, u64 value)
{
    // use wrmsr_safe which returns non-zero on #gp
    return wrmsr_safe(msr, (u32)value, (u32)(value >> 32)) == 0;
}

/*
*   handle rdmsr vm-exit
*/
int vmexit_handle_msr_read(struct cpu_ctx *cpu, struct vmexit_ctx *ctx)
{
    u32 msr = (u32)ctx->regs->rcx;
    u64 value;
    
    hv_cpu_log(debug, "rdmsr: msr=0x%x\n", msr);
    
    // validate msr range per intel sdm
    if (!msr_is_valid(msr)) {
        hv_cpu_log(debug, "rdmsr: invalid msr 0x%x, injecting #gp\n", msr);
        vmexit_inject_gp(0);
        ctx->should_advance_rip = false;
        return 0;
    }
    
    // try to read the msr safely
    if (!safe_rdmsr(msr, &value)) {
        hv_cpu_log(debug, "rdmsr: msr 0x%x caused #gp, injecting\n", msr);
        vmexit_inject_gp(0);
        ctx->should_advance_rip = false;
        return 0;
    }
    
    ctx->regs->rax = (u32)value;
    ctx->regs->rdx = (u32)(value >> 32);
    
    return 0;
}

/*
*   handle wrmsr vm-exit
*/
int vmexit_handle_msr_write(struct cpu_ctx *cpu, struct vmexit_ctx *ctx)
{
    u32 msr = (u32)ctx->regs->rcx;
    u64 value = (ctx->regs->rdx << 32) | (u32)ctx->regs->rax;
    
    hv_cpu_log(debug, "wrmsr: msr=0x%x value=0x%llx\n", msr, value);
    
    // validate msr range per intel sdm
    if (!msr_is_valid(msr)) {
        hv_cpu_log(debug, "wrmsr: invalid msr 0x%x, injecting #gp\n", msr);
        vmexit_inject_gp(0);
        ctx->should_advance_rip = false;
        return 0;
    }
    
    // try to write the msr safely
    if (!safe_wrmsr(msr, value)) {
        hv_cpu_log(debug, "wrmsr: msr 0x%x caused #gp, injecting\n", msr);
        vmexit_inject_gp(0);
        ctx->should_advance_rip = false;
        return 0;
    }
    
    return 0;
}

/*
*   handle vmcall vm-exit
*/
int vmexit_handle_vmcall(struct cpu_ctx *cpu, struct vmexit_ctx *ctx)
{
    u64 call_number = ctx->regs->rax;
    
    hv_cpu_log(debug, "vmcall: number=%llu\n", call_number);
    
    // could implement hypercall interface here
    ctx->regs->rax = 0;  // success
    
    return 0;
}

/*
*   handle ept violation vm-exit
*/
int vmexit_handle_ept_violation(struct cpu_ctx *cpu, struct vmexit_ctx *ctx)
{
    int ret;
    
    ctx->should_advance_rip = false;
    ret = ept_handle_violation(cpu, ctx->guest_physical_addr,
                               ctx->exit_qualification);
    
    // if ept violation couldn't be handled, exit vmx gracefully
    // this prevents system freeze on unmapped regions
    if (ret != 0) {
        hv_cpu_log(err, "unhandled ept violation, detaching hypervisor\n");
        ctx->should_exit_vmx = true;
        return 0;  // return 0 to continue with detachment flow
    }
    
    return 0;
}

/*
*   handle ept misconfiguration vm-exit
*/
int vmexit_handle_ept_misconfig(struct cpu_ctx *cpu, struct vmexit_ctx *ctx)
{
    ctx->should_advance_rip = false;
    ctx->should_exit_vmx = true;
    return ept_handle_misconfiguration(cpu, ctx->guest_physical_addr);
}

/*
*   handle xsetbv vm-exit
*   per intel sdm and reference implementations, validate xcr index and value
*/
int vmexit_handle_xsetbv(struct cpu_ctx *cpu, struct vmexit_ctx *ctx)
{
    u32 index = (u32)ctx->regs->rcx;
    u64 value = (ctx->regs->rdx << 32) | (u32)ctx->regs->rax;
    
    hv_cpu_log(debug, "xsetbv: index=%u value=0x%llx\n", index, value);
    
    // only xcr0 is valid (index 0)
    if (index != 0) {
        hv_cpu_log(debug, "xsetbv: invalid xcr index %u, injecting #gp\n", index);
        vmexit_inject_gp(0);
        ctx->should_advance_rip = false;
        return 0;
    }
    
    // xcr0 bit 0 (x87) must always be set
    if (!(value & 1)) {
        hv_cpu_log(debug, "xsetbv: xcr0 bit 0 not set, injecting #gp\n");
        vmexit_inject_gp(0);
        ctx->should_advance_rip = false;
        return 0;
    }
    
    // if avx (bit 2) is set, sse (bit 1) must also be set
    if ((value & (1 << 2)) && !(value & (1 << 1))) {
        hv_cpu_log(debug, "xsetbv: avx without sse, injecting #gp\n");
        vmexit_inject_gp(0);
        ctx->should_advance_rip = false;
        return 0;
    }
    
    // execute xsetbv
    asm volatile("xsetbv" :: "a"((u32)value), "d"((u32)(value >> 32)), "c"(index));
    
    return 0;
}

/*
*   handle invd vm-exit
*/
int vmexit_handle_invd(struct cpu_ctx *cpu, struct vmexit_ctx *ctx)
{
    // wbinvd instead of invd for safety
    asm volatile("wbinvd" ::: "memory");
    return 0;
}

/*
*   detach from hypervisor and return to guest
*/
static void vmexit_detach(struct cpu_ctx *cpu, struct vmexit_ctx *ctx)
{
    u64 guest_cr3;
    
    hv_cpu_log(info, "detaching hypervisor\n");
    
    // get guest cr3 for address space switch
    guest_cr3 = arch_vmread(VMCS_GUEST_CR3);
    
    // advance rip past the cpuid instruction
    vmexit_advance_rip(ctx);
    
    // update resume state
    cpu->guest_rip = arch_vmread(VMCS_GUEST_RIP);
    cpu->guest_rsp = arch_vmread(VMCS_GUEST_RSP);
    cpu->guest_rflags = arch_vmread(VMCS_GUEST_RFLAGS);
    
    // exit vmx operation
    vmx_exit_root(cpu);
    
    // restore guest cr3
    write_cr3(guest_cr3);
    
    // store cpu pointer in rax for assembly routine
    ctx->regs->rax = (u64)cpu;
}

/*
*   main vm-exit handler
*/
int vmexit_handler(struct cpu_ctx *cpu, struct gp_regs *regs)
{
    struct vmexit_ctx ctx;
    int ret = 0;
    
    vmexit_init_context(&ctx, regs);
    
    // check for vm-entry failure
    if (ctx.exit_reason.VmEntryFailure) {
        hv_cpu_log(err, "vm-entry failure: reason=%u\n",
                   ctx.exit_reason.BasicExitReason);
        return -1;
    }
    
    // dispatch based on exit reason
    switch (ctx.exit_reason.BasicExitReason) {
    case VMX_EXIT_REASON_EXECUTE_CPUID:
        ret = vmexit_handle_cpuid(cpu, &ctx);
        break;
        
    case VMX_EXIT_REASON_EXECUTE_RDMSR:
        ret = vmexit_handle_msr_read(cpu, &ctx);
        break;
        
    case VMX_EXIT_REASON_EXECUTE_WRMSR:
        ret = vmexit_handle_msr_write(cpu, &ctx);
        break;
        
    case VMX_EXIT_REASON_EXECUTE_VMCALL:
        ret = vmexit_handle_vmcall(cpu, &ctx);
        break;
        
    case VMX_EXIT_REASON_EPT_VIOLATION:
        ret = vmexit_handle_ept_violation(cpu, &ctx);
        break;
        
    case VMX_EXIT_REASON_EPT_MISCONFIGURATION:
        ret = vmexit_handle_ept_misconfig(cpu, &ctx);
        break;
        
    case VMX_EXIT_REASON_EXECUTE_XSETBV:
        ret = vmexit_handle_xsetbv(cpu, &ctx);
        break;
        
    case VMX_EXIT_REASON_EXECUTE_INVD:
        ret = vmexit_handle_invd(cpu, &ctx);
        break;
        
    // vmx instructions cause #ud in guest since vmx is not exposed
    case VMX_EXIT_REASON_EXECUTE_VMXON:
    case VMX_EXIT_REASON_EXECUTE_VMXOFF:
    case VMX_EXIT_REASON_EXECUTE_VMCLEAR:
    case VMX_EXIT_REASON_EXECUTE_VMPTRLD:
    case VMX_EXIT_REASON_EXECUTE_VMPTRST:
    case VMX_EXIT_REASON_EXECUTE_VMREAD:
    case VMX_EXIT_REASON_EXECUTE_VMWRITE:
    case VMX_EXIT_REASON_EXECUTE_VMLAUNCH:
    case VMX_EXIT_REASON_EXECUTE_VMRESUME:
    case VMX_EXIT_REASON_EXECUTE_INVEPT:
    case VMX_EXIT_REASON_EXECUTE_INVVPID:
        vmexit_inject_ud();
        ctx.should_advance_rip = false;  // exception delivery handles rip
        break;
    
    // init signal - typically from mp initialization protocol
    // for type-2 hypervisor, we can generally ignore or pass through
    case VMX_EXIT_REASON_INIT_SIGNAL:
        hv_cpu_log(debug, "init signal received\n");
        ctx.should_advance_rip = false;
        // for a type-2 hypervisor running on active system, init is unexpected
        // could implement full init handling per intel sdm if needed
        break;
    
    // sipi (startup ipi) - used in mp initialization  
    // for type-2 hypervisor on running system, this shouldn't occur
    case VMX_EXIT_REASON_STARTUP_IPI:
        hv_cpu_log(debug, "sipi signal received\n");
        ctx.should_advance_rip = false;
        break;
    
    // triple fault - unrecoverable error
    case VMX_EXIT_REASON_TRIPLE_FAULT:
        hv_cpu_log(err, "triple fault detected\n");
        ctx.should_advance_rip = false;
        ctx.should_exit_vmx = true;  // must exit on triple fault
        break;
    
    // external interrupt - must be re-injected to guest
    // this only occurs if external-interrupt exiting is enabled
    case VMX_EXIT_REASON_EXTERNAL_INTERRUPT:
        // interrupt info is in exit interruption information field
        // for type-2 hypervisor with pass-through, we shouldn't see these
        // but if we do, just continue - the interrupt will be delivered on vmresume
        ctx.should_advance_rip = false;
        break;
    
    // nmi - handle or pass through to guest
    case VMX_EXIT_REASON_NMI_WINDOW:
        // nmi window opened - clear nmi-window exiting
        ctx.should_advance_rip = false;
        break;
    
    // exception or nmi - only occurs if exception bitmap or nmi exiting is set
    case VMX_EXIT_REASON_EXCEPTION_OR_NMI:
        ctx.should_advance_rip = false;
        // for now, we shouldn't see this with exception bitmap = 0
        // if we do, re-inject the exception
        hv_cpu_log(debug, "exception/nmi exit: qual=0x%llx\n", 
                   ctx.exit_qualification);
        break;
    
    // interrupt window - guest can now receive interrupts
    case VMX_EXIT_REASON_INTERRUPT_WINDOW:
        ctx.should_advance_rip = false;
        break;
    
    // control register access - can occur if cr masks are set
    case VMX_EXIT_REASON_MOV_CR:
        ctx.should_advance_rip = false;
        hv_cpu_log(debug, "mov cr exit: qual=0x%llx\n", ctx.exit_qualification);
        // should handle CR access if CR masks are non-zero
        break;
    
    // hlt instruction - guest executed hlt
    case VMX_EXIT_REASON_EXECUTE_HLT:
        // for type-2, just let it continue - interrupts will wake it
        ctx.should_advance_rip = true;
        break;
    
    // invlpg instruction
    case VMX_EXIT_REASON_EXECUTE_INVLPG:
        ctx.should_advance_rip = true;
        break;
    
    // io instruction - only if unconditional or bitmap causes exit  
    case VMX_EXIT_REASON_EXECUTE_IO_INSTRUCTION:
        hv_cpu_log(debug, "io instruction exit: qual=0x%llx\n", ctx.exit_qualification);
        // if we somehow get here, advance past the instruction
        // the instruction info field contains the instruction length for rep prefixed IO
        ctx.should_advance_rip = true;
        break;
    
    // pause instruction
    case VMX_EXIT_REASON_EXECUTE_PAUSE:
        ctx.should_advance_rip = true;
        break;
    
    // dr access - only if MOV-DR exiting is enabled
    case VMX_EXIT_REASON_MOV_DR:
        hv_cpu_log(debug, "mov dr exit: qual=0x%llx\n", ctx.exit_qualification);
        ctx.should_advance_rip = true;
        break;
        
    default:
        hv_cpu_log(warn, "unhandled exit reason: %u qual=0x%llx\n",
                   ctx.exit_reason.BasicExitReason, ctx.exit_qualification);
        // for unhandled exits that have instruction length, try advancing
        // this prevents infinite loops on unhandled instruction exits
        if (ctx.instruction_length > 0 && ctx.instruction_length <= 15) {
            ctx.should_advance_rip = true;
        } else {
            ctx.should_advance_rip = false;
        }
        break;
    }
    
    // handle detachment
    if (ctx.should_exit_vmx) {
        vmexit_detach(cpu, &ctx);
        // vmx_detach_guest will be called from assembly
        return 1;
    }
    
    // advance rip if needed
    if (ctx.should_advance_rip && ret == 0) {
        vmexit_advance_rip(&ctx);
    }
    
    return ret;
}

/*
*   handle vm-exit failure (vmresume failed)
*/
void vmexit_failure_handler(struct cpu_ctx *cpu, struct gp_regs *regs)
{
    u64 error = vmx_get_error();
    
    hv_cpu_log(err, "vmresume failed: error=%llu\n", error);
    
    // this is fatal - halt the cpu
    asm volatile("hlt");
}

/*
*   exit.c - vm-exit handling
*   based on patterns from ksm (asamy/ksm)
*/

#include <linux/kernel.h>
#include <asm/msr.h>
#include <asm/debugreg.h>
#include <asm/special_insns.h>

#include "exit.h"
#include "cpu.h"
#include "vmm.h"
#include "vmx.h"
#include "ept.h"
#include "arch.h"
#include "hv.h"

// x86 trap numbers
#define X86_TRAP_DE     0   // divide error
#define X86_TRAP_DB     1   // debug
#define X86_TRAP_NMI    2   // nmi
#define X86_TRAP_BP     3   // breakpoint
#define X86_TRAP_OF     4   // overflow
#define X86_TRAP_BR     5   // bound range exceeded
#define X86_TRAP_UD     6   // invalid opcode
#define X86_TRAP_NM     7   // device not available
#define X86_TRAP_DF     8   // double fault
#define X86_TRAP_TS     10  // invalid tss
#define X86_TRAP_NP     11  // segment not present
#define X86_TRAP_SS     12  // stack segment fault
#define X86_TRAP_GP     13  // general protection
#define X86_TRAP_PF     14  // page fault
#define X86_TRAP_MF     16  // x87 fpu error
#define X86_TRAP_AC     17  // alignment check
#define X86_TRAP_MC     18  // machine check
#define X86_TRAP_XF     19  // simd exception

// dr6/dr7 bits
#define DR6_BD          (1 << 13)   // debug register access detected
#define DR6_BS          (1 << 14)   // single step
#define DR6_RTM         (1 << 16)   // rtm
#define DR7_GD          (1 << 13)   // general detect enable

// forward declarations
static void vmexit_inject_exception(u8 vector, bool has_error_code, u32 error_code);
static void vmexit_inject_ud(void);
static void vmexit_inject_gp(u32 error_code);
static int vmexit_handle_mov_dr(struct cpu_ctx *cpu, struct vmexit_ctx *ctx);
static int vmexit_handle_io(struct cpu_ctx *cpu, struct vmexit_ctx *ctx);
static int vmexit_handle_exception_nmi(struct cpu_ctx *cpu, struct vmexit_ctx *ctx);
static int vmexit_handle_rdtsc(struct cpu_ctx *cpu, struct vmexit_ctx *ctx);
static int vmexit_handle_rdtscp(struct cpu_ctx *cpu, struct vmexit_ctx *ctx);

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
*   returns true if advanced, false if exception injected instead
*/
static bool vmexit_advance_rip(struct cpu_ctx *cpu, struct vmexit_ctx *ctx)
{
    u64 interruptibility;
    
    // clear interrupt blocking by mov-ss and sti per intel sdm
    interruptibility = arch_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE);
    interruptibility &= ~(VMX_INTERRUPTIBILITY_STATE_BLOCKING_BY_STI_FLAG | 
                          VMX_INTERRUPTIBILITY_STATE_BLOCKING_BY_MOV_SS_FLAG);
    arch_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, interruptibility);
    
    // advance RIP past the instruction
    arch_vmwrite(VMCS_GUEST_RIP, ctx->guest_rip + ctx->instruction_length);
    
    return true;
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
    
    // per intel sdm vol 3 26.2.1.3: instruction length field is used only for
    // software interrupts/exceptions (types 4, 5, 6). for hardware exceptions
    // (type 3), this field is not used, but set to 0 for clarity
    arch_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, 0);
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
    
    if (leaf == HV_CPUID_MAGIC_LEAF && subleaf == HV_CPUID_MAGIC_SUBLEAF) {
        hv_cpu_log(info, "received detach request via cpuid\n");
        ctx->should_exit_vmx = true;
        ctx->should_advance_rip = true;
        return 0;
    }
    
    cpuid_count(leaf, subleaf, &eax, &ebx, &ecx, &edx);
    
    if (leaf == CPUID_VERSION_INFO) {
        ecx = HV_BIT_CLEAR(ecx, CPUID_VMX_BIT);
        ecx = HV_BIT_CLEAR(ecx, 31);
    }
    
    ctx->regs->rax = eax;
    ctx->regs->rbx = ebx;
    ctx->regs->rcx = ecx;
    ctx->regs->rdx = edx;
    
    return 0;
}

/*
*   safe msr read - returns true on success, false on #gp
*/
static bool safe_rdmsr(u32 msr, u64 *value)
{
    u32 low, high;
    
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
    
    if (msr == IA32_FEATURE_CONTROL) {
        hv_cpu_log(warn, "wrmsr: blocked write to ia32_feature_control\n");
        vmexit_inject_gp(0);
        ctx->should_advance_rip = false;
        return 0;
    }
    
    if (!safe_wrmsr(msr, value)) {
        hv_cpu_log(debug, "wrmsr: msr 0x%x caused #gp, injecting\n", msr);
        vmexit_inject_gp(0);
        ctx->should_advance_rip = false;
        return 0;
    }
    
    return 0;
}

/*
*   handle mov cr vm-exit
*   exit qualification format per intel sdm:
*   bits 3:0 = cr number
*   bits 5:4 = access type (0=mov to cr, 1=mov from cr, 2=clts, 3=lmsw)
*   bits 11:8 = source/dest register
*/
int vmexit_handle_mov_cr(struct cpu_ctx *cpu, struct vmexit_ctx *ctx)
{
    u64 qual = ctx->exit_qualification;
    u32 cr_num = qual & 0xF;
    u32 access_type = (qual >> 4) & 0x3;
    u32 reg = (qual >> 8) & 0xF;
    u32 lmsw_source = (qual >> 16) & 0xFFFF;
    u64 *gp_reg;
    u64 value;
    u16 vpid = (u16)arch_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER);
    
    switch (reg) {
    case 0:  gp_reg = &ctx->regs->rax; break;
    case 1:  gp_reg = &ctx->regs->rcx; break;
    case 2:  gp_reg = &ctx->regs->rdx; break;
    case 3:  gp_reg = &ctx->regs->rbx; break;
    case 4:  gp_reg = &ctx->guest_rsp; break;  // rsp from vmcs
    case 5:  gp_reg = &ctx->regs->rbp; break;
    case 6:  gp_reg = &ctx->regs->rsi; break;
    case 7:  gp_reg = &ctx->regs->rdi; break;
    case 8:  gp_reg = &ctx->regs->r8;  break;
    case 9:  gp_reg = &ctx->regs->r9;  break;
    case 10: gp_reg = &ctx->regs->r10; break;
    case 11: gp_reg = &ctx->regs->r11; break;
    case 12: gp_reg = &ctx->regs->r12; break;
    case 13: gp_reg = &ctx->regs->r13; break;
    case 14: gp_reg = &ctx->regs->r14; break;
    case 15: gp_reg = &ctx->regs->r15; break;
    default: gp_reg = &ctx->regs->rax; break;
    }
    
    switch (access_type) {
    case 0:  // mov to cr (write)
        value = *gp_reg;
        switch (cr_num) {
        case 0:
            arch_vmwrite(VMCS_GUEST_CR0, value);
            arch_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, value);
            break;
        case 3:
            arch_vmwrite(VMCS_GUEST_CR3, value & ~(1ULL << 63));
            vmx_invvpid_single_retain_globals(vpid);
            break;
        case 4:
            arch_vmwrite(VMCS_GUEST_CR4, value);
            arch_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, value);
            vmx_invvpid_single(vpid);
            break;
        case 8:
            break;
        }
        break;
        
    case 1:  // mov from cr (read)
        switch (cr_num) {
        case 0:
            value = arch_vmread(VMCS_GUEST_CR0);
            break;
        case 3:
            value = arch_vmread(VMCS_GUEST_CR3);
            break;
        case 4:
            value = arch_vmread(VMCS_GUEST_CR4);
            break;
        case 8:
            value = 0;
            break;
        default:
            value = 0;
            break;
        }
        *gp_reg = value;
        break;
        
    case 2:
        value = arch_vmread(VMCS_GUEST_CR0) & ~X86_CR0_TS;
        arch_vmwrite(VMCS_GUEST_CR0, value);
        arch_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, value);
        break;
        
    case 3:
        value = arch_vmread(VMCS_GUEST_CR0);
        value = (value & ~0xFULL) | (lmsw_source & 0xF);
        if (arch_vmread(VMCS_GUEST_CR0) & X86_CR0_PE)
            value |= X86_CR0_PE;
        arch_vmwrite(VMCS_GUEST_CR0, value);
        arch_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, value);
        break;
    }
    
    return 0;
}

/*
*   handle vmcall vm-exit
*/
int vmexit_handle_vmcall(struct cpu_ctx *cpu, struct vmexit_ctx *ctx)
{
    u64 call_number = ctx->regs->rax;
    
    u32 ss_ar = (u32)arch_vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);
    u32 cpl = (ss_ar >> 5) & 3;
    if (cpl != 0) {
        vmexit_inject_gp(0);
        ctx->should_advance_rip = false;
        return 0;
    }
    
    switch (call_number) {
    case HV_VMCALL_STOP:
        hv_cpu_log(info, "received stop vmcall - detaching\n");
        ctx->should_exit_vmx = true;
        ctx->regs->rax = 0;
        return 1;
        
    default:
        hv_cpu_log(debug, "vmcall: unknown number=%llu\n", call_number);
        vmexit_inject_ud();
        ctx->should_advance_rip = false;
        return 0;
    }
}

/*
*   handle mov dr vm-exit
*   exit qualification format per intel sdm:
*   bits 2:0 = debug register number
*   bit 4    = direction (0=mov to dr, 1=mov from dr)
*   bits 11:8 = general purpose register
*/
static int vmexit_handle_mov_dr(struct cpu_ctx *cpu, struct vmexit_ctx *ctx)
{
    u64 qual = ctx->exit_qualification;
    u32 dr_num = qual & 7;
    bool from_dr = (qual >> 4) & 1;
    u32 reg = (qual >> 8) & 0xF;
    u64 *gp_reg;
    u64 value;
    
    u32 ss_ar = (u32)arch_vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);
    u32 cpl = (ss_ar >> 5) & 3;
    if (cpl != 0) {
        vmexit_inject_gp(0);
        ctx->should_advance_rip = false;
        return 0;
    }
    
    u64 cr4 = arch_vmread(VMCS_GUEST_CR4);
    if ((cr4 & X86_CR4_DE) && (dr_num == 4 || dr_num == 5)) {
        vmexit_inject_ud();
        ctx->should_advance_rip = false;
        return 0;
    }
    
    u64 dr7 = arch_vmread(VMCS_GUEST_DR7);
    if (dr7 & DR7_GD) {
        native_set_debugreg(6, (native_get_debugreg(6) & ~15) | DR6_RTM | DR6_BD);
        vmexit_inject_exception(X86_TRAP_DB, false, 0);
        ctx->should_advance_rip = false;
        return 0;
    }
    
    switch (reg) {
    case 0:  gp_reg = &ctx->regs->rax; break;
    case 1:  gp_reg = &ctx->regs->rcx; break;
    case 2:  gp_reg = &ctx->regs->rdx; break;
    case 3:  gp_reg = &ctx->regs->rbx; break;
    case 4:  gp_reg = &ctx->guest_rsp; break;
    case 5:  gp_reg = &ctx->regs->rbp; break;
    case 6:  gp_reg = &ctx->regs->rsi; break;
    case 7:  gp_reg = &ctx->regs->rdi; break;
    case 8:  gp_reg = &ctx->regs->r8;  break;
    case 9:  gp_reg = &ctx->regs->r9;  break;
    case 10: gp_reg = &ctx->regs->r10; break;
    case 11: gp_reg = &ctx->regs->r11; break;
    case 12: gp_reg = &ctx->regs->r12; break;
    case 13: gp_reg = &ctx->regs->r13; break;
    case 14: gp_reg = &ctx->regs->r14; break;
    case 15: gp_reg = &ctx->regs->r15; break;
    default: gp_reg = &ctx->regs->rax; break;
    }
    
    if (from_dr) {
        switch (dr_num) {
        case 0: value = native_get_debugreg(0); break;
        case 1: value = native_get_debugreg(1); break;
        case 2: value = native_get_debugreg(2); break;
        case 3: value = native_get_debugreg(3); break;
        case 4: value = native_get_debugreg(4); break;
        case 5: value = native_get_debugreg(5); break;
        case 6: value = native_get_debugreg(6); break;
        case 7: value = arch_vmread(VMCS_GUEST_DR7); break;
        default: value = 0; break;
        }
        *gp_reg = value;
    } else {
        value = *gp_reg;
        switch (dr_num) {
        case 0: native_set_debugreg(0, value); break;
        case 1: native_set_debugreg(1, value); break;
        case 2: native_set_debugreg(2, value); break;
        case 3: native_set_debugreg(3, value); break;
        case 4: native_set_debugreg(4, value); break;
        case 5: native_set_debugreg(5, value); break;
        case 6:
            if ((value >> 32) != 0) {
                vmexit_inject_gp(0);
                ctx->should_advance_rip = false;
                return 0;
            }
            native_set_debugreg(6, value);
            break;
        case 7:
            if ((value >> 32) != 0) {
                vmexit_inject_gp(0);
                ctx->should_advance_rip = false;
                return 0;
            }
            arch_vmwrite(VMCS_GUEST_DR7, value);
            break;
        }
    }
    
    return 0;
}

/*
*   handle io instruction vm-exit
*   exit qualification format per intel sdm:
*   bits 2:0   = size of access (0=1 byte, 1=2 bytes, 3=4 bytes)
*   bit 3      = direction (0=out, 1=in)
*   bit 4      = string instruction
*   bit 5      = rep prefixed
*   bit 6      = operand encoding (0=dx, 1=immediate)
*   bits 31:16 = port number
*/
static int vmexit_handle_io(struct cpu_ctx *cpu, struct vmexit_ctx *ctx)
{
    u64 qual = ctx->exit_qualification;
    u32 size = (qual & 7) + 1;
    bool is_in = (qual >> 3) & 1;
    bool is_string = (qual >> 4) & 1;
    bool is_rep = (qual >> 5) & 1;
    u16 port = (u16)(qual >> 16);
    u32 count = 1;
    
    if (is_rep)
        count = (u32)ctx->regs->rcx;
    
    hv_cpu_log(debug, "io: %s port=0x%x size=%d str=%d rep=%d count=%d\n",
               is_in ? "in" : "out", port, size, is_string, is_rep, count);
    
    if (is_string) {
        void *addr = is_in ? (void *)ctx->regs->rdi : (void *)ctx->regs->rsi;
        
        if (is_in) {
            switch (size) {
            case 1:
                asm volatile("rep insb" : "+D"(addr), "+c"(count) : "d"(port) : "memory");
                break;
            case 2:
                asm volatile("rep insw" : "+D"(addr), "+c"(count) : "d"(port) : "memory");
                break;
            case 4:
                asm volatile("rep insl" : "+D"(addr), "+c"(count) : "d"(port) : "memory");
                break;
            }
        } else {
            switch (size) {
            case 1:
                asm volatile("rep outsb" : "+S"(addr), "+c"(count) : "d"(port) : "memory");
                break;
            case 2:
                asm volatile("rep outsw" : "+S"(addr), "+c"(count) : "d"(port) : "memory");
                break;
            case 4:
                asm volatile("rep outsl" : "+S"(addr), "+c"(count) : "d"(port) : "memory");
                break;
            }
        }
        
        u32 orig_count = is_rep ? (u32)ctx->regs->rcx : 1;
        u64 delta = orig_count * size;
        if (ctx->guest_rflags & X86_EFLAGS_DF) {
            if (is_in)
                ctx->regs->rdi -= delta;
            else
                ctx->regs->rsi -= delta;
        } else {
            if (is_in)
                ctx->regs->rdi += delta;
            else
                ctx->regs->rsi += delta;
        }
        if (is_rep)
            ctx->regs->rcx = 0;
    } else {
        u32 value;
        
        if (is_in) {
            switch (size) {
            case 1:
                asm volatile("inb %w1, %b0" : "=a"(value) : "d"(port));
                ctx->regs->rax = (ctx->regs->rax & ~0xFFULL) | (value & 0xFF);
                break;
            case 2:
                asm volatile("inw %w1, %w0" : "=a"(value) : "d"(port));
                ctx->regs->rax = (ctx->regs->rax & ~0xFFFFULL) | (value & 0xFFFF);
                break;
            case 4:
                asm volatile("inl %w1, %0" : "=a"(value) : "d"(port));
                ctx->regs->rax = value;
                break;
            }
        } else {
            value = (u32)ctx->regs->rax;
            switch (size) {
            case 1:
                asm volatile("outb %b0, %w1" :: "a"(value), "d"(port));
                break;
            case 2:
                asm volatile("outw %w0, %w1" :: "a"(value), "d"(port));
                break;
            case 4:
                asm volatile("outl %0, %w1" :: "a"(value), "d"(port));
                break;
            }
        }
    }
    
    return 0;
}

/*
*   handle exception or nmi vm-exit
*   re-inject the exception into guest
*/
static int vmexit_handle_exception_nmi(struct cpu_ctx *cpu, struct vmexit_ctx *ctx)
{
    u32 intr_info = (u32)arch_vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION);
    u32 intr_type = (intr_info >> 8) & 7;
    u32 vector = intr_info & 0xFF;
    bool has_error = (intr_info >> 11) & 1;
    u32 error_code = 0;
    
    if (has_error)
        error_code = (u32)arch_vmread(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE);
    
    hv_cpu_log(debug, "exception/nmi: vector=%d type=%d err=%d code=0x%x\n",
               vector, intr_type, has_error, error_code);
    
    if (vector == X86_TRAP_PF) {
        u64 fault_addr = arch_vmread(VMCS_EXIT_QUALIFICATION);
        asm volatile("mov %0, %%cr2" :: "r"(fault_addr) : "memory");
    }
    
    vmexit_inject_exception((u8)vector, has_error, error_code);
    ctx->should_advance_rip = false;
    
    return 0;
}

/*
*   handle rdtsc vm-exit
*/
static int vmexit_handle_rdtsc(struct cpu_ctx *cpu, struct vmexit_ctx *ctx)
{
    u32 low, high;
    asm volatile("rdtsc" : "=a"(low), "=d"(high));
    ctx->regs->rax = low;
    ctx->regs->rdx = high;
    return 0;
}

/*
*   handle rdtscp vm-exit
*/
static int vmexit_handle_rdtscp(struct cpu_ctx *cpu, struct vmexit_ctx *ctx)
{
    u32 low, high, aux;
    asm volatile("rdtscp" : "=a"(low), "=d"(high), "=c"(aux));
    ctx->regs->rax = low;
    ctx->regs->rdx = high;
    ctx->regs->rcx = aux;
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
    
    if (ret != 0) {
        hv_cpu_log(err, "unhandled ept violation, detaching hypervisor\n");
        ctx->should_exit_vmx = true;
        return 0;
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
*   per intel sdm vol 2b, validate xcr index and value per xcr0 rules
*/
int vmexit_handle_xsetbv(struct cpu_ctx *cpu, struct vmexit_ctx *ctx)
{
    u32 index = (u32)ctx->regs->rcx;
    u64 value = (ctx->regs->rdx << 32) | (u32)ctx->regs->rax;
    u64 xcr0_supported;
    u32 eax, ebx, ecx, edx;
    
    hv_cpu_log(debug, "xsetbv: index=%u value=0x%llx\n", index, value);
    
    if (index != 0) {
        hv_cpu_log(debug, "xsetbv: invalid xcr index %u, injecting #gp\n", index);
        vmexit_inject_gp(0);
        ctx->should_advance_rip = false;
        return 0;
    }
    
    cpuid_count(0x0D, 0, &eax, &ebx, &ecx, &edx);
    xcr0_supported = ((u64)edx << 32) | eax;
    
    if (value & ~xcr0_supported) {
        hv_cpu_log(debug, "xsetbv: unsupported bits set, injecting #gp\n");
        vmexit_inject_gp(0);
        ctx->should_advance_rip = false;
        return 0;
    }
    
    if (!(value & 1)) {
        hv_cpu_log(debug, "xsetbv: xcr0 bit 0 not set, injecting #gp\n");
        vmexit_inject_gp(0);
        ctx->should_advance_rip = false;
        return 0;
    }
    
    if ((value & (1 << 2)) && !(value & (1 << 1))) {
        hv_cpu_log(debug, "xsetbv: avx without sse, injecting #gp\n");
        vmexit_inject_gp(0);
        ctx->should_advance_rip = false;
        return 0;
    }
    
    // avx-512: bits 5-7 must be set together with bit 2
    if (value & 0xE0) {
        if ((value & 0xE4) != 0xE4) {
            hv_cpu_log(debug, "xsetbv: avx-512 partial state, injecting #gp\n");
            vmexit_inject_gp(0);
            ctx->should_advance_rip = false;
            return 0;
        }
    }
    
    asm volatile("xsetbv" :: "a"((u32)value), "d"((u32)(value >> 32)), "c"(index));
    
    return 0;
}

/*
*   handle invd vm-exit
*/
int vmexit_handle_invd(struct cpu_ctx *cpu, struct vmexit_ctx *ctx)
{
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
    
    guest_cr3 = arch_vmread(VMCS_GUEST_CR3);
    
    vmexit_advance_rip(cpu, ctx);
    
    cpu->guest_rip = arch_vmread(VMCS_GUEST_RIP);
    cpu->guest_rsp = arch_vmread(VMCS_GUEST_RSP);
    cpu->guest_rflags = arch_vmread(VMCS_GUEST_RFLAGS);
    
    vmx_exit_root(cpu);
    
    write_cr3(guest_cr3);
    
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
    
    if (READ_ONCE(cpu->vmm->should_exit)) {
        ctx.should_exit_vmx = true;
        vmexit_detach(cpu, &ctx);
        cpu->virtualized = false;
        return 1;
    }
    
    if (ctx.exit_reason.VmEntryFailure) {
        hv_cpu_log(err, "vm-entry failure: reason=%u\n",
                   ctx.exit_reason.BasicExitReason);
        return -1;
    }
    
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
        
    // vmx instructions inject #ud since vmx is not exposed
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
    
    case VMX_EXIT_REASON_INIT_SIGNAL:
        hv_cpu_log(debug, "init signal received\n");
        ctx.should_advance_rip = false;
        break;
    
    case VMX_EXIT_REASON_STARTUP_IPI:
        hv_cpu_log(debug, "sipi signal received\n");
        ctx.should_advance_rip = false;
        break;
    
    case VMX_EXIT_REASON_TRIPLE_FAULT:
        hv_cpu_log(err, "triple fault detected\n");
        ctx.should_advance_rip = false;
        ctx.should_exit_vmx = true;
        break;
    
    case VMX_EXIT_REASON_EXTERNAL_INTERRUPT:
        ctx.should_advance_rip = false;
        break;
    
    case VMX_EXIT_REASON_NMI_WINDOW:
        ctx.should_advance_rip = false;
        break;
    
    case VMX_EXIT_REASON_EXCEPTION_OR_NMI:
        ret = vmexit_handle_exception_nmi(cpu, &ctx);
        break;
    
    case VMX_EXIT_REASON_INTERRUPT_WINDOW:
        ctx.should_advance_rip = false;
        break;
    
    case VMX_EXIT_REASON_MOV_CR:
        ret = vmexit_handle_mov_cr(cpu, &ctx);
        break;
    
    case VMX_EXIT_REASON_EXECUTE_HLT:
        asm volatile("hlt" ::: "memory");
        ctx.should_advance_rip = true;
        break;
    
    case VMX_EXIT_REASON_EXECUTE_INVLPG:
    {
        u64 addr = ctx.exit_qualification;
        u16 vpid = (u16)arch_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER);
        asm volatile("invlpg (%0)" :: "r"(addr) : "memory");
        invvpid_individual_address(vpid, addr);
        ctx.should_advance_rip = true;
        break;
    }
    
    case VMX_EXIT_REASON_EXECUTE_IO_INSTRUCTION:
        ret = vmexit_handle_io(cpu, &ctx);
        break;
    
    case VMX_EXIT_REASON_EXECUTE_PAUSE:
        ctx.should_advance_rip = true;
        break;
    
    case VMX_EXIT_REASON_MOV_DR:
        ret = vmexit_handle_mov_dr(cpu, &ctx);
        break;
    
    case VMX_EXIT_REASON_EXECUTE_RDTSC:
        ret = vmexit_handle_rdtsc(cpu, &ctx);
        break;
    
    case VMX_EXIT_REASON_EXECUTE_RDTSCP:
        ret = vmexit_handle_rdtscp(cpu, &ctx);
        break;
        
    default:
        if (ctx.instruction_length > 0 && ctx.instruction_length <= 15) {
            ctx.should_advance_rip = true;
        } else {
            ctx.should_advance_rip = false;
        }
        break;
    }
    
    if (ctx.should_exit_vmx) {
        vmexit_detach(cpu, &ctx);
        return 1;
    }
    
    if (ctx.should_advance_rip && ret == 0) {
        vmexit_advance_rip(cpu, &ctx);
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
    
    asm volatile("hlt");
}

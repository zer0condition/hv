/*
*   vmxasm.S - vmx assembly routines for context switching
*
*   handles saving/restoring guest register state during vm-exits
*   and launching the guest.
*/

#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/nospec-branch.h>
#include <asm/unwind_hints.h>

.extern cpu_vmx_init_from_guest
.extern vmexit_handler
.extern vmexit_failure_handler

.text

/*
*   struct gp_regs layout (must match cpu.h):
*   offset  field
*   0x00    r15
*   0x08    r14
*   0x10    r13
*   0x18    r12
*   0x20    r11
*   0x28    r10
*   0x30    r9
*   0x38    r8
*   0x40    rdi
*   0x48    rsi
*   0x50    rdx
*   0x58    rcx
*   0x60    rbx
*   0x68    rax
*   0x70    _pad (rsp placeholder)
*   0x78    rbp
*   total: 0x80 bytes
*/

#define REGS_R15    0x00
#define REGS_R14    0x08
#define REGS_R13    0x10
#define REGS_R12    0x18
#define REGS_R11    0x20
#define REGS_R10    0x28
#define REGS_R9     0x30
#define REGS_R8     0x38
#define REGS_RDI    0x40
#define REGS_RSI    0x48
#define REGS_RDX    0x50
#define REGS_RCX    0x58
#define REGS_RBX    0x60
#define REGS_RAX    0x68
#define REGS_PAD    0x70
#define REGS_RBP    0x78
#define REGS_SIZE   0x80

/*
*   launch guest and enter vmx operation
*
*   void vmx_launch_guest(void *vmm_ctx)
*
*   saves current register state and calls cpu_vmx_init to setup vmx.
*   if vmlaunch succeeds, execution continues at vmx_guest_resume.
*   if it fails, we return normally.
*/
SYM_FUNC_START(vmx_launch_guest)
    ENDBR
    UNWIND_HINT_FUNC
    // save all callee-saved registers
    push %rbp
    mov %rsp, %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    pushfq
    
    /*
    *   call cpu_vmx_init_from_guest(vmm_ctx, rsp, rip, rflags)
    *   rdi = vmm_ctx (already set by caller)
    */
    
    // rsp value for guest resume
    mov %rsp, %rsi
    
    // rip = address to resume at after vmlaunch
    lea vmx_guest_resume(%rip), %rdx
    
    // rflags from stack
    mov (%rsp), %rcx
    
    // call cpu initialization - this will call vmlaunch
    call cpu_vmx_init_from_guest
    
    // if we get here, vmlaunch failed - restore and return
    popfq
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    RET

vmx_guest_resume:
    // vmlaunch succeeded and we've exited vmx
    // restore saved state and return to normal execution
    popfq
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    RET
SYM_FUNC_END(vmx_launch_guest)
EXPORT_SYMBOL(vmx_launch_guest)

/*
*   vm-exit handler entry point
*
*   called by the processor on vm-exit.
*   host_rsp was set to &host_stack->cpu, so [rsp] = cpu_ctx pointer.
*
*   critical: the first thing we do is save the cpu pointer before
*   any push instructions overwrite [rsp].
*/
SYM_FUNC_START(vmx_vmexit_handler)
    ENDBR
    UNWIND_HINT_REGS base=%rsp offset=0
    /*
    *   on vm-exit: rsp = host_rsp = &host_stack->cpu
    *   [rsp] = cpu_ctx pointer (8 bytes)
    *
    *   we use xchg to atomically swap guest r15 with the cpu pointer:
    *   - r15 gets the cpu pointer
    *   - [rsp] gets the original guest r15 value
    *   then we can push normally, and [rsp] (which becomes part of our
    *   pushed data) will contain the guest r15.
    */
    xchg %r15, (%rsp)       // r15 = cpu_ctx, [rsp] = guest_r15
    
    // allocate stack frame for gp_regs
    sub $(REGS_SIZE - 8), %rsp   // -8 because r15 slot is at [rsp+0x78] after original push area
    
    // save all registers to the stack frame
    mov %rbp, REGS_RBP(%rsp)
    mov %rax, REGS_RAX(%rsp)
    mov %rbx, REGS_RBX(%rsp)
    mov %rcx, REGS_RCX(%rsp)
    mov %rdx, REGS_RDX(%rsp)
    mov %rsi, REGS_RSI(%rsp)
    mov %rdi, REGS_RDI(%rsp)
    mov %r8,  REGS_R8(%rsp)
    mov %r9,  REGS_R9(%rsp)
    mov %r10, REGS_R10(%rsp)
    mov %r11, REGS_R11(%rsp)
    mov %r12, REGS_R12(%rsp)
    mov %r13, REGS_R13(%rsp)
    mov %r14, REGS_R14(%rsp)
    
    // guest r15 is at [rsp + regs_size - 8] = [rsp + 0x78] from the xchg
    mov (REGS_SIZE - 8)(%rsp), %rax
    mov %rax, REGS_R15(%rsp)
    
    // store cpu pointer where we can retrieve it (reuse the r15 backup location)
    mov %r15, (REGS_SIZE - 8)(%rsp)
    
    // set up arguments for c handler
    mov %r15, %rdi          // cpu_ctx pointer (first arg)
    mov %rsp, %rsi          // gp_regs pointer (second arg)
    
    // 16-byte align stack for abi compliance
    mov %rsp, %rbp          // save original rsp in rbp
    sub $8, %rsp            // host stack is 8 bytes off 16-byte alignment
    UNWIND_HINT_REGS base=%rsp offset=0 // rsp aligned for the C call

    // call c handler: int vmexit_handler(cpu_ctx*, gp_regs*)
    call vmexit_handler
    
    // restore original stack pointer
    mov %rbp, %rsp
    
    // check return value
    test %eax, %eax
    jnz .Lvmexit_special
    
    // normal exit - restore guest registers and resume
    mov REGS_R14(%rsp), %r14
    mov REGS_R13(%rsp), %r13
    mov REGS_R12(%rsp), %r12
    mov REGS_R11(%rsp), %r11
    mov REGS_R10(%rsp), %r10
    mov REGS_R9(%rsp),  %r9
    mov REGS_R8(%rsp),  %r8
    mov REGS_RDI(%rsp), %rdi
    mov REGS_RSI(%rsp), %rsi
    mov REGS_RDX(%rsp), %rdx
    mov REGS_RCX(%rsp), %rcx
    mov REGS_RBX(%rsp), %rbx
    mov REGS_RAX(%rsp), %rax
    mov REGS_RBP(%rsp), %rbp
    mov REGS_R15(%rsp), %r15
    
    // restore stack and resume
    add $(REGS_SIZE - 8), %rsp
    add $8, %rsp            // skip the saved r15/cpu_ptr slot
    
    vmresume
    
    // if vmresume fails, handle error
    jmp .Lvmresume_failed

.Lvmexit_special:
    // return value != 0: positive = detach, negative = error
    test %eax, %eax
    js .Lvmresume_failed
    
    // detach requested - restore registers for return to guest mode
    mov REGS_R14(%rsp), %r14
    mov REGS_R13(%rsp), %r13
    mov REGS_R12(%rsp), %r12
    mov REGS_R11(%rsp), %r11
    mov REGS_R10(%rsp), %r10
    mov REGS_R9(%rsp),  %r9
    mov REGS_R8(%rsp),  %r8
    mov REGS_RDI(%rsp), %rdi
    mov REGS_RSI(%rsp), %rsi
    mov REGS_RDX(%rsp), %rdx
    mov REGS_RCX(%rsp), %rcx
    mov REGS_RBX(%rsp), %rbx
    mov REGS_RBP(%rsp), %rbp
    mov REGS_R15(%rsp), %r15
    // don't restore rax - it has return info from vmexit_detach
    
    // get cpu_ctx pointer for detach
    mov (REGS_SIZE - 8)(%rsp), %rax  // cpu_ctx in rax
    
    add $(REGS_SIZE), %rsp
    
    jmp vmx_do_detach

.Lvmresume_failed:
    // vmresume failed - get cpu pointer and call failure handler
    mov (REGS_SIZE - 8)(%rsp), %rdi  // cpu_ctx
    mov %rsp, %rsi                    // gp_regs
    
    // align stack
    and $-16, %rsp
    
    call vmexit_failure_handler
    
    // should not return
1:  hlt
    jmp 1b
SYM_FUNC_END(vmx_vmexit_handler)
EXPORT_SYMBOL(vmx_vmexit_handler)

/*
*   complete vmx detach and return to normal execution
*
*   at entry:
*   - rax = cpu_ctx pointer with guest_rsp, guest_rip, guest_rflags set
*   - vmx has been exited (vmxoff done)
*   - all other registers restored to guest values
*/
SYM_FUNC_START(vmx_do_detach)
    ENDBR
    UNWIND_HINT_REGS base=%rsp offset=0
    /*
    *   rax = cpu_ctx pointer
    *   cpu_ctx->guest_rsp (offset 0x1c8) has the rsp to restore
    *   cpu_ctx->guest_rip (offset 0x1d0) has the rip to return to
    *   cpu_ctx->guest_rflags (offset 0x1d8) has rflags to restore
    */
    
    // load guest rsp into rcx (temp)
    mov 0x1c8(%rax), %rcx    // guest_rsp
    
    // load guest rip into rdx (temp)
    mov 0x1d0(%rax), %rdx    // guest_rip
    
    // load guest rflags
    mov 0x1d8(%rax), %rax    // guest_rflags
    
    // switch to guest stack
    mov %rcx, %rsp
    UNWIND_HINT_REGS base=%rsp offset=0

    // push return address (guest rip)
    push %rdx

    // push rflags so we can restore with popfq
    push %rax

    // restore rflags
    popfq

    // clear rax to not leak info
    xor %eax, %eax

    // return to guest rip
    RET
SYM_FUNC_END(vmx_do_detach)
/*
*   guest resume label (for vmcs guest rip)
*/
SYM_FUNC_START(vmx_guest_resume_label)
    ENDBR
    RET
SYM_FUNC_END(vmx_guest_resume_label)
EXPORT_SYMBOL(vmx_guest_resume_label)

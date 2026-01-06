#pragma once

#include <linux/types.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/special_insns.h>
#include "ia32/ia32_wrapper.h"
#include "hv.h"

/*
*   cpuid leaves
*/
#define CPUID_VERSION_INFO      0x01
#define CPUID_FEATURE_INFO      0x07
#define CPUID_EXTENDED_STATE    0x0D
#define CPUID_PHYS_ADDR_WIDTH   0x80000008

/*
*   cpuid bit positions
*/
#define CPUID_VMX_BIT           5   // ecx bit 5 for vmx support
#define CPUID_XSAVE_BIT         26  // ecx bit 26 for xsave support

/*
*   segment descriptor
*/
struct hv_segment_descriptor {
    u16 selector;
    u64 base;
    u32 limit;
    u32 access_rights;
};

/*
*   descriptor table register
*/
struct hv_descriptor_table {
    u64 base;
    u16 limit;
} __packed;

/*
*   cpu state snapshot for vmx
*/
struct hv_cpu_state {
    // control registers
    CR0 cr0;
    u64 cr2;
    CR3 cr3;
    CR4 cr4;
    DR7 dr7;
    
    // descriptor table registers
    struct hv_descriptor_table gdtr;
    struct hv_descriptor_table idtr;
    
    // segment registers
    struct hv_segment_descriptor cs;
    struct hv_segment_descriptor ds;
    struct hv_segment_descriptor es;
    struct hv_segment_descriptor ss;
    struct hv_segment_descriptor fs;
    struct hv_segment_descriptor gs;
    struct hv_segment_descriptor tr;
    struct hv_segment_descriptor ldtr;
    
    // fs/gs bases
    u64 fs_base;
    u64 gs_base;
    u64 kernel_gs_base;
    
    // msrs
    u64 debugctl;
    u64 sysenter_cs;
    u64 sysenter_esp;
    u64 sysenter_eip;
    u64 efer;
    u64 pat;
    u64 star;
    u64 lstar;
    u64 cstar;
    u64 sfmask;
};

/*
*   function declarations
*/
bool arch_running_in_vm(void);
bool arch_cpu_has_vmx(void);
bool arch_vmx_enabled_by_bios(void);
void arch_enable_vmxe(void);
void arch_disable_vmxe(void);
void arch_capture_cpu_state(struct hv_cpu_state *state);

/*
*   vmx instruction wrappers
*/
int arch_vmxon(phys_addr_t vmxon_phys);
int arch_vmxoff(void);
int arch_vmclear(phys_addr_t vmcs_phys);
int arch_vmptrld(phys_addr_t vmcs_phys);
int arch_vmlaunch(void);
int arch_vmresume(void);
u64 arch_vmread(u64 field);
int arch_vmwrite(u64 field, u64 value);

/*
*   check if address is canonical
*/
static inline bool arch_is_canonical(u64 addr)
{
    s64 saddr = (s64)addr;
    return (saddr >> 47) == 0 || (saddr >> 47) == -1;
}

static inline u64 arch_get_rsp(void)
{
    u64 rsp;
    asm volatile("mov %%rsp, %0" : "=r"(rsp));
    return rsp;
}

static inline u64 arch_get_rflags(void)
{
    u64 rflags;
    asm volatile("pushfq; pop %0" : "=r"(rflags));
    return rflags;
}

static inline void arch_set_cr0_bits(u64 set, u64 clear)
{
    u64 cr0 = read_cr0();
    cr0 |= set;
    cr0 &= ~clear;
    write_cr0(cr0);
}

static inline void arch_set_cr4_bits(u64 set, u64 clear)
{
    u64 cr4 = __read_cr4();
    cr4 |= set;
    cr4 &= ~clear;
    __write_cr4(cr4);
}

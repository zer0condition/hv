#pragma once

#include <linux/types.h>
#include <linux/list.h>
#include "ia32/ia32_wrapper.h"

struct cpu_ctx;
struct vmm_ctx;

/*
*   ept memory types
*/
#define EPT_MEMORY_TYPE_UC  0   // uncacheable
#define EPT_MEMORY_TYPE_WC  1   // write combining
#define EPT_MEMORY_TYPE_WT  4   // write through
#define EPT_MEMORY_TYPE_WP  5   // write protected
#define EPT_MEMORY_TYPE_WB  6   // write back

/*
*   ept page sizes
*/
#define EPT_PAGE_SIZE_4K    PAGE_SIZE
#define EPT_PAGE_SIZE_2M    (512UL * PAGE_SIZE)
#define EPT_PAGE_SIZE_1G    (512UL * EPT_PAGE_SIZE_2M)

#define EPT_ENTRIES_PER_TABLE 512

/*
*   ept pml4 entry (page map level 4)
*/
typedef union {
    struct {
        u64 read        : 1;
        u64 write       : 1;
        u64 execute     : 1;
        u64 reserved1   : 5;
        u64 accessed    : 1;
        u64 ignored1    : 1;
        u64 user_exec   : 1;
        u64 ignored2    : 1;
        u64 pfn         : 40;
        u64 ignored3    : 12;
    };
    u64 value;
} ept_pml4e_t;

/*
*   ept pdpt entry (page directory pointer table)
*/
typedef union {
    struct {
        u64 read        : 1;
        u64 write       : 1;
        u64 execute     : 1;
        u64 reserved1   : 4;
        u64 large_page  : 1;    // 1gb page if set
        u64 accessed    : 1;
        u64 ignored1    : 1;
        u64 user_exec   : 1;
        u64 ignored2    : 1;
        u64 pfn         : 40;
        u64 ignored3    : 12;
    };
    u64 value;
} ept_pdpte_t;

/*
*   ept pd entry (page directory)
*/
typedef union {
    struct {
        u64 read        : 1;
        u64 write       : 1;
        u64 execute     : 1;
        u64 mem_type    : 3;
        u64 ignore_pat  : 1;
        u64 large_page  : 1;    // 2mb page if set
        u64 accessed    : 1;
        u64 dirty       : 1;
        u64 user_exec   : 1;
        u64 ignored1    : 1;
        u64 pfn         : 40;
        u64 ignored2    : 11;
        u64 suppress_ve : 1;
    };
    u64 value;
} ept_pde_t;

/*
*   ept pt entry (page table) - 4kb pages
*/
typedef union {
    struct {
        u64 read        : 1;
        u64 write       : 1;
        u64 execute     : 1;
        u64 mem_type    : 3;
        u64 ignore_pat  : 1;
        u64 ignored1    : 1;
        u64 accessed    : 1;
        u64 dirty       : 1;
        u64 user_exec   : 1;
        u64 ignored2    : 1;
        u64 pfn         : 40;
        u64 ignored3    : 11;
        u64 suppress_ve : 1;
    };
    u64 value;
} ept_pte_t;

/*
*   ept page table structure (identity mapped)
*/
struct ept_tables {
    // pml4 - covers 512 * 512gb = 256tb
    ept_pml4e_t pml4[EPT_ENTRIES_PER_TABLE] __aligned(PAGE_SIZE);
    
    // pdpt - covers 512 * 1gb = 512gb (only first entry of pml4 used)
    ept_pdpte_t pdpt[EPT_ENTRIES_PER_TABLE] __aligned(PAGE_SIZE);
    
    // pd tables - one per pdpt entry we use, each covers 512 * 2mb = 1gb
    ept_pde_t pds[EPT_ENTRIES_PER_TABLE][EPT_ENTRIES_PER_TABLE] __aligned(PAGE_SIZE);
};

/*
*   split 2mb page tracking
*/
struct ept_split_page {
    ept_pte_t pt[EPT_ENTRIES_PER_TABLE] __aligned(PAGE_SIZE);
    struct list_head list;
    u64 phys_base;
};

/*
*   ept hook entry
*/
struct ept_hook {
    struct list_head list;
    
    u64 original_phys;          // original page physical address
    u64 hook_phys;              // hook page physical address
    void *hook_virt;
    
    ept_pte_t original_entry;   // original 4kb mapping before hook
    struct ept_split_page *split;
    u16 pt_index;               // index within the split page table
};

/*
*   global ept state
*/
struct ept_state {
    struct ept_tables *tables;
    phys_addr_t tables_phys;
    struct vmm_ctx *vmm;
    
    EPT_POINTER eptp;           // eptp value for vmcs
    bool invept_supported;      // hardware invept support flag
    
    struct list_head split_pages;
    struct list_head hooks;
    spinlock_t lock;            // protects hooks/split_pages
};

/*
*   ept functions
*/
struct ept_state *ept_init(struct vmm_ctx *vmm);
void ept_destroy(struct ept_state *ept);
int ept_build_identity_map(struct ept_state *ept, struct vmm_ctx *vmm);

/*
*   ept hooking functions
*/
int ept_hook_page(struct ept_state *ept, u64 target_phys, void *hook_func);
int ept_unhook_page(struct ept_state *ept, u64 target_phys);

/*
*   ept violation handling
*/
int ept_handle_violation(struct cpu_ctx *cpu, u64 guest_phys, u64 qualification);
int ept_handle_misconfiguration(struct cpu_ctx *cpu, u64 guest_phys);

/*
*   utility
*/
u8 ept_get_memory_type(struct vmm_ctx *vmm, u64 phys_addr);

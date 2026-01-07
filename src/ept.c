/*
*   ept.c - extended page tables (ept) implementation
*/

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/io.h>
#include <linux/spinlock.h>
#include <asm/msr.h>

#include "ept.h"
#include "vmm.h"
#include "hv.h"

static struct ept_split_page *ept_split_large_page(struct ept_state *ept,
                                                   struct vmm_ctx *vmm,
                                                   u64 phys_base);

struct invept_desc {
    u64 eptp;
    u64 reserved;
};

static inline void ept_invalidate(struct ept_state *ept)
{
    u8 zf;
    u64 type = 1;  // single-context invalidation
    struct invept_desc desc = {
        .eptp = ept->eptp.AsUInt,
        .reserved = 0,
    };

    if (!ept->invept_supported)
        return;

    asm volatile("invept %[desc], %[type]\n\tsetz %b[zf]"
                 : [zf] "=q"(zf)
                 : [type] "r"(type), [desc] "m"(desc)
                 : "cc", "memory");
    if (zf)
        hv_log(warn, "invept failed (type=%llu, eptp=0x%llx)\n", type, desc.eptp);
}

static struct ept_split_page *ept_find_split(struct ept_state *ept, u64 phys_base)
{
    struct ept_split_page *split;
    list_for_each_entry(split, &ept->split_pages, list) {
        if (split->phys_base == phys_base)
            return split;
    }
    return NULL;
}

static struct ept_hook *ept_find_hook(struct ept_state *ept, u64 page_phys)
{
    struct ept_hook *hook;
    list_for_each_entry(hook, &ept->hooks, list) {
        if (hook->original_phys == page_phys)
            return hook;
    }
    return NULL;
}

static struct ept_split_page *ept_ensure_split(struct ept_state *ept,
                                               ept_pde_t *pde,
                                               u64 phys_base)
{
    struct ept_split_page *split;
    u64 pt_phys;
    
    split = ept_find_split(ept, phys_base);
    if (split)
        return split;
    
    if (!pde->large_page)
        return NULL;
    
    split = ept_split_large_page(ept, ept->vmm, phys_base);
    if (!split)
        return NULL;
    
    pt_phys = virt_to_phys(split->pt) >> 12;
    pde->value = 0;
    pde->read = 1;
    pde->write = 1;
    pde->execute = 1;
    pde->user_exec = 1;
    pde->pfn = pt_phys;
    pde->large_page = 0;
    
    ept_invalidate(ept);
    return split;
}

static inline u16 ept_pt_index(u64 phys)
{
    return (phys >> 12) & 0x1FF;
}

static inline u16 ept_pd_index(u64 phys)
{
    return (phys >> 21) & 0x1FF;
}

static inline u16 ept_pdpt_index(u64 phys)
{
    return (phys >> 30) & 0x1FF;
}

/*
*   check ept capabilities
*/
static bool ept_check_capabilities(void)
{
    IA32_VMX_EPT_VPID_CAP_REGISTER cap;
    
    cap.AsUInt = native_read_msr(IA32_VMX_EPT_VPID_CAP);
    
    if (!cap.PageWalkLength4) {
        hv_log(err, "ept does not support 4-level page walk\n");
        return false;
    }
    
    if (!cap.MemoryTypeWriteBack) {
        hv_log(err, "ept does not support wb memory type\n");
        return false;
    }
    
    if (!cap.Pde2MbPages) {
        hv_log(err, "ept does not support 2mb pages\n");
        return false;
    }
    
    hv_log(info, "ept capabilities: 4-level=%d, wb=%d, 2mb=%d, 1gb=%d, invept=%d\n",
           cap.PageWalkLength4, cap.MemoryTypeWriteBack,
           cap.Pde2MbPages, cap.Pdpte1GbPages, cap.Invept);
    
    return true;
}

/*
*   get memory type for physical address from mtrr
*/
u8 ept_get_memory_type(struct vmm_ctx *vmm, u64 phys_addr)
{
    unsigned int i;
    
    for (i = 0; i < vmm->mtrr.num_ranges; i++) {
        if (phys_addr >= vmm->mtrr.ranges[i].base &&
            phys_addr <= vmm->mtrr.ranges[i].end) {
            return vmm->mtrr.ranges[i].type;
        }
    }
    
    return vmm->mtrr.default_type;
}

/*
*   build ept identity map with 2mb pages
*/
int ept_build_identity_map(struct ept_state *ept, struct vmm_ctx *vmm)
{
    struct ept_tables *tables = ept->tables;
    unsigned int pdpt_idx, pd_idx;
    u64 phys_addr;
    u8 mem_type;
    
    tables->pml4[0].value = 0;
    tables->pml4[0].read = 1;
    tables->pml4[0].write = 1;
    tables->pml4[0].execute = 1;
    tables->pml4[0].pfn = virt_to_phys(tables->pdpt) >> 12;
    
    for (pdpt_idx = 0; pdpt_idx < EPT_ENTRIES_PER_TABLE; pdpt_idx++) {
        tables->pdpt[pdpt_idx].value = 0;
        tables->pdpt[pdpt_idx].read = 1;
        tables->pdpt[pdpt_idx].write = 1;
        tables->pdpt[pdpt_idx].execute = 1;
        tables->pdpt[pdpt_idx].pfn = virt_to_phys(tables->pds[pdpt_idx]) >> 12;
        
        for (pd_idx = 0; pd_idx < EPT_ENTRIES_PER_TABLE; pd_idx++) {
            phys_addr = ((u64)pdpt_idx << 30) | ((u64)pd_idx << 21);
            
            mem_type = ept_get_memory_type(vmm, phys_addr);
            
            tables->pds[pdpt_idx][pd_idx].value = 0;
            tables->pds[pdpt_idx][pd_idx].read = 1;
            tables->pds[pdpt_idx][pd_idx].write = 1;
            tables->pds[pdpt_idx][pd_idx].execute = 1;
            tables->pds[pdpt_idx][pd_idx].large_page = 1;
            tables->pds[pdpt_idx][pd_idx].mem_type = mem_type;
            tables->pds[pdpt_idx][pd_idx].pfn = phys_addr >> 12;
        }
    }
    
    hv_log(info, "ept identity map built: 512gb mapped with 2mb pages\n");
    return 0;
}

/*
*   initialize ept state
*/
struct ept_state *ept_init(struct vmm_ctx *vmm)
{
    struct ept_state *ept;
    
    if (!ept_check_capabilities())
        return NULL;
    
    ept = kzalloc(sizeof(*ept), GFP_KERNEL);
    if (!ept)
        return NULL;
    ept->vmm = vmm;
    {
        IA32_VMX_EPT_VPID_CAP_REGISTER cap;
        cap.AsUInt = native_read_msr(IA32_VMX_EPT_VPID_CAP);
        ept->invept_supported = cap.Invept;
    }
    
    INIT_LIST_HEAD(&ept->split_pages);
    INIT_LIST_HEAD(&ept->hooks);
    spin_lock_init(&ept->lock);
    
    ept->tables = (struct ept_tables *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
                                      get_order(sizeof(struct ept_tables)));
    if (!ept->tables) {
        hv_log(err, "failed to allocate ept tables\n");
        kfree(ept);
        return NULL;
    }
    ept->tables_phys = virt_to_phys(ept->tables);
    
    if (ept_build_identity_map(ept, vmm) != 0) {
        free_pages((unsigned long)ept->tables, get_order(sizeof(struct ept_tables)));
        kfree(ept);
        return NULL;
    }
    
    ept->eptp.AsUInt = 0;
    ept->eptp.MemoryType = EPT_MEMORY_TYPE_WB;
    ept->eptp.PageWalkLength = 3;
    ept->eptp.EnableAccessAndDirtyFlags = 0;
    ept->eptp.PageFrameNumber = ept->tables_phys >> 12;
    
    hv_log(info, "ept initialized: eptp=0x%llx\n", ept->eptp.AsUInt);
    
    return ept;
}

/*
*   destroy ept state
*/
void ept_destroy(struct ept_state *ept)
{
    struct ept_split_page *split, *tmp_split;
    struct ept_hook *hook, *tmp_hook;
    
    if (!ept)
        return;
    
    list_for_each_entry_safe(split, tmp_split, &ept->split_pages, list) {
        list_del(&split->list);
        free_pages_exact(split, sizeof(*split));
    }
    
    list_for_each_entry_safe(hook, tmp_hook, &ept->hooks, list) {
        if (hook->hook_virt)
            free_pages_exact(hook->hook_virt, PAGE_SIZE);
        list_del(&hook->list);
        kfree(hook);
    }
    
    if (ept->tables)
        free_pages((unsigned long)ept->tables, get_order(sizeof(struct ept_tables)));
    
    kfree(ept);
}

/*
*   split 2mb page into 4kb pages
*/
static struct ept_split_page *ept_split_large_page(struct ept_state *ept,
                                                   struct vmm_ctx *vmm,
                                                   u64 phys_base)
{
    struct ept_split_page *split;
    unsigned int i;
    u64 phys_addr;
    u8 mem_type;
    
    split = alloc_pages_exact(sizeof(*split), GFP_KERNEL | __GFP_ZERO);
    if (!split)
        return NULL;
    
    split->phys_base = phys_base & ~(EPT_PAGE_SIZE_2M - 1);
    
    // create 512 x 4kb entries
    for (i = 0; i < EPT_ENTRIES_PER_TABLE; i++) {
        phys_addr = split->phys_base + (i * PAGE_SIZE);
        mem_type = ept_get_memory_type(vmm, phys_addr);
        
        split->pt[i].value = 0;
        split->pt[i].read = 1;
        split->pt[i].write = 1;
        split->pt[i].execute = 1;
        split->pt[i].mem_type = mem_type;
        split->pt[i].pfn = phys_addr >> 12;
    }
    
    list_add(&split->list, &ept->split_pages);
    
    return split;
}

/*
*   handle ept violation
*/
int ept_handle_violation(struct cpu_ctx *cpu, u64 guest_phys, u64 qualification)
{
    struct ept_state *ept = cpu->vmm->ept;
    u64 page_phys = guest_phys & PAGE_MASK;
    struct ept_hook *hook;
    VMX_EXIT_QUALIFICATION_EPT_VIOLATION qual = {.AsUInt = qualification};
    
    hv_cpu_log(debug, "ept violation: gpa=0x%llx r=%d w=%d x=%d\n",
               guest_phys, qual.ReadAccess, qual.WriteAccess, qual.ExecuteAccess);
    
    hook = ept_find_hook(ept, page_phys);
    if (hook) {
        ept_pte_t *pte = &hook->split->pt[hook->pt_index];
        /* allow the access that faulted, keep execute enabled */
        if (qual.ReadAccess)
            pte->read = 1;
        if (qual.WriteAccess)
            pte->write = 1;
        pte->execute = 1;
        ept_invalidate(ept);
        return 0;
    }
    
    hv_cpu_log(err, "unexpected ept violation at 0x%llx\n", guest_phys);
    return -1;
}

/*
*   handle ept misconfiguration
*/
int ept_handle_misconfiguration(struct cpu_ctx *cpu, u64 guest_phys)
{
    hv_cpu_log(err, "ept misconfiguration at gpa=0x%llx\n", guest_phys);
    
    // this indicates a bug in ept setup
    return -1;
}

/*
*   hook a page using ept
*   creates an execute-only shadow page with hooked code
*/
int ept_hook_page(struct ept_state *ept, u64 target_phys, void *hook_func)
{
    struct ept_hook *hook;
    struct ept_split_page *split;
    ept_pde_t *pde;
    ept_pte_t new_pte;
    u64 page_phys = target_phys & PAGE_MASK;
    u16 pdpt_idx = ept_pdpt_index(page_phys);
    u16 pd_idx = ept_pd_index(page_phys);
    u16 pt_idx = ept_pt_index(page_phys);
    u64 phys_base = page_phys & ~(EPT_PAGE_SIZE_2M - 1);
    unsigned long flags;
    
    if (!hook_func)
        return -EINVAL;
    
    spin_lock_irqsave(&ept->lock, flags);
    if (ept_find_hook(ept, page_phys)) {
        spin_unlock_irqrestore(&ept->lock, flags);
        return -EEXIST;
    }
    
    pde = &ept->tables->pds[pdpt_idx][pd_idx];
    if (!pde->read || !pde->write || !pde->execute) {
        spin_unlock_irqrestore(&ept->lock, flags);
        return -EFAULT;
    }
    split = ept_ensure_split(ept, pde, phys_base);
    if (!split) {
        spin_unlock_irqrestore(&ept->lock, flags);
        return -ENOMEM;
    }
    
    hook = kzalloc(sizeof(*hook), GFP_KERNEL);
    if (!hook) {
        spin_unlock_irqrestore(&ept->lock, flags);
        return -ENOMEM;
    }
    
    hook->hook_virt = alloc_pages_exact(PAGE_SIZE, GFP_KERNEL | __GFP_ZERO);
    if (!hook->hook_virt) {
        kfree(hook);
        spin_unlock_irqrestore(&ept->lock, flags);
        return -ENOMEM;
    }
    hook->hook_phys = virt_to_phys(hook->hook_virt);
    hook->original_phys = page_phys;
    hook->original_entry = split->pt[pt_idx];
    hook->split = split;
    hook->pt_index = pt_idx;
    
    /* simple hook
     * mov rax, hook_func; jmp rax 
     */
    {
        u8 *stub = hook->hook_virt;
        stub[0] = 0x48; stub[1] = 0xB8;
        *(u64 *)(stub + 2) = (u64)hook_func;
        stub[10] = 0xFF; stub[11] = 0xE0;
        memset(stub + 12, 0x90, 16);
    }
    
    new_pte.value = 0;
    new_pte.read = 0;
    new_pte.write = 0;
    new_pte.execute = 1;
    new_pte.mem_type = EPT_MEMORY_TYPE_WB;
    new_pte.pfn = hook->hook_phys >> 12;
    split->pt[pt_idx] = new_pte;
    
    list_add(&hook->list, &ept->hooks);
    ept_invalidate(ept);
    spin_unlock_irqrestore(&ept->lock, flags);
    hv_log(info, "ept hook installed for gpa 0x%llx -> hook 0x%llx\n",
           page_phys, (u64)hook_func);
    return 0;
}

/*
*   remove ept hook
*/
int ept_unhook_page(struct ept_state *ept, u64 target_phys)
{
    struct ept_hook *hook;
    u64 page_phys = target_phys & PAGE_MASK;
    unsigned long flags;
    
    spin_lock_irqsave(&ept->lock, flags);
    hook = ept_find_hook(ept, page_phys);
    if (!hook) {
        spin_unlock_irqrestore(&ept->lock, flags);
        return -ENOENT;
    }
    
    hook->split->pt[hook->pt_index] = hook->original_entry;
    ept_invalidate(ept);
    
    if (hook->hook_virt)
        free_pages_exact(hook->hook_virt, PAGE_SIZE);
    list_del(&hook->list);
    kfree(hook);
    spin_unlock_irqrestore(&ept->lock, flags);
    hv_log(info, "ept hook removed for gpa 0x%llx\n", page_phys);
    return 0;
}

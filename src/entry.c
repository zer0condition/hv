/*
*   entry.c - module entry point
*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/string.h>

#include "hv.h"
#include "vmm.h"
#include "arch.h"

static struct vmm_ctx *vmm = NULL;

/*
*   module initialization
*/
static int __init hv_init(void)
{
    int ret;
    
    hv_log(info, "linux type-2 hypervisor v%s\n", HV_VERSION);
    
    // check if we're running inside a vm
    if (arch_running_in_vm()) {
        hv_log(err, "cannot enable hypervisor inside a vm\n");
        return -ENODEV;
    }
    
    hv_log(info, "initializing vmm\n");
    
    vmm = vmm_init();
    if (!vmm) {
        hv_log(err, "failed to initialize vmm\n");
        return -EINVAL;
    }
    
    ret = vmm_start(vmm);
    if (ret != 0) {
        hv_log(err, "failed to start hypervisor\n");
        vmm_shutdown(vmm);
        vmm = NULL;
        return ret;
    }
    
    hv_log(info, "hypervisor enabled successfully (%u/%u cpus)\n",
           vmm->num_virtualized, vmm->num_cpus);
    
    return 0;
}

/*
*   module cleanup
*/
static void __exit hv_exit(void)
{
    if (vmm) {
        hv_log(info, "shutting down hypervisor\n");
        vmm_shutdown(vmm);
        vmm = NULL;
        hv_log(info, "hypervisor shutdown complete\n");
    }
}

module_init(hv_init);
module_exit(hv_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zer0condition");
MODULE_DESCRIPTION("Intel VT-x type-2 hypervisor");
MODULE_VERSION(HV_VERSION);
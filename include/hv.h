#pragma once

#include <linux/kernel.h>
#include <linux/printk.h>

#define HV_VERSION "1.0.0"

/*
*   logging macros
*/
#define hv_log(level, fmt, ...) \
    pr_##level("hv: " fmt, ##__VA_ARGS__)

#define hv_cpu_log(level, fmt, ...) \
    pr_##level("hv[cpu%u]: " fmt, cpu->cpu_id, ##__VA_ARGS__)

/*
*   bit manipulation macros
*/
#define HV_BIT_TEST(val, bit)    (((val) >> (bit)) & 1)
#define HV_BIT_SET(val, bit)     ((val) | (1ULL << (bit)))
#define HV_BIT_CLEAR(val, bit)   ((val) & ~(1ULL << (bit)))

/*
*   cpuid magic leaf for hypervisor detection
*/
#define HV_CPUID_MAGIC_LEAF      0x4A4D5651  // "HV\0\0"
#define HV_CPUID_MAGIC_SUBLEAF   0

/*
*   physical address mask (48-bit physical address space on current Intel)
*/
#define HV_PHYS_ADDR_MASK        ((1ULL << 48) - 1)

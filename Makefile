# Linux Intel VT-x Type-2 Hypervisor

obj-m += hv.o
hv-y += src/entry.o src/vmm.o src/cpu.o src/vmx.o src/vmcs.o src/ept.o src/exit.o src/arch.o src/vmx_asm.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Release build by default (no debug logging for performance)
ccflags-y := -I$(src)/include -Wno-declaration-after-statement -O2

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

debug:
	$(MAKE) -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS="-DDEBUG -g -O0"

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	sudo insmod hv.ko

uninstall:
	sudo rmmod hv

reload: uninstall install

.PHONY: all clean install uninstall reload debug

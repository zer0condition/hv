# Linux Intel VT-x Type-2 Hypervisor

obj-m += hv.o
hv-y += src/entry.o src/vmm.o src/cpu.o src/vmx.o src/vmcs.o src/ept.o src/exit.o src/arch.o src/vmx_asm.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Common flags
ccflags-y := -I$(src)/include -Wno-declaration-after-statement

# Debug build
debug: ccflags-y += -DDEBUG -g -O0
debug: all

# Release build
release: ccflags-y += -O2 -DNDEBUG
release: all

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	sudo insmod hv.ko

uninstall:
	sudo rmmod hv

reload: uninstall install

.PHONY: all clean install uninstall reload debug release

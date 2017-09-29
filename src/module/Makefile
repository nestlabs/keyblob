#
#    Description:
#      This file is the makefile for building KeyBlob kernel module.
#

obj-m += keyblob.o

ccflags-y += -I$(src)/../common

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

ifeq ($(CONFIG_ALLOW_NONSECURE_KEYBLOB),y)
KBUILD_CFLAGS += -DALLOW_NONSECURE_SECURITY_STATE
endif

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $(if $(VERBOSE),V=1) modules

modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $(if $(VERBOSE),V=1) modules_install

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $(if $(VERBOSE),V=1) clean

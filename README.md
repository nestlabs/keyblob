# KeyBlob Linux Kernel Module

This is a Linux kernel module for producing keys wrapped with Freescale's CAAM
Blob protocol and injecting them into kernel keyring service.

This is not an official Google product.

## Prerequisites

* Freescale's Linux kernel that includes CAAM driver. See
  https://github.com/Freescale/linux-fslc/
* Linux kernel configured with keyring (CONFIG_KEYS) enabled.
* In the Linux distribution, create a directory 'caam' in the include directory
  and symbolic links to intern.h, sm.h and snvsregs.h from drivers/crypto/caam/.

      $ cd <path-to>/linux-fslc
      $ mkdir include/caam
      $ cd include/caam
      $ ln -s ../../drivers/crypto/caam/intern.h .
      $ ln -s ../../drivers/crypto/caam/sm.h .
      $ ln -s ../../drivers/crypto/caam/snvsregs.h .

## Compiling

If compiling the module for the host machine:

    $ make -C src/module

If compiling for another host, specify KERNELDIR, e.g.:

    $ make -C src/module KERNELDIR=<path-to>/linux-fslc


# Comment/uncomment the following line to enable/disable debugging
DEBUG = y


ifeq ($(DEBUG),y)
  DEBFLAGS = -O -g -DUCALL_DEBUG # "-O" is needed to expand inlines
else
  DEBFLAGS = -O2
endif

EXTRA_CFLAGS += $(DEBFLAGS) -I$(LDDINC)

TARGET = ucall

ifneq ($(KERNELRELEASE),)

ucall-objs := main.o

obj-m	:= ucall.o

else

#KERNELDIR ?= /lib/modules/$(shell uname -r)/build
KERNELDIR ?= ${ANDROID_PRODUCT_OUT}/obj/KERNEL
PWD       := $(shell pwd)
KERNELRELEASE :=$(shell grep  "Linux/arm" ${KERNELDIR}/include/generated/autoconf.h|grep -oP "\d.\d\d.\d+")
EXTRA_CFLAGS += -DKERNEL310

modules:
	$(info ${KERNELRELEASE})
	$(MAKE) -C $(KERNELDIR) M=$(PWD) LDDINC=$(PWD) KBUILD_EXTRA_SYMBOLS=${KERNELDIR}/Module.symvers modules ARCH=arm CROSS_COMPILE=arm-eabi-
	#$(MAKE) -C $(KERNELDIR) M=$(PWD) LDDINC=$(PWD) modules

endif

install:
	-adb shell rmmod $(TARGET)
	adb push $(TARGET).ko /data/
	adb shell insmod /data/$(TARGET).ko
clean:
	#rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions
	$(MAKE) -C $(KERNELDIR) M=$(PWD) LDDINC=$(PWD) clean ARCH=arm CROSS_COMPILE=arm-eabi-
	-adb shell rmmod $(TARGET)


depend .depend dep:
	$(CC) $(EXTRA_CFLAGS) -M *.c > .depend

ifeq (.depend,$(wildcard .depend))
include .depend
endif

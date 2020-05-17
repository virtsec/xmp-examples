KERNEL	:= /lib/modules/$(shell uname -r)/build/

obj-m	:= parrot.o

all: clean
	make -C $(KERNEL) M=$(PWD) modules

clean:
	make -C $(KERNEL) M=$(PWD) clean

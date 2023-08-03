CC = arm-linux-gnueabihf-gcc

all: vul32.o vul64.o

vul32.o: vul.c
	arm-linux-gnueabihf-gcc  $< -o $@ -fno-PIC -fno-stack-protector -g -c

vul64.o: vul.c
	aarch64-linux-gnu-gcc $< -o $@ -fno-PIC -fno-stack-protector -g -c

.PHONY:
clean:
	-rm -f *.o

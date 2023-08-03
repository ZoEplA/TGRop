CC = mipsel-linux-gnu-gcc

all: vul32.o

vul32.o: vul.c
	mipsel-linux-gnu-gcc $< -o $@ -fno-PIC -fno-stack-protector -g -c

vul64.o: vul.c
	mips64-linux-gnuabi64-gcc $< -o $@ -fno-PIC -fno-stack-protector -g -c

.PHONY:
clean:
	-rm -f *.o

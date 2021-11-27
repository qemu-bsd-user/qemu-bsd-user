ARCHS=armv7 amd64 aarch64 i386 powerpc powerpc64 riscv64

.for a in ${ARCHS}
all: h.${a}
h.${a}: h.${a}.S
	cc -target ${a}-unknown-freebsd14.0 -o h.${a} h.${a}.S -nostdlib -Wl,-e -Wl,qemu_start -static
CLEANFILES+=h.${a}
BINS+=h.${a}
.endfor

pkg:	${BINS}
	tar cf hello-bsd.tar ${BINS}
	xz -9 hello-bsd.tar

clean:
	rm -f ${CLEANFILES}

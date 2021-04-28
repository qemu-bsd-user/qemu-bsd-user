bsd_user_ss.add(files(
  'bsd-ioctl.c',
  'bsd-mem.c',
  'bsd-misc.c',
  'bsd-proc.c',
  'bsd-socket.c',
  'bsdload.c',
  'elfload.c',
  'main.c',
  'mmap.c',
  'safe-syscall.S',
  'signal.c',
  'strace.c',
  'syscall.c',
  'uaccess.c',
))

subdir(targetos)
elf = cc.find_library('elf', required: true)
procstat = cc.find_library('procstat', required: true)
bsd_user_ss.add(elf, procstat)

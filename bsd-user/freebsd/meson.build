bsd_syscall_nr = custom_target('bsd-syscall-h',
    output: '@BASENAME@_nr.h',
    input: ['/usr/include/sys/syscall.h'],
    command: [sh, meson.current_source_dir() / 'scripts/syscallhdr.sh', '@INPUT@', '@OUTPUT@', 'FREEBSD'])

# Generate the systruss.h-like file
gen_systruss_h = find_program(meson.current_source_dir() / 'scripts/systruss.lua')
systruss = custom_target(
    'systruss-gen',
    output: ['systruss.h'],
    input: [ freebsd_syscall_dir / '../../kern/syscalls.master'],
    env: flua_env,
    command: [gen_systruss_h, '@INPUT@', '@OUTPUT@'])

# Generate the special system call prototypes, etc file
gen_special_syscall_h = find_program(meson.current_source_dir() / 'scripts/special_syscall_h.lua')
special_syscall_h = custom_target(
    'special-syscall-h-gen',
    output: ['special-syscall.h'],
    input: [meson.current_source_dir() / 'scripts/syscall-meta.json'],
    env: flua_env,
    command: [gen_special_syscall_h, '@INPUT@', '@OUTPUT@'])

bsd_user_ss.add(files(
  'os-extattr.c',
  'os-proc.c',
  'os-socket.c',
  'os-stat.c',
  'os-proc.c',
  'os-sys.c',
  'os-syscall.c',
  'os-thread.c',
  'os-time.c',
  'truss.c'),
  bsd_syscall_nr,
  systruss,
  special_syscall_h
)

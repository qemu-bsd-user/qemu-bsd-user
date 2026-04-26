syscalls_master = freebsd_syscall_dir / '../../kern/syscalls.master'

bsd_syscall_nr = custom_target('bsd-syscall-h',
    output: '@BASENAME@_nr.h',
    input: ['/usr/include/sys/syscall.h'],
    command: [sh, meson.current_source_dir() / 'scripts/syscallhdr.sh', '@INPUT@', '@OUTPUT@', 'FREEBSD'])

# Generate the systruss.h-like file
gen_systruss_h = find_program(meson.current_source_dir() / 'scripts/systruss.lua')
systruss = custom_target(
    'systruss-gen',
    output: ['systruss.h'],
    input: [ syscalls_master ],
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

# Generate a target_sysproto.h file with all the target_$SYSCALL_args structs
gen_sysproto_h = find_program(meson.current_source_dir() / 'scripts/sysproto_h.lua')
sysproto_h = custom_target(
    'sysproto-gen',
    output: ['os-sysproto.h'],
    input: [ syscalls_master ],
    env: flua_env,
    command: [gen_sysproto_h, '@INPUT@', '@OUTPUT@'])

# Generate the system calls
gen_syscalls = find_program(meson.current_source_dir() / 'scripts/gen_qemu_syscalls.lua')
syscalls = custom_target(
    'syscall-gen',
    output: ['@BASENAME@.c'],
    input: [ syscalls_master ],
    env: flua_env,
    command: [gen_syscalls, '@INPUT@', '@OUTPUT@'])

bsd_user_ss.add(files(
  'stubs.c',
  'sys_custom.c',
  'truss.c'),
  bsd_syscall_nr,
  systruss,
  special_syscall_h,
  sysproto_h,
  syscalls
)

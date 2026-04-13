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
  'truss.c'
))

bsd_syscall_nr = generator(sh,
			   arguments: [ meson.current_source_dir() / 'syscallhdr.sh', '@INPUT@', '@OUTPUT@', '@EXTRA_ARGS@'],
			   output: '@BASENAME@_nr.h')

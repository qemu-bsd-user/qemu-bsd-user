
BSD USER README
===============

The bsd-user fork of QEMU. Documentation can be found hosted online at
`<https://www.qemu.org/documentation/>`_ for the upstream project.

bsd-user fixes the BSD user-mode emulation for the QEMU project. There are a
number of changes that need to be upstreamed, however.

Getting Started
===============

To get started, create a FreeBSD VM with a ZFS root filesystem. This is detailed
fairly well in `<https://docs.freebsd.org/en/books/handbook/bsdinstall/>`_ so
I'll omit the details here. Make sure that the ZFS pool is named zpool. It will
make your life much easier. This is the default. You should install FreeBSD 13.2
release.

Next, once you've installed your system, set a root password and create an
account. It's better to work not as root, but you will need root from time to
time. I recommend that you install (# are commands as root, % are commands as user)

.. code-block:: shell

  # pkg bootstrap
  # pkg install git pkgconf bzip2 ninja bash gmake gsed gettext gnutls jpeg-turbo png sdl2 libxkbcommon mesa-libs zstd libslirp sndio python libproxy meson pixman bison
  # pkg install qemu-user-static
  # pkg install poudriere
  # rehash
  # sysrc qemu_user_static_enable=YES
  # service qemu_user_static start

This will install all the prerequisites to successfully build. Except the last
one, that will install FreeBSD's qemu-user-static package, which will setup
things so you can directly run the armv7 or other foreign binaries. More on what
you'll do with this later. Likewise with poudriere. It's not needed to build
bsd-user, but is used for testing it.

Next, you'll need to clone this repo. I like to use the directory 'bsd-user'
for the fork and 'qemu' for the upstream project. The rest 

.. code-block:: shell

  % mkdir git
  % cd git
  % git clone -b blitz  https://github.com/qemu-bsd-user/qemu-bsd-user.git bsd-user
  % git clone git@gitlab.com:qemu-project/qemu.git qemu
  % cd bsd-user
  % mkdir 00-bsd-user
  % cd 00-bsd-user
  % ../configure --disable-system --static
  % gmake
  % cd ../../qemu
  % mkdir 00-qemu
  % cd 00-qemu
  % ../configure --disable-system --static
  % gmake

The above takes a little while to build. I disable the qemu-system-* binaries
since they take a longer time to build and aren't relevant to bsd-user. Other
than the args to configure, this is the standard way you build qemu.

Setting up Pouduriere
====================

Poudriere is the standard way that FreeBSD builds package. It has a great many
feaetures one won't use when developing bsd-user, unless you are using it to
build package. There's a number of tutorials on poduriere online, so I won't
repeat them here. I will show how to build a jail, however, which is fairly
fast with pkgbase.

.. code-block:: shell

 # poudriere -e ~/FreeBSD/etc jail -c -j 15armv7 -a armv7 -m pkgbase -p local -v 15 -X

Note about packages
===================
These instructions have people install qemu-user-static so that the binmiscctl
commands are executed at boot. /usr/local/bin/qemu-$ARCH-user is copied over
(see below), so after installing it, I usually do the following:

.. code-block:: shell

  # cd /usr/local/bin
  # mv qemu-arm-static qemu-arm-static.3.1
  # ln -s qemu-arm-static.3.1 qemu-arm-static

so that the binary is a symlink. Later, when I want to test, I copy my qemu-arm
that I build (more on that later) into either
/usr/local/bin/qemu-arm-static.bsd-user or /usr/local/bin/qemu-arm-static.up
so I can do A/B testing more eaily by moving the symbolic link.

Starting the jail
=================

The following starts the jail and then shows how to jexec into it to get a shell
prompt:

.. code-block:: shell

  # poudriere jail -s -j 132armv7
  # jls
  <listing of the jails to get the jail number>
  # jexec X
  # 

This will test to make sure that you have qmeu-user-static installed
correctly. You should get a # prompt from our (somewhat old based on 3.1)
qemu-arm-static binary.

When Poudriere starts a jail, it copies a 'clean' snapshot so that any changes
to the jail aren't recorded. It also copies /usr/local/bin/qemu-$ARCH-user into
that tree. The $ARCH in this case is arm for armv7 binaries. This is why I
usually create a symlink: so I can move it as I test. One can also copy it into
the running jail directory, though I try not to do that since I like restarting
my jails when I change tests. One can also have multiple jails one leaves
running and just copy bsd-user or upstream binaries in as needed. Finally, if
you are just going to test qemu-arm for one binary, you can copy it directly
into the jail w/o updating the symlink so that all the other command work. We
recommend --static so that one can do this w/o needing to copy libraries over as
well.

Building Test Binaries Without The Jail
=======================================

Since you've created the jail, you have a 'sysroot' that you can use to build
binaries. Let's say you want to build hello-armv7 from hello.c.

.. code-block:: shell

 % cc -target freebsd-armv7 --sysroot /vidpool/qemu/jails/jails/131armv7 -o hello-armv7


Will do the trick.

Running Without The Jail
========================

Sometimes it is desirable to run qemu to test without running in the jail. You
will still need to create the jail, as outlined above, but you don't need to
start it. You'll need to get the 'root' of the jail for this step. Use
`poudriere jail -l` to get a list of all your jails, and to find the root

.. code-block:: shell

 # joudriere jail -l
 JAILNAME        VERSION                              ARCH      METHOD  TIMESTAMP           PATH
 131armv7        13.2-RC3 1302001 d9bf9d732           arm.armv7 git+ssh 2023-03-18 13:54:23 /vidpool/qemu/jails/jails/131armv7
 #

In this case, it's the PATH column.

You'll can test binaries either inside or outside the jail. You'll run qemu-user
directly to do this test. Let's say you have a 'hello world' binary that you're
trying to debug. For example, if you're debugging an arm binary using the above
jail:

.. code-block:: shell

 % cd qemu/00-qemu
 % <build-here>
 % qemu-arm -L /vidpool/qemu/jails/jails/131armv7 hello-arm

whill run it looking in the jail's root directory for all the dynamic parts of
the binary (ld-elf.so, libc.so, etc).

Upstreaming
===========
When upstreaming, we try to attribute commits.

 % git clone https://github.com/qemu-bsd-user/qemu
 % cd qemu
 % git remote add seanbruno https://github.com/seanbruno/qemu-bsd-user.git
 # The following makes git blame work because of my copying
 % git replace --graft e31b768202c seanbruno/bsd-user

makes seanbruno/bsd-user the parent of the hash e31b768202c which makes
`git blame` work better.

Podman
======

Creating the container
--------------------
Creating the container, note the dns stuff is due to weird firewalls
 # podman build --dns=10.0.0.5 --dns-search=bsdimp.com -f Containerfile.freebsd-15 -t qemu-15 .

Building with podman
--------------------

The first two commands are needed to bootstrap, once we have that, then the
third rebuilds.

.. codeblock:: shell
 # mkdir 16-freebsd
 # podman run --rm --dns=10.0.0.5 --dns-search=bsdimp.com -v ~/git/qemu-claude-bsd-user:/home/qemu qemu-16 sh -c "cd /home/qemu/16-freebsd; ../configure --disable-system --static"
 # podman run --rm --dns=10.0.0.5 --dns-search=bsdimp.com -v ~/git/qemu-claude-bsd-user:/home/qemu qemu-16 sh -c "cd /home/qemu/16-freebsd; gmake -j 100"

--rm is needed because we don't put anything new into the image and don't need
the container to stick around.

Testing with a container
-------------
 % sudo podman run -it --rm --arch=arm64 -v /usr/local/bin/qemu-aarch64-static:/usr/local/bin/qemu-aarch64-static ghcr.io/freebsd/freebsd-runtime:15.1.beta2 uname -a`

Unimplemented Syscalls
======================

The following FreeBSD syscalls (from ``/usr/include/sys/syscall.h``) do not have
a corresponding ``case TARGET_FREEBSD_NR_xxxx:`` in the main switch statement in
``bsd-user/freebsd/os-syscall.c``. Some of these are kernel-only, obsolete, or
not meaningful in a user-mode emulation context.

Compatibility/versioned syscalls
--------------------------------

- ``SYS_freebsd14_getgroups`` (79)
- ``SYS_freebsd14_setgroups`` (80)
- ``SYS_freebsd7___semctl`` (220)
- ``SYS_freebsd7_msgctl`` (224)
- ``SYS_freebsd7_shmctl`` (229)
- ``SYS_freebsd10__umtx_lock`` (434)
- ``SYS_freebsd10__umtx_unlock`` (435)

AIO (asynchronous I/O)
-----------------------

- ``SYS_aio_read`` (255)
- ``SYS_aio_write`` (256)
- ``SYS_lio_listio`` (257)
- ``SYS_aio_return`` (314)
- ``SYS_aio_suspend`` (315)
- ``SYS_aio_cancel`` (316)
- ``SYS_aio_error`` (317)
- ``SYS_aio_waitcomplete`` (359)
- ``SYS_aio_fsync`` (465)
- ``SYS_aio_mlock`` (543)
- ``SYS_aio_writev`` (578)
- ``SYS_aio_readv`` (579)

Audit
-----

- ``SYS_audit`` (445)
- ``SYS_auditon`` (446)
- ``SYS_getauid`` (447)
- ``SYS_setauid`` (448)
- ``SYS_getaudit`` (449)
- ``SYS_setaudit`` (450)
- ``SYS_getaudit_addr`` (451)
- ``SYS_setaudit_addr`` (452)
- ``SYS_auditctl`` (453)

MAC (Mandatory Access Control)
------------------------------

- ``SYS___mac_get_proc`` (384)
- ``SYS___mac_set_proc`` (385)
- ``SYS___mac_get_fd`` (386)
- ``SYS___mac_get_file`` (387)
- ``SYS___mac_set_fd`` (388)
- ``SYS___mac_set_file`` (389)
- ``SYS_mac_syscall`` (394)
- ``SYS___mac_get_pid`` (409)
- ``SYS___mac_get_link`` (410)
- ``SYS___mac_set_link`` (411)
- ``SYS___mac_execve`` (415)

Jail
----

- ``SYS_jail`` (338)
- ``SYS_jail_attach`` (436)
- ``SYS_jail_get`` (506)
- ``SYS_jail_set`` (507)
- ``SYS_jail_remove`` (508)
- ``SYS_jail_attach_jd`` (597)
- ``SYS_jail_remove_jd`` (598)

POSIX kernel semaphores (ksem)
------------------------------

- ``SYS_ksem_close`` (400)
- ``SYS_ksem_post`` (401)
- ``SYS_ksem_wait`` (402)
- ``SYS_ksem_trywait`` (403)
- ``SYS_ksem_init`` (404)
- ``SYS_ksem_open`` (405)
- ``SYS_ksem_unlink`` (406)
- ``SYS_ksem_getvalue`` (407)
- ``SYS_ksem_destroy`` (408)
- ``SYS_ksem_timedwait`` (441)

POSIX message queues (kmq)
--------------------------

- ``SYS_kmq_open`` (457)
- ``SYS_kmq_setattr`` (458)
- ``SYS_kmq_timedreceive`` (459)
- ``SYS_kmq_timedsend`` (460)
- ``SYS_kmq_notify`` (461)
- ``SYS_kmq_unlink`` (462)

SCTP
----

- ``SYS_sctp_peeloff`` (471)
- ``SYS_sctp_generic_sendmsg`` (472)
- ``SYS_sctp_generic_sendmsg_iov`` (473)
- ``SYS_sctp_generic_recvmsg`` (474)

Capsicum (read-only queries)
----------------------------

Note: The write-side Capsicum syscalls (``cap_enter``, ``cap_rights_limit``,
``cap_ioctls_limit``, ``cap_fcntls_limit``) are handled (returning ``-ENOSYS``).
These read-only query counterparts are completely missing.

- ``SYS___cap_rights_get`` (515)
- ``SYS_cap_getmode`` (517)
- ``SYS_cap_ioctls_get`` (535)
- ``SYS_cap_fcntls_get`` (537)

RCTL (resource control)
-----------------------

- ``SYS_rctl_get_racct`` (525)
- ``SYS_rctl_get_rules`` (526)
- ``SYS_rctl_get_limits`` (527)
- ``SYS_rctl_add_rule`` (528)
- ``SYS_rctl_remove_rule`` (529)

Clock/timer
-----------

- ``SYS_ffclock_getcounter`` (241)
- ``SYS_ffclock_setestimate`` (242)
- ``SYS_ffclock_getestimate`` (243)
- ``SYS_ktimer_getoverrun`` (239)
- ``SYS_timerfd_create`` (585)
- ``SYS_timerfd_gettime`` (586)
- ``SYS_timerfd_settime`` (587)

NFS/RPC kernel
--------------

- ``SYS_nlm_syscall`` (154)
- ``SYS_nfssvc`` (155)
- ``SYS_rpctls_syscall`` (576)

Network filesystem
------------------

- ``SYS_nnpfs_syscall`` (339)
- ``SYS_afs3_syscall`` (377)

File handle
-----------

- ``SYS_getfhat`` (564)
- ``SYS_fhlink`` (565)
- ``SYS_fhlinkat`` (566)
- ``SYS_fhreadlink`` (567)

File/VFS
--------

- ``SYS_sendfile`` (393)
- ``SYS_fspacectl`` (580)
- ``SYS_funlinkat`` (568)
- ``SYS_posix_fadvise`` (531)

Process/thread
--------------

- ``SYS_thr_create`` (430)
- ``SYS_yield`` (321)
- ``SYS_rtprio`` (166)
- ``SYS_abort2`` (463)
- ``SYS_pdrfork`` (600)
- ``SYS_pdwait`` (601)

Module
------

- ``SYS_modnext`` (300)
- ``SYS_modstat`` (301)

Miscellaneous
-------------

- ``SYS_semsys`` (169)
- ``SYS_msgsys`` (170)
- ``SYS_shmsys`` (171)
- ``SYS_cpuset_getdomain`` (561)
- ``SYS_cpuset_setdomain`` (562)
- ``SYS_sched_getcpu`` (581)
- ``SYS_kqueuex`` (583)
- ``SYS_membarrier`` (584)
- ``SYS_kcmp`` (588)
- ``SYS_getrlimitusage`` (589)
- ``SYS_fchroot`` (590)
- ``SYS_setcred`` (591)
- ``SYS_exterrctl`` (592)
- ``SYS_inotify_add_watch_at`` (593)
- ``SYS_inotify_rm_watch`` (594)
- ``SYS_kexec_load`` (599)
- ``SYS_renameat2`` (602)

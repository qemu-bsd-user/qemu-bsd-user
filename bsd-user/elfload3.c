/*
 *  ELF loading code
 *
 *  Copyright (c) 2013 Stacey D. Son
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"

#include "qemu.h"
#include "disas/disas.h"
#include "qemu/path.h"

static abi_ulong target_auxents;   /* Where the AUX entries are in target */
static size_t target_auxents_sz;   /* Size of AUX entries including AT_NULL */

#include "target_arch_reg.h"
#include "target_os_elf.h"
#include "target_os_stack.h"
#include "target_os_thread.h"
#include "target_os_user.h"

abi_ulong target_stksiz;
abi_ulong target_stkbas;

abi_ulong mmap_min_addr;

static int elf_core_dump(int signr, CPUArchState *env);
static int load_elf_sections(const struct elfhdr *hdr, struct elf_phdr *phdr,
    int fd, abi_ulong rbase, abi_ulong *baddrp);

// XXX
void probe_guest_base(const char *image_name, abi_ulong guest_loaddr,
                      abi_ulong guest_hiaddr);

static inline void memcpy_fromfs(void *to, const void *from, unsigned long n)
{
    memcpy(to, from, n);
}

#ifdef BSWAP_NEEDED
static void bswap_ehdr(struct elfhdr *ehdr)
{
    bswap16s(&ehdr->e_type);            /* Object file type */
    bswap16s(&ehdr->e_machine);         /* Architecture */
    bswap32s(&ehdr->e_version);         /* Object file version */
    bswaptls(&ehdr->e_entry);           /* Entry point virtual address */
    bswaptls(&ehdr->e_phoff);           /* Program header table file offset */
    bswaptls(&ehdr->e_shoff);           /* Section header table file offset */
    bswap32s(&ehdr->e_flags);           /* Processor-specific flags */
    bswap16s(&ehdr->e_ehsize);          /* ELF header size in bytes */
    bswap16s(&ehdr->e_phentsize);       /* Program header table entry size */
    bswap16s(&ehdr->e_phnum);           /* Program header table entry count */
    bswap16s(&ehdr->e_shentsize);       /* Section header table entry size */
    bswap16s(&ehdr->e_shnum);           /* Section header table entry count */
    bswap16s(&ehdr->e_shstrndx);        /* Section header string table index */
}

static void bswap_phdr(struct elf_phdr *phdr, int phnum)
{
    int i;

    for (i = 0; i < phnum; i++, phdr++) {
        bswap32s(&phdr->p_type);        /* Segment type */
        bswap32s(&phdr->p_flags);       /* Segment flags */
        bswaptls(&phdr->p_offset);      /* Segment file offset */
        bswaptls(&phdr->p_vaddr);       /* Segment virtual address */
        bswaptls(&phdr->p_paddr);       /* Segment physical address */
        bswaptls(&phdr->p_filesz);      /* Segment size in file */
        bswaptls(&phdr->p_memsz);       /* Segment size in memory */
        bswaptls(&phdr->p_align);       /* Segment alignment */
    }
}

static void bswap_shdr(struct elf_shdr *shdr, int shnum)
{
    int i;

    for (i = 0; i < shnum; i++, shdr++) {
        bswap32s(&shdr->sh_name);
        bswap32s(&shdr->sh_type);
        bswaptls(&shdr->sh_flags);
        bswaptls(&shdr->sh_addr);
        bswaptls(&shdr->sh_offset);
        bswaptls(&shdr->sh_size);
        bswap32s(&shdr->sh_link);
        bswap32s(&shdr->sh_info);
        bswaptls(&shdr->sh_addralign);
        bswaptls(&shdr->sh_entsize);
    }
}

static void bswap_sym(struct elf_sym *sym)
{
    bswap32s(&sym->st_name);
    bswaptls(&sym->st_value);
    bswaptls(&sym->st_size);
    bswap16s(&sym->st_shndx);
}

static void bswap_note(struct elf_note *en)
{
    bswap32s(&en->n_namesz);
    bswap32s(&en->n_descsz);
    bswap32s(&en->n_type);
}

#else /* ! BSWAP_NEEDED */

static void bswap_ehdr(struct elfhdr *ehdr) { }
static void bswap_phdr(struct elf_phdr *phdr, int phnum) { }
static void bswap_shdr(struct elf_shdr *shdr, int shnum) { }
static void bswap_sym(struct elf_sym *sym) { }
static void bswap_note(struct elf_note *en) { }

#endif /* ! BSWAP_NEEDED */

#include "elfcore.c"

/*
 * 'copy_elf_strings()' copies argument/envelope strings from user
 * memory to free pages in kernel mem. These are in a format ready
 * to be put directly into the top of new user memory.
 *
 */
static abi_ulong copy_elf_strings(int argc, char **argv, void **page,
                                  abi_ulong p)
{
    char *tmp, *tmp1, *pag = NULL;
    int len, offset = 0;

    if (!p) {
        return 0;       /* bullet-proofing */
    }
    while (argc-- > 0) {
        tmp = argv[argc];
        if (!tmp) {
            fprintf(stderr, "VFS: argc is wrong");
            exit(-1);
        }
        tmp1 = tmp;
        while (*tmp++) {
            continue;
        }
        len = tmp - tmp1;
        if (p < len) {  /* this shouldn't happen - 128kB */
            return 0;
        }
        while (len) {
            --p; --tmp; --len;
            if (--offset < 0) {
                offset = p % TARGET_PAGE_SIZE;
                pag = (char *)page[p / TARGET_PAGE_SIZE];
                if (!pag) {
                    pag = g_try_malloc0(TARGET_PAGE_SIZE);
                    page[p / TARGET_PAGE_SIZE] = pag;
                    if (!pag) {
                        return 0;
                    }
                }
            }
            if (len == 0 || offset == 0) {
                *(pag + offset) = *tmp;
            } else {
              int bytes_to_copy = (len > offset) ? offset : len;
              tmp -= bytes_to_copy;
              p -= bytes_to_copy;
              offset -= bytes_to_copy;
              len -= bytes_to_copy;
              memcpy_fromfs(pag + offset, tmp, bytes_to_copy + 1);
            }
        }
    }
    return p;
}

static void setup_arg_pages(struct bsd_binprm *bprm, struct image_info *info,
                            abi_ulong *stackp, abi_ulong *stringp)
{
    abi_ulong stack_base, size;
    abi_long addr;

    /*
     * Create enough stack to hold everything.  If we don't use it for args,
     * we'll use it for something else...
     */
    size = target_dflssiz;
    stack_base = TARGET_USRSTACK - size;
    addr = target_mmap(stack_base , size + qemu_host_page_size,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (addr == -1) {
        perror("stk mmap");
        exit(-1);
    }
    /* we reserve one extra page at the top of the stack as guard */
    target_mprotect(addr + size, qemu_host_page_size, PROT_NONE);

    target_stksiz = size;
    target_stkbas = addr;

    if (setup_initial_stack(bprm, stackp, stringp) != 0) {
        perror("stk setup");
        exit(-1);
    }
}

static void set_brk(abi_ulong start, abi_ulong end)
{
    /* page-align the start and end addresses... */
    start = HOST_PAGE_ALIGN(start);
    end = HOST_PAGE_ALIGN(end);
    if (end <= start) {
        return;
    }
    if (target_mmap(start, end - start, PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANON, -1, 0) == -1) {
        perror("cannot mmap brk");
        exit(-1);
    }
}


/*
 * We need to explicitly zero any fractional pages after the data
 * section (i.e. bss).  This would contain the junk from the file that
 * should not be in memory.
 */
static void padzero(abi_ulong elf_bss, abi_ulong last_bss)
{
    abi_ulong nbyte;

    if (elf_bss >= last_bss) {
        return;
    }

    /*
     * XXX: this is really a hack : if the real host page size is
     * smaller than the target page size, some pages after the end
     * of the file may not be mapped. A better fix would be to
     * patch target_mmap(), but it is more complicated as the file
     * size must be known.
     */
    if (qemu_real_host_page_size < qemu_host_page_size) {
        abi_ulong end_addr, end_addr1;
        end_addr1 = REAL_HOST_PAGE_ALIGN(elf_bss);
        end_addr = HOST_PAGE_ALIGN(elf_bss);
        if (end_addr1 < end_addr) {
            mmap((void *)g2h_untagged(end_addr1), end_addr - end_addr1,
                 PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_FIXED | MAP_PRIVATE | MAP_ANON, -1, 0);
        }
    }

    nbyte = elf_bss & (qemu_host_page_size - 1);
    if (nbyte) {
        nbyte = qemu_host_page_size - nbyte;
        do {
            /* FIXME - what to do if put_user() fails? */
            put_user_u8(0, elf_bss);
            elf_bss++;
        } while (--nbyte);
    }
}

static abi_ulong load_elf_interp(struct elfhdr *interp_elf_ex,
                                 int interpreter_fd,
                                 abi_ulong *interp_load_addr)
{
    struct elf_phdr *elf_phdata  =  NULL;
    abi_ulong rbase;
    int retval;
    abi_ulong baddr, error;

    error = 0;

    bswap_ehdr(interp_elf_ex);
    /* First of all, some simple consistency checks */
    if ((interp_elf_ex->e_type != ET_EXEC && interp_elf_ex->e_type != ET_DYN) ||
          !elf_check_arch(interp_elf_ex->e_machine)) {
        return ~((abi_ulong)0UL);
    }


    /* Now read in all of the header information */
    if (sizeof(struct elf_phdr) * interp_elf_ex->e_phnum > TARGET_PAGE_SIZE) {
        return ~(abi_ulong)0UL;
    }

    elf_phdata =  (struct elf_phdr *) malloc(sizeof(struct elf_phdr) *
            interp_elf_ex->e_phnum);

    if (!elf_phdata) {
        return ~((abi_ulong)0UL);
    }

    /*
     * If the size of this structure has changed, then punt, since
     * we will be doing the wrong thing.
     */
    if (interp_elf_ex->e_phentsize != sizeof(struct elf_phdr)) {
        free(elf_phdata);
        return ~((abi_ulong)0UL);
    }

    retval = lseek(interpreter_fd, interp_elf_ex->e_phoff, SEEK_SET);
    if (retval >= 0) {
        retval = read(interpreter_fd, (char *) elf_phdata,
                sizeof(struct elf_phdr) * interp_elf_ex->e_phnum);
    }
    if (retval < 0) {
        perror("load_elf_interp");
        exit(-1);
        free(elf_phdata);
        return retval;
    }
    bswap_phdr(elf_phdata, interp_elf_ex->e_phnum);

    rbase = 0;
    if (interp_elf_ex->e_type == ET_DYN) {
        /*
         * In order to avoid hardcoding the interpreter load
         * address in qemu, we allocate a big enough memory zone.
         */
        rbase = target_mmap(0, INTERP_MAP_SIZE, PROT_NONE,
                MAP_PRIVATE | MAP_ANON, -1, 0);
        if (rbase == -1) {
            perror("mmap");
            exit(-1);
        }
    }

    error = load_elf_sections(interp_elf_ex, elf_phdata, interpreter_fd, rbase,
        &baddr);
    if (error != 0) {
        perror("load_elf_sections");
        exit(-1);
    }

    /* Now use mmap to map the library into memory. */
    close(interpreter_fd);
    free(elf_phdata);

    *interp_load_addr = baddr;
    return ((abi_ulong) interp_elf_ex->e_entry) + rbase;
}

static int symfind(const void *s0, const void *s1)
{
    target_ulong addr = *(target_ulong *)s0;
    struct elf_sym *sym = (struct elf_sym *)s1;
    int result = 0;
    if (addr < sym->st_value) {
        result = -1;
    } else if (addr >= sym->st_value + sym->st_size) {
        result = 1;
    }
    return result;
}

static const char *lookup_symbolxx(struct syminfo *s, target_ulong orig_addr)
{
#if ELF_CLASS == ELFCLASS32
    struct elf_sym *syms = s->disas_symtab.elf32;
#else
    struct elf_sym *syms = s->disas_symtab.elf64;
#endif

    /* binary search */
    struct elf_sym *sym;

    sym = bsearch(&orig_addr, syms, s->disas_num_syms, sizeof(*syms), symfind);
    if (sym != NULL) {
        return s->disas_strtab + sym->st_name;
    }

    return "";
}

/* FIXME: This should use elf_ops.h  */
static int symcmp(const void *s0, const void *s1)
{
    struct elf_sym *sym0 = (struct elf_sym *)s0;
    struct elf_sym *sym1 = (struct elf_sym *)s1;
    return (sym0->st_value < sym1->st_value) ? -1 :
        ((sym0->st_value > sym1->st_value) ? 1 : 0);
}

/* Best attempt to load symbols from this ELF object. */
static void load_symbols(struct elfhdr *hdr, int fd)
{
    unsigned int i, nsyms;
    struct elf_shdr sechdr, symtab, strtab;
    char *strings;
    struct syminfo *s;
    struct elf_sym *syms, *new_syms;

    lseek(fd, hdr->e_shoff, SEEK_SET);
    for (i = 0; i < hdr->e_shnum; i++) {
        if (read(fd, &sechdr, sizeof(sechdr)) != sizeof(sechdr)) {
            return;
        }
        bswap_shdr(&sechdr, 1);
        if (sechdr.sh_type == SHT_SYMTAB) {
            symtab = sechdr;
            lseek(fd, hdr->e_shoff + sizeof(sechdr) * sechdr.sh_link,
                  SEEK_SET);
            if (read(fd, &strtab, sizeof(strtab)) != sizeof(strtab)) {
                return;
            }
            bswap_shdr(&strtab, 1);
            goto found;
        }
    }
    return; /* Shouldn't happen... */

found:
    /* Now know where the strtab and symtab are.  Snarf them. */
    s = malloc(sizeof(*s));
    syms = malloc(symtab.sh_size);
    if (!syms) {
        free(s);
        return;
    }
    s->disas_strtab = strings = malloc(strtab.sh_size);
    if (!s->disas_strtab) {
        free(s);
        free(syms);
        return;
    }

    lseek(fd, symtab.sh_offset, SEEK_SET);
    if (read(fd, syms, symtab.sh_size) != symtab.sh_size) {
        free(s);
        free(syms);
        free(strings);
        return;
    }

    nsyms = symtab.sh_size / sizeof(struct elf_sym);

    i = 0;
    while (i < nsyms) {
        bswap_sym(syms + i);
        /* Throw away entries which we do not need. */
        if (syms[i].st_shndx == SHN_UNDEF ||
                syms[i].st_shndx >= SHN_LORESERVE ||
                ELF_ST_TYPE(syms[i].st_info) != STT_FUNC) {
            nsyms--;
            if (i < nsyms) {
                syms[i] = syms[nsyms];
            }
            continue;
        }
#if defined(TARGET_ARM) || defined(TARGET_MIPS)
        /* The bottom address bit marks a Thumb or MIPS16 symbol.  */
        syms[i].st_value &= ~(target_ulong)1;
#endif
        i++;
    }

     /*
      * Attempt to free the storage associated with the local symbols
      * that we threw away.  Whether or not this has any effect on the
      * memory allocation depends on the malloc implementation and how
      * many symbols we managed to discard.
      */
    new_syms = realloc(syms, nsyms * sizeof(*syms));
    if (new_syms == NULL) {
        free(s);
        free(syms);
        free(strings);
        return;
    }
    syms = new_syms;

    qsort(syms, nsyms, sizeof(*syms), symcmp);

    lseek(fd, strtab.sh_offset, SEEK_SET);
    if (read(fd, strings, strtab.sh_size) != strtab.sh_size) {
        free(s);
        free(syms);
        free(strings);
        return;
    }
    s->disas_num_syms = nsyms;
#if ELF_CLASS == ELFCLASS32
    s->disas_symtab.elf32 = syms;
    s->lookup_symbol = (lookup_symbol_t)lookup_symbolxx;
#else
    s->disas_symtab.elf64 = syms;
    s->lookup_symbol = (lookup_symbol_t)lookup_symbolxx;
#endif
    s->next = syminfos;
    syminfos = s;
}

/* Check the elf header and see if this a target elf binary. */
int is_target_elf_binary(int fd)
{
    uint8_t buf[128];
    struct elfhdr elf_ex;

    if (lseek(fd, 0L, SEEK_SET) < 0) {
        return 0;
    }
    if (read(fd, buf, sizeof(buf)) < 0) {
        return 0;
    }

    elf_ex = *((struct elfhdr *)buf);
    bswap_ehdr(&elf_ex);

    if ((elf_ex.e_type != ET_EXEC && elf_ex.e_type != ET_DYN) ||
        (!elf_check_arch(elf_ex.e_machine))) {
        return 0;
    } else {
        return 1;
    }
}

static int
load_elf_sections(const struct elfhdr *hdr, struct elf_phdr *phdr, int fd,
    abi_ulong rbase, abi_ulong *baddrp)
{
    struct elf_phdr *elf_ppnt;
    abi_ulong baddr;
    int i;
    bool first;

    /*
     * Now we do a little grungy work by mmaping the ELF image into
     * the correct location in memory.  At this point, we assume that
     * the image should be loaded at fixed address, not at a variable
     * address.
     */
    first = true;
    for (i = 0, elf_ppnt = phdr; i < hdr->e_phnum; i++, elf_ppnt++) {
        int elf_prot = 0;
        abi_ulong error;

        /* XXX Skip memsz == 0. */
        if (elf_ppnt->p_type != PT_LOAD) {
            continue;
        }

        if (elf_ppnt->p_flags & PF_R) {
            elf_prot |= PROT_READ;
        }
        if (elf_ppnt->p_flags & PF_W) {
            elf_prot |= PROT_WRITE;
        }
        if (elf_ppnt->p_flags & PF_X) {
            elf_prot |= PROT_EXEC;
        }

        error = target_mmap(TARGET_ELF_PAGESTART(rbase + elf_ppnt->p_vaddr),
                            (elf_ppnt->p_filesz +
                             TARGET_ELF_PAGEOFFSET(elf_ppnt->p_vaddr)),
                            elf_prot,
                            (MAP_FIXED | MAP_PRIVATE | MAP_DENYWRITE),
                            fd,
                            (elf_ppnt->p_offset -
                             TARGET_ELF_PAGEOFFSET(elf_ppnt->p_vaddr)));
        if (error == -1) {
            perror("mmap");
            exit(-1);
        } else if (elf_ppnt->p_memsz != elf_ppnt->p_filesz) {
            abi_ulong start_bss, end_bss;

            start_bss = rbase + elf_ppnt->p_vaddr + elf_ppnt->p_filesz;
            end_bss = rbase + elf_ppnt->p_vaddr + elf_ppnt->p_memsz;

            /*
             * Calling set_brk effectively mmaps the pages that we need for the
             * bss and break sections.
             */
            set_brk(start_bss, end_bss);
            padzero(start_bss, end_bss);
        }

        if (first) {
            baddr = TARGET_ELF_PAGESTART(rbase + elf_ppnt->p_vaddr);
            first = false;
        }
    }

    if (baddrp != NULL) {
        *baddrp = baddr;
    }
    return 0;
}

#ifndef ARM_COMMPAGE
#define ARM_COMMPAGE 0
#define init_guest_commpage() true
#endif

#define read_self_maps() NULL

static void pgb_fail_in_use(const char *image_name)
{
    error_report("%s: requires virtual address space that is in use "
                 "(omit the -B option or choose a different value)",
                 image_name);
    exit(EXIT_FAILURE);
}

static void pgb_have_guest_base(const char *image_name, abi_ulong guest_loaddr,
                                abi_ulong guest_hiaddr, long align)
{
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE;
    void *addr, *test;

    if (!QEMU_IS_ALIGNED(guest_base, align)) {
        fprintf(stderr, "Requested guest base %p does not satisfy "
                "host minimum alignment (0x%lx)\n",
                (void *)guest_base, align);
        exit(EXIT_FAILURE);
    }

    /* Sanity check the guest binary. */
    if (reserved_va) {
        if (guest_hiaddr > reserved_va) {
            error_report("%s: requires more than reserved virtual "
                         "address space (0x%" PRIx64 " > 0x%lx)",
                         image_name, (uint64_t)guest_hiaddr, reserved_va);
            exit(EXIT_FAILURE);
        }
    } else {
#if HOST_LONG_BITS < TARGET_ABI_BITS
        if ((guest_hiaddr - guest_base) > ~(uintptr_t)0) {
            error_report("%s: requires more virtual address space "
                         "than the host can provide (0x%" PRIx64 ")",
                         image_name, (uint64_t)guest_hiaddr - guest_base);
            exit(EXIT_FAILURE);
        }
#endif
    }

    /*
     * Expand the allocation to the entire reserved_va.
     * Exclude the mmap_min_addr hole.
     */
    if (reserved_va) {
        guest_loaddr = (guest_base >= mmap_min_addr ? 0
                        : mmap_min_addr - guest_base);
        guest_hiaddr = reserved_va;
    }

    /* Reserve the address space for the binary, or reserved_va. */
    test = g2h_untagged(guest_loaddr);
    addr = mmap(test, guest_hiaddr - guest_loaddr, PROT_NONE, flags, -1, 0);
    if (test != addr) {
        pgb_fail_in_use(image_name);
    }
}

/**
 * pgd_find_hole_fallback: potential mmap address
 * @guest_size: size of available space
 * @brk: location of break
 * @align: memory alignment
 *
 * This is a fallback method for finding a hole in the host address
 * space if we don't have the benefit of being able to access
 * /proc/self/map. It can potentially take a very long time as we can
 * only dumbly iterate up the host address space seeing if the
 * allocation would work.
 */
static uintptr_t pgd_find_hole_fallback(uintptr_t guest_size, uintptr_t brk,
                                        long align, uintptr_t offset)
{
    uintptr_t base;

    /* Start (aligned) at the bottom and work our way up */
    base = ROUND_UP(mmap_min_addr, align);

    while (true) {
        uintptr_t align_start, end;
        align_start = ROUND_UP(base, align);
        end = align_start + guest_size + offset;

        /* if brk is anywhere in the range give ourselves some room to grow. */
        if (align_start <= brk && brk < end) {
            base = brk + (16 * MiB);
            continue;
        } else if (align_start + guest_size < align_start) {
            /* we have run out of space */
            return -1;
        } else {
            int flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE |
                MAP_FIXED_NOREPLACE;
            void * mmap_start = mmap((void *) align_start, guest_size,
                                     PROT_NONE, flags, -1, 0);
            if (mmap_start != MAP_FAILED) {
                munmap(mmap_start, guest_size);
                if (mmap_start == (void *) align_start) {
                    return (uintptr_t) mmap_start + offset;
                }
            }
            base += qemu_host_page_size;
        }
    }
}

/* Return value for guest_base, or -1 if no hole found. */
static uintptr_t pgb_find_hole(uintptr_t guest_loaddr, uintptr_t guest_size,
                               long align, uintptr_t offset)
{
#if 0
    GSList *maps, *iter;
    uintptr_t this_start, this_end, next_start, brk;
#else
    uintptr_t brk;
    void *maps;
#endif
    intptr_t ret = -1;

    assert(QEMU_IS_ALIGNED(guest_loaddr, align));

    maps = read_self_maps();

    /* Read brk after we've read the maps, which will malloc. */
    brk = (uintptr_t)sbrk(0);

    if (!maps) {
        ret = pgd_find_hole_fallback(guest_size, brk, align, offset);
        return ret == -1 ? -1 : ret - guest_loaddr;
    }

#if 0
    /* The first hole is before the first map entry. */
    this_start = mmap_min_addr;

    for (iter = maps; iter;
         this_start = next_start, iter = g_slist_next(iter)) {
        uintptr_t align_start, hole_size;

        this_end = ((MapInfo *)iter->data)->start;
        next_start = ((MapInfo *)iter->data)->end;
        align_start = ROUND_UP(this_start + offset, align);

        /* Skip holes that are too small. */
        if (align_start >= this_end) {
            continue;
        }
        hole_size = this_end - align_start;
        if (hole_size < guest_size) {
            continue;
        }

        /* If this hole contains brk, give ourselves some room to grow. */
        if (this_start <= brk && brk < this_end) {
            hole_size -= guest_size;
            if (sizeof(uintptr_t) == 8 && hole_size >= 1 * GiB) {
                align_start += 1 * GiB;
            } else if (hole_size >= 16 * MiB) {
                align_start += 16 * MiB;
            } else {
                align_start = (this_end - guest_size) & -align;
                if (align_start < this_start) {
                    continue;
                }
            }
        }

        /* Record the lowest successful match. */
        if (ret < 0) {
            ret = align_start - guest_loaddr;
        }
        /* If this hole contains the identity map, select it. */
        if (align_start <= guest_loaddr &&
            guest_loaddr + guest_size <= this_end) {
            ret = 0;
        }
        /* If this hole ends above the identity map, stop looking. */
        if (this_end >= guest_loaddr) {
            break;
        }
    }
    free_self_maps(maps);
#endif
    return ret;
}

static void pgb_static(const char *image_name, abi_ulong orig_loaddr,
                       abi_ulong orig_hiaddr, long align)
{
    uintptr_t loaddr = orig_loaddr;
    uintptr_t hiaddr = orig_hiaddr;
    uintptr_t offset = 0;
    uintptr_t addr;

    if (hiaddr != orig_hiaddr) {
        error_report("%s: requires virtual address space that the "
                     "host cannot provide (0x%" PRIx64 ")",
                     image_name, (uint64_t)orig_hiaddr);
        exit(EXIT_FAILURE);
    }

    loaddr &= -align;
    if (ARM_COMMPAGE) {
        /*
         * Extend the allocation to include the commpage.
         * For a 64-bit host, this is just 4GiB; for a 32-bit host we
         * need to ensure there is space bellow the guest_base so we
         * can map the commpage in the place needed when the address
         * arithmetic wraps around.
         */
        if (sizeof(uintptr_t) == 8 || loaddr >= 0x80000000u) {
            hiaddr = (uintptr_t) 4 << 30;
        } else {
            offset = -(ARM_COMMPAGE & -align);
        }
    }

    addr = pgb_find_hole(loaddr, hiaddr - loaddr, align, offset);
    if (addr == -1) {
        /*
         * If ARM_COMMPAGE, there *might* be a non-consecutive allocation
         * that can satisfy both.  But as the normal arm32 link base address
         * is ~32k, and we extend down to include the commpage, making the
         * overhead only ~96k, this is unlikely.
         */
        error_report("%s: Unable to allocate %#zx bytes of "
                     "virtual address space", image_name,
                     (size_t)(hiaddr - loaddr));
        exit(EXIT_FAILURE);
    }

    guest_base = addr;
}

static void pgb_dynamic(const char *image_name, long align)
{
    /*
     * The executable is dynamic and does not require a fixed address.
     * All we need is a commpage that satisfies align.
     * If we do not need a commpage, leave guest_base == 0.
     */
    if (ARM_COMMPAGE) {
        uintptr_t addr, commpage;

        /* 64-bit hosts should have used reserved_va. */
        assert(sizeof(uintptr_t) == 4);

        /*
         * By putting the commpage at the first hole, that puts guest_base
         * just above that, and maximises the positive guest addresses.
         */
        commpage = ARM_COMMPAGE & -align;
        addr = pgb_find_hole(commpage, -commpage, align, 0);
        assert(addr != -1);
        guest_base = addr;
    }
}

static void pgb_reserved_va(const char *image_name, abi_ulong guest_loaddr,
                            abi_ulong guest_hiaddr, long align)
{
    int flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE;
    void *addr, *test;

    if (guest_hiaddr > reserved_va) {
        error_report("%s: requires more than reserved virtual "
                     "address space (0x%" PRIx64 " > 0x%lx)",
                     image_name, (uint64_t)guest_hiaddr, reserved_va);
        exit(EXIT_FAILURE);
    }

    /* Widen the "image" to the entire reserved address space. */
    pgb_static(image_name, 0, reserved_va, align);

    /* osdep.h defines this as 0 if it's missing */
    flags |= MAP_FIXED_NOREPLACE;

    /* Reserve the memory on the host. */
    assert(guest_base != 0);
    test = g2h_untagged(0);
    addr = mmap(test, reserved_va, PROT_NONE, flags, -1, 0);
    if (addr == MAP_FAILED || addr != test) {
        error_report("Unable to reserve 0x%lx bytes of virtual address "
                     "space at %p (%s) for use as guest address space (check your"
                     "virtual memory ulimit setting, min_mmap_addr or reserve less "
                     "using -R option)", reserved_va, test, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void probe_guest_base(const char *image_name, abi_ulong guest_loaddr,
                      abi_ulong guest_hiaddr)
{
    /* In order to use host shmat, we must be able to honor SHMLBA.  */
    uintptr_t align = MAX(SHMLBA, qemu_host_page_size);

    if (have_guest_base) {
        pgb_have_guest_base(image_name, guest_loaddr, guest_hiaddr, align);
    } else if (reserved_va) {
        pgb_reserved_va(image_name, guest_loaddr, guest_hiaddr, align);
    } else if (guest_loaddr) {
        pgb_static(image_name, guest_loaddr, guest_hiaddr, align);
    } else {
        pgb_dynamic(image_name, align);
    }

    /* Reserve and initialize the commpage. */
    if (!init_guest_commpage()) {
        /*
         * With have_guest_base, the user has selected the address and
         * we are trying to work with that.  Otherwise, we have selected
         * free space and init_guest_commpage must succeeded.
         */
        assert(have_guest_base);
        pgb_fail_in_use(image_name);
    }

    assert(QEMU_IS_ALIGNED(guest_base, align));
    qemu_log_mask(CPU_LOG_PAGE, "Locating guest address space "
                  "@ 0x%" PRIx64 "\n", (uint64_t)guest_base);
}

int load_elf_binary(struct bsd_binprm *bprm, struct target_pt_regs *regs,
                    struct image_info *info)
{
    struct elfhdr elf_ex;
    struct elfhdr *ehdr;
    struct elfhdr interp_elf_ex;
    int interpreter_fd = -1; /* avoid warning */
    abi_ulong load_addr;
    int i;
    struct elf_phdr *elf_ppnt;
    struct elf_phdr *elf_phdata;
    struct elf_phdr *phdr;
    abi_ulong elf_brk;
    int error, retval;
    char *pinterp_name;
    abi_ulong baddr, elf_entry, et_dyn_addr, interp_load_addr = 0;
    abi_ulong loaddr, hiaddr;
    abi_ulong reloc_func_desc = 0;

    load_addr = 0;
    elf_ex = *((struct elfhdr *) bprm->buf);          /* exec-header */
    bswap_ehdr(&elf_ex);
    ehdr = &elf_ex;

    /* First of all, some simple consistency checks */
    if ((elf_ex.e_type != ET_EXEC && elf_ex.e_type != ET_DYN) ||
        (!elf_check_arch(elf_ex.e_machine))) {
            return -ENOEXEC;
    }

    bprm->p = copy_elf_strings(1, &bprm->filename, bprm->page, bprm->p);
    bprm->p = copy_elf_strings(bprm->envc, bprm->envp, bprm->page, bprm->p);
    bprm->p = copy_elf_strings(bprm->argc, bprm->argv, bprm->page, bprm->p);
    if (!bprm->p) {
        retval = -E2BIG;
    }

    /* Now read in all of the header information */
    elf_phdata = (struct elf_phdr *)malloc(elf_ex.e_phentsize * elf_ex.e_phnum);
    if (elf_phdata == NULL) {
        return -ENOMEM;
    }

    retval = lseek(bprm->fd, elf_ex.e_phoff, SEEK_SET);
    if (retval > 0) {
        retval = read(bprm->fd, (char *)elf_phdata,
                                elf_ex.e_phentsize * elf_ex.e_phnum);
    }

    if (retval < 0) {
        perror("load_elf_binary");
        exit(-1);
        free(elf_phdata);
        return -errno;
    }

    bswap_phdr(elf_phdata, elf_ex.e_phnum);
    elf_ppnt = elf_phdata;

    elf_brk = 0;

    pinterp_name = NULL;
    for (i = 0; i < elf_ex.e_phnum; i++) {
        if (elf_ppnt->p_type == PT_INTERP) {
            if (pinterp_name != NULL) {
                free(elf_phdata);
                free(pinterp_name);
                close(bprm->fd);
                return -EINVAL;
            }

            pinterp_name = (char *)malloc(elf_ppnt->p_filesz);
            if (pinterp_name == NULL) {
                free(elf_phdata);
                close(bprm->fd);
                return -ENOMEM;
            }

            retval = lseek(bprm->fd, elf_ppnt->p_offset, SEEK_SET);
            if (retval >= 0) {
                retval = read(bprm->fd, pinterp_name, elf_ppnt->p_filesz);
            }
            if (retval < 0) {
                perror("load_elf_binary2");
                exit(-1);
            }

            if (retval >= 0) {
                retval = open(path(pinterp_name), O_RDONLY);
                if (retval >= 0) {
                    interpreter_fd = retval;
                } else {
                    perror(pinterp_name);
                    exit(-1);
                    /* retval = -errno; */
                }
            }

            if (retval >= 0) {
                retval = lseek(interpreter_fd, 0, SEEK_SET);
                if (retval >= 0) {
                    retval = read(interpreter_fd, bprm->buf, 128);
                }
            }
            if (retval >= 0) {
                interp_elf_ex = *((struct elfhdr *) bprm->buf);
            }
            if (retval < 0) {
                perror("load_elf_binary3");
                exit(-1);
                free(elf_phdata);
                free(pinterp_name);
                close(bprm->fd);
                return retval;
            }
        }
        elf_ppnt++;
    }

    /* Some simple consistency checks for the interpreter */
    if (pinterp_name) {
        if (interp_elf_ex.e_ident[0] != 0x7f ||
            strncmp((char *)&interp_elf_ex.e_ident[1], "ELF", 3) != 0) {
            free(pinterp_name);
            free(elf_phdata);
            close(bprm->fd);
            return -ELIBBAD;
        }
    }

    /*
     * OK, we are done with that, now set up the arg stuff, and then start this
     * sucker up
     */
    if (!bprm->p) {
        free(pinterp_name);
        free(elf_phdata);
        close(bprm->fd);
        return -E2BIG;
    }

    /* OK, This is the point of no return */
    info->end_data = 0;
    info->end_code = 0;
    info->start_mmap = (abi_ulong)ELF_START_MMAP;
    info->mmap = 0;
    elf_entry = (abi_ulong) elf_ex.e_entry;

    mmap_lock();

    /*
     * Find the maximum size of the image and allocate an appropriate
     * amount of memory to handle that.  Locate the interpreter, if any.
     */
    loaddr = -1, hiaddr = 0;
//  info->alignment = 0;
    for (i = 0; i < ehdr->e_phnum; ++i) {
        struct elf_phdr *eppnt = phdr + i;
        if (eppnt->p_type == PT_LOAD) {
            abi_ulong a = eppnt->p_vaddr - eppnt->p_offset;
            if (a < loaddr) {
                loaddr = a;
            }
            a = eppnt->p_vaddr + eppnt->p_memsz;
            if (a > hiaddr) {
                hiaddr = a;
            }
//          ++info->nsegs;
//          info->alignment |= eppnt->p_align;
        } else if (eppnt->p_type == PT_INTERP && pinterp_name) {
            g_autofree char *interp_name = NULL;

            if (*pinterp_name) {
//                error_setg(&err, "Multiple PT_INTERP entries");
//                goto exit_errmsg;
                errx(1, "Multiple PT_INTERP entries");
            }

            interp_name = g_malloc(eppnt->p_filesz);

            if (eppnt->p_offset + eppnt->p_filesz <= BPRM_BUF_SIZE) {
                memcpy(interp_name, bprm_buf + eppnt->p_offset,
                       eppnt->p_filesz);
            } else {
                retval = pread(image_fd, interp_name, eppnt->p_filesz,
                               eppnt->p_offset);
                if (retval != eppnt->p_filesz) {
                    err(1, "read");
                }
            }
            if (interp_name[eppnt->p_filesz - 1] != 0) {
                errx(1, "Invalid PT_INTERP entry");
            }
            *pinterp_name = g_steal_pointer(&interp_name);
    }

    if (pinterp_name != NULL) {
        /*
         * This is the main executable.
         *
         * Reserve extra space for brk.
         * We hold on to this space while placing the interpreter
         * and the stack, lest they be placed immediately after
         * the data segment and block allocation from the brk.
         *
         * 16MB is chosen as "large enough" without being so large
         * as to allow the result to not fit with a 32-bit guest on
         * a 32-bit host.
         */
//        info->reserve_brk = 16 * MiB;
//        hiaddr += info->reserve_brk;
        hiaddr += 16 * MiB;

        if (ehdr->e_type == ET_EXEC) {
            /*
             * Make sure that the low address does not conflict with
             * MMAP_MIN_ADDR or the QEMU application itself.
             */
            probe_guest_base("image_name", loaddr, hiaddr);
        } else {
            /*
             * The binary is dynamic, but we still need to
             * select guest_base.  In this case we pass a size.
             */
            probe_guest_base("image_name", 0, hiaddr - loaddr);
        }
    }

    /*
     * Reserve address space for all of this.
     *
     * In the case of ET_EXEC, we supply MAP_FIXED so that we get
     * exactly the address range that is required.
     *
     * Otherwise this is ET_DYN, and we are searching for a location
     * that can hold the memory space required.  If the image is
     * pre-linked, LOADDR will be non-zero, and the kernel should
     * honor that address if it happens to be free.
     *
     * In both cases, we will overwrite pages in this range with mappings
     * from the executable.
     */
    load_addr = target_mmap(loaddr, hiaddr - loaddr, PROT_NONE,
                            MAP_PRIVATE | MAP_ANON | MAP_NORESERVE |
                            (ehdr->e_type == ET_EXEC ? MAP_FIXED : 0),
                            -1, 0);
    if (load_addr == -1) {
        err(1, "mmap");
    }
    load_bias = load_addr - loaddr;

    et_dyn_addr = 0;
    if (elf_ex.e_type == ET_DYN && baddr == 0) {
        et_dyn_addr = ELF_ET_DYN_LOAD_ADDR;
    }

    /*
     * Do this so that we can load the interpreter, if need be.  We will
     * change some of these later
     */
    info->rss = 0;
    setup_arg_pages(bprm, info, &bprm->p, &bprm->stringp);
    info->start_stack = bprm->p;

    info->elf_flags = elf_ex.e_flags;

    error = load_elf_sections(&elf_ex, elf_phdata, bprm->fd, et_dyn_addr,
        &load_addr);
    for (i = 0, elf_ppnt = elf_phdata; i < elf_ex.e_phnum; i++, elf_ppnt++) {
        if (elf_ppnt->p_type != PT_LOAD) {
            continue;
        }
        if (elf_ppnt->p_memsz > elf_ppnt->p_filesz)
            elf_brk = MAX(elf_brk, et_dyn_addr + elf_ppnt->p_vaddr +
                elf_ppnt->p_memsz);
    }
    if (error != 0) {
        perror("load_elf_sections");
        exit(-1);
    }

    if (pinterp_name) {
        elf_entry = load_elf_interp(&interp_elf_ex, interpreter_fd,
                                    &interp_load_addr);
        reloc_func_desc = interp_load_addr;

        close(interpreter_fd);
        free(pinterp_name);

        if (elf_entry == ~((abi_ulong)0UL)) {
            printf("Unable to load interpreter\n");
            free(elf_phdata);
            exit(-1);
            return 0;
        }
    } else {
        interp_load_addr = et_dyn_addr;
        elf_entry += interp_load_addr;
    }

    free(elf_phdata);

    if (qemu_log_enabled()) {
        load_symbols(&elf_ex, bprm->fd);
    }

    close(bprm->fd);

    bprm->p = target_create_elf_tables(bprm->p, bprm->argc, bprm->envc,
                                       bprm->stringp, &elf_ex, load_addr,
                                       et_dyn_addr, interp_load_addr, info);
    info->load_addr = reloc_func_desc;
    info->start_brk = info->brk = elf_brk;
    info->start_stack = bprm->p;
    info->load_bias = 0;

    info->entry = elf_entry;

#ifdef USE_ELF_CORE_DUMP
    bprm->core_dump = &elf_core_dump;
#else
    bprm->core_dump = NULL;
#endif

    return 0;
}

void do_init_thread(struct target_pt_regs *regs, struct image_info *infop)
{

    target_thread_init(regs, infop);
}

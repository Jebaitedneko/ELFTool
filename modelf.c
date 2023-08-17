/*
   BSD 3-Clause License

   Copyright (c) 2022 dropbear

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this
      list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

   3. Neither the name of the copyright holder nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// This program requires -fno-strict-aliasing.

#include <elf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

enum op_mode { SEGMENT_MODE, SECTION_MODE };

// fun clang-format bug: & is parsed as the binary infix
// "bitwise AND" operator here instead of the unary prefix
// "address-of" operator
enum op_field_segment {
    PT_TYPE = (size_t) & ((Elf64_Phdr *)NULL)->p_type,
    PT_FLAGS = (size_t) & ((Elf64_Phdr *)NULL)->p_flags,
    PT_OFFSET = (size_t) & ((Elf64_Phdr *)NULL)->p_offset,
    PT_VADDR = (size_t) & ((Elf64_Phdr *)NULL)->p_vaddr,
    PT_PADDR = (size_t) & ((Elf64_Phdr *)NULL)->p_paddr,
    PT_FILESZ = (size_t) & ((Elf64_Phdr *)NULL)->p_filesz,
    PT_MEMSZ = (size_t) & ((Elf64_Phdr *)NULL)->p_memsz,
    PT_ALIGN = (size_t) & ((Elf64_Phdr *)NULL)->p_align,
};

enum op_field_section {
    SH_NAME = (size_t) & ((Elf64_Shdr *)NULL)->sh_name,
    SH_TYPE = (size_t) & ((Elf64_Shdr *)NULL)->sh_type,
    SH_FLAGS = (size_t) & ((Elf64_Shdr *)NULL)->sh_flags,
    SH_ADDR = (size_t) & ((Elf64_Shdr *)NULL)->sh_addr,
    SH_OFFSET = (size_t) & ((Elf64_Shdr *)NULL)->sh_offset,
    SH_SIZE = (size_t) & ((Elf64_Shdr *)NULL)->sh_size,
    SH_LINK = (size_t) & ((Elf64_Shdr *)NULL)->sh_link,
    SH_INFO = (size_t) & ((Elf64_Shdr *)NULL)->sh_info,
    SH_ADDRALIGN = (size_t) & ((Elf64_Shdr *)NULL)->sh_addralign,
    SH_ENTSIZE = (size_t) & ((Elf64_Shdr *)NULL)->sh_entsize,
};

typedef struct {
    size_t width;
    char *name;
} headerFieldInfo;

headerFieldInfo programHeaderFieldInfo[] = {
    [PT_TYPE] = { sizeof(((Elf64_Phdr *)NULL)->p_type), "TYPE" },       //
    [PT_FLAGS] = { sizeof(((Elf64_Phdr *)NULL)->p_flags), "FLAGS" },    //
    [PT_OFFSET] = { sizeof(((Elf64_Phdr *)NULL)->p_offset), "OFFSET" }, //
    [PT_VADDR] = { sizeof(((Elf64_Phdr *)NULL)->p_vaddr), "VADDR" },    //
    [PT_PADDR] = { sizeof(((Elf64_Phdr *)NULL)->p_paddr), "PADDR" },    //
    [PT_FILESZ] = { sizeof(((Elf64_Phdr *)NULL)->p_filesz), "FILESZ" }, //
    [PT_MEMSZ] = { sizeof(((Elf64_Phdr *)NULL)->p_memsz), "MEMSZ" },    //
    [PT_ALIGN] = { sizeof(((Elf64_Phdr *)NULL)->p_align), "ALIGN" },    //
};

headerFieldInfo sectionHeaderFieldInfo[] = {
    [SH_NAME] = { sizeof(((Elf64_Shdr *)NULL)->sh_name), "NAME" },                //
    [SH_TYPE] = { sizeof(((Elf64_Shdr *)NULL)->sh_type), "TYPE" },                //
    [SH_FLAGS] = { sizeof(((Elf64_Shdr *)NULL)->sh_flags), "FLAGS" },             //
    [SH_ADDR] = { sizeof(((Elf64_Shdr *)NULL)->sh_addr), "ADDR" },                //
    [SH_OFFSET] = { sizeof(((Elf64_Shdr *)NULL)->sh_offset), "OFFSET" },          //
    [SH_SIZE] = { sizeof(((Elf64_Shdr *)NULL)->sh_size), "SIZE" },                //
    [SH_LINK] = { sizeof(((Elf64_Shdr *)NULL)->sh_link), "LINK" },                //
    [SH_INFO] = { sizeof(((Elf64_Shdr *)NULL)->sh_info), "INFO" },                //
    [SH_ADDRALIGN] = { sizeof(((Elf64_Shdr *)NULL)->sh_addralign), "ADDRALIGN" }, //
    [SH_ENTSIZE] = { sizeof(((Elf64_Shdr *)NULL)->sh_entsize), "ENTSIZE" },       //
};

const struct {
    char *flag;
    int field[2];
} ARG_LIST[] = {
    { "--type", { PT_TYPE, SH_TYPE } },        //
    { "--flags", { PT_FLAGS, SH_FLAGS } },     //
    { "--offset", { PT_OFFSET, SH_OFFSET } },  //
    { "--vaddr", { PT_VADDR, -1 } },           //
    { "--paddr", { PT_PADDR, -1 } },           //
    { "--filesz", { PT_FILESZ, -1 } },         //
    { "--memsz", { PT_MEMSZ, -1 } },           //
    { "--align", { PT_ALIGN, SH_ADDRALIGN } }, //

    { "--name", { -1, SH_NAME } },       //
    { "--addr", { -1, SH_ADDR } },       //
    { "--size", { -1, SH_SIZE } },       //
    { "--link", { -1, SH_LINK } },       //
    { "--info", { -1, SH_INFO } },       //
    { "--entsize", { -1, SH_ENTSIZE } }, //
};

const struct {
    char *flag;
    int mode;
} SPECIAL_ARGS[] = {
    { "--segment", SEGMENT_MODE }, //
    { "--section", SECTION_MODE }, //
};

typedef struct modelf_op_s {
    enum op_mode mode;
    int index;
    int field;
    uint64_t newValue;
    struct modelf_op_s *next;
} modelf_op;

off_t fsize(FILE *fp) {
    if (!fp)
        return -1;

    struct stat st;
    if (fstat(fileno(fp), &st))
        return -1;

    return st.st_size;
}

void printUsageAndExit(void) {
    fprintf(stderr, "Usage: [add later]\n");
    exit(1);
}

int main(int argc, char **argv) {
    if (argc <= 0) {
        fprintf(stderr, "No shenanigans! (argc <= 0)\n");
        exit(1);
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [filename]\n", argv[0]);
        exit(1);
    }

    char *filename = NULL;
    modelf_op *operation = NULL;

    enum op_mode currentMode = -1;
    int currentIndex = -1;
    modelf_op *currentOp = NULL;
    bool expectingValue = false;
    bool expectingNewIndex = false;
    for (int i = 1; i < argc; i++) {
        for (int j = 0; j < sizeof(ARG_LIST) / sizeof(ARG_LIST[0]); j++) {
            if (!strcmp(argv[i], ARG_LIST[j].flag)) {
                if (expectingValue) {
                    fprintf(stderr, "Extra argument '%s'\n", argv[i]);
                    printUsageAndExit();
                }

                modelf_op *newOp = malloc(sizeof(*newOp));
                newOp->mode = currentMode;
                newOp->index = currentIndex;
                newOp->field = ARG_LIST[j].field[currentMode];
                if (newOp->field < 0) {
                    fprintf(stderr, "'%s' cannot be used on a %s\n", argv[i], currentMode == SEGMENT_MODE ? "segment" : "section");
                    printUsageAndExit();
                }

                newOp->next = NULL;
                if (currentOp) {
                    currentOp->next = newOp;
                } else {
                    operation = newOp;
                }
                currentOp = newOp;

                expectingValue = true;

                goto outer_loop;
            }
        }

        for (int j = 0; j < sizeof(SPECIAL_ARGS) / sizeof(SPECIAL_ARGS[0]); j++) {
            if (!strcmp(argv[i], SPECIAL_ARGS[j].flag)) {
                if (expectingValue) {
                    fprintf(stderr, "Extra argument '%s'\n", argv[i]);
                    printUsageAndExit();
                }

                currentMode = SPECIAL_ARGS[j].mode;

                expectingValue = true;
                expectingNewIndex = true;
                goto outer_loop;
            }
        }

        if (!expectingValue) {
            if (filename) {
                fprintf(stderr, "Expected flag, not '%s' (filename has already been set to '%s')\n", argv[i], argv[i - 1]);
                printUsageAndExit();
            } else {
                if (argv[i][0] == '-' && argv[i][1] == '-') {
                    fprintf(stderr, "Unknown flag '%s'\n", argv[i]);
                    printUsageAndExit();
                }
                filename = argv[i];
                continue;
            }
        }

        // make sure the value is a well-formed (hexa)decimal value
        for (int j = 0; j < strlen(argv[i]); j++) {
            if (!((argv[i][j] >= '0' && argv[i][j] <= '9') || (argv[i][j] >= 'a' && argv[i][j] <= 'f') || (argv[i][j] == 'x' && j == 1))) {
                fprintf(stderr, "Invalid value '%s'\n", argv[i]);
                printUsageAndExit();
            }
        }

        if (expectingNewIndex) {
            currentIndex = strtoul(argv[i], NULL, 0);
            expectingNewIndex = false;
        } else {
            currentOp->newValue = strtoul(argv[i], NULL, 0);
        }
        expectingValue = false;

    outer_loop:
        continue;
    }

    if (!filename) {
        printUsageAndExit();
    }

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open file: %s (%d)\n", strerror(errno), errno);
        exit(1);
    }

    off_t fileSize = fsize(fp);
    if (fp < 0) {
        fprintf(stderr, "Error getting size of file: %s (%d)\n", strerror(errno), errno);
    }

    char *fileBuf = malloc(fileSize);
    fread(fileBuf, 1, fileSize, fp);
    fclose(fp);

    if (fileBuf[4] != ELFCLASS64) {
        fprintf(stderr, "Only ELF64 is supported (file is %s)\n", fileBuf[4] == ELFCLASS32 ? "ELF32" : "not a valid ELF file");
    }

    Elf64_Ehdr elfHeader;
    memcpy(&elfHeader, fileBuf, sizeof(elfHeader));
    Elf64_Phdr *programHeaders = NULL;
    if (elfHeader.e_phnum) {
        programHeaders = malloc(sizeof(Elf64_Phdr) * elfHeader.e_phnum);
        memcpy(programHeaders, fileBuf + elfHeader.e_phoff, elfHeader.e_phnum * elfHeader.e_phentsize);
    }
    Elf64_Shdr *sectionHeaders = NULL;
    if (elfHeader.e_shnum) {
        sectionHeaders = malloc(sizeof(Elf64_Shdr) * elfHeader.e_shnum);
        memcpy(sectionHeaders, fileBuf + elfHeader.e_shoff, elfHeader.e_shnum * elfHeader.e_shentsize);
    }

    while (operation) {
        if (operation->mode == SEGMENT_MODE) {
            if (programHeaderFieldInfo[operation->field].width == 4) {
                printf("Phdr[%d] %s: 0x%x -> 0x%lx\n",
                       operation->index,
                       programHeaderFieldInfo[operation->field].name,
                       *(Elf64_Word *)((char *)(programHeaders + operation->index) + operation->field),
                       operation->newValue);
                *(Elf64_Word *)((char *)(programHeaders + operation->index) + operation->field) = operation->newValue;
            } else {
                printf("Phdr[%d] %s: 0x%lx -> 0x%lx\n",
                       operation->index,
                       programHeaderFieldInfo[operation->field].name,
                       *(Elf64_Xword *)((char *)(programHeaders + operation->index) + operation->field),
                       operation->newValue);
                *(Elf64_Xword *)((char *)(programHeaders + operation->index) + operation->field) = operation->newValue;
            }
        } else if (operation->mode == SECTION_MODE) {
            if (sectionHeaderFieldInfo[operation->field].width == 4) {
                printf("Shdr[%d] %s: 0x%x -> 0x%lx\n",
                       operation->index,
                       sectionHeaderFieldInfo[operation->field].name,
                       *(Elf64_Word *)((char *)(sectionHeaders + operation->index) + operation->field),
                       operation->newValue);
                *(Elf64_Word *)((char *)(sectionHeaders + operation->index) + operation->field) = operation->newValue;
            } else {
                printf("Shdr[%d] %s: 0x%lx -> 0x%lx\n",
                       operation->index,
                       sectionHeaderFieldInfo[operation->field].name,
                       *(Elf64_Xword *)((char *)(sectionHeaders + operation->index) + operation->field),
                       operation->newValue);
                *(Elf64_Xword *)((char *)(sectionHeaders + operation->index) + operation->field) = operation->newValue;
            }
        } else {
            fprintf(stderr, "Unexpected op_mode\n");
            exit(1);
        }

        operation = operation->next;
    }

    memcpy(fileBuf + elfHeader.e_phoff, programHeaders, elfHeader.e_phnum * elfHeader.e_phentsize);
    memcpy(fileBuf + elfHeader.e_shoff, sectionHeaders, elfHeader.e_shnum * elfHeader.e_shentsize);

    fp = fopen("modelf-out.elf", "wb");
    fwrite(fileBuf, 1, fileSize, fp);
    fclose(fp);
}

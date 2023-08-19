PFX=aarch64-linux-gnu-
PFX=

${PFX}gcc modelf.c -o modelf

cat << EOF > target.c
#include <stdio.h>
int main(){int a=0;asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");printf("%d\n",a);return 0;}
EOF
# cat << EOF > target.c
# #include <stdio.h>
# int main(){return 1;}
# EOF
${PFX}gcc target.c -o target -g -Wall && rm target.c
${PFX}objcopy --dump-section .text=target.text target
TARGET_TEXT_SZ_ORIG=$(printf %x $(stat -c '%s' target.text) | sed 's/^0*//;s/^/0x/')
echo "==== TARGET_TEXT_SZ_ORIG: $TARGET_TEXT_SZ_ORIG ===="
${PFX}readelf -a target > re-target_pre.txt

cat << EOF > patch.S
.section .text
.globl __patch
.type __patch, @function
__patch:
    push   %rbp
    mov    %rsp,%rbp
    mov    %eax, %eax
    mov    %eax, %eax
    mov    %eax, %eax
    mov    %eax, %eax
    pop    %rbp
    ret
.size __patch, .-__patch
EOF
# cat << EOF > patch.S
# .section .text
# .globl __patch
# .type __patch, @function
# __patch:
#     mov w0, wzr
#     ret
# .size __patch, .-__patch
# EOF
${PFX}as -c patch.S -o patch.o && rm patch.S
${PFX}readelf -a patch.o > re-patch.txt

echo "==== patch.o objdump start ===="
${PFX}objdump -d patch.o
echo "==== patch.o objdump end ===="

${PFX}objcopy --dump-section .text=patch.text patch.o && rm patch.o
PATCH_TEXT_SZ=$(printf %x $(stat -c '%s' patch.text) | sed 's/^0*//;s/^/0x/')
echo "==== PATCH_TEXT_SZ: $PATCH_TEXT_SZ ===="
cat patch.text >> target.text && rm patch.text
TARGET_TEXT_SZ_PATCHED=0x$(printf %x $(stat -c '%s' target.text))
echo "==== TARGET_TEXT_SZ_PATCHED: $TARGET_TEXT_SZ_PATCHED ===="

S_ADDR=$(${PFX}readelf -a target | grep ".text  " -A3 | tail -n2 | tr -d '\n' | sed "s/  \+/\n/g"  | sed -n 5p | tr -d '\n' | sed 's/^0*//' | tac -rs .. | echo "$(tr -d '\n')")

DYN_ADDR=$(${PFX}readelf -a target | grep ".dynamic  " -A1 | tr -d '\n' | sed "s/  \+/\n/g"  | sed -n 5p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
DYN_SIZE=$(${PFX}readelf -a target | grep ".dynamic  " -A1 | tr -d '\n' | sed "s/  \+/\n/g"  | sed -n 6p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
DYN_OLDHX=$(xxd -s $(printf %d $DYN_ADDR) -l $(printf %d $DYN_SIZE) -g0 target | grep -oE "[0-9a-f]{32}" | tr -d '\n' | grep -oE ".{,4}$S_ADDR.{,4}")

SYM_ADDR=$(${PFX}readelf -a target | grep ".symtab  " -A1 | tr -d '\n' | sed "s/  \+/\n/g"  | sed -n 5p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
SYM_SIZE=$(${PFX}readelf -a target | grep ".symtab  " -A1 | tr -d '\n' | sed "s/  \+/\n/g"  | sed -n 6p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
SYM_OLDHX=$(xxd -s $(printf %d $SYM_ADDR) -l $(printf %d $SYM_SIZE) -g0 target | grep -oE "[0-9a-f]{32}" | tr -d '\n' | grep -oE ".{,4}$S_ADDR.{,4}")

function patch_symtab_and_dynamic_sections() {
    DYN_PATCH=$(echo $DYN_OLDHX | sed "s/$S_ADDR/$1/g")
    DYN_NEWHX=$(echo $DYN_PATCH | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
    DYN_OLDHX=$(echo $DYN_OLDHX | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
    echo "DYN_PATCH: $DYN_OLDHX|$DYN_NEWHX"
    sed -i "s|$DYN_OLDHX|$DYN_NEWHX|g" target

    SYM_PATCH=$(echo $SYM_OLDHX | sed "s/$S_ADDR/$1/g")
    SYM_NEWHX=$(echo $SYM_PATCH | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
    SYM_OLDHX=$(echo $SYM_OLDHX | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
    echo "SYM_PATCH: $SYM_OLDHX|$SYM_NEWHX"
    sed -i "s|$SYM_OLDHX|$SYM_NEWHX|g" target
}

${PFX}objcopy --update-section .text=target.text target target_patch &> objcopy-out.txt && mv target_patch target && rm target.text

S_NEW_ADDR=$(cat objcopy-out.txt | grep -oE "0x[0-9a-f]+$" | sed "s/0x//g" | tac -rs .. | echo "$(tr -d '\n')")

patch_symtab_and_dynamic_sections $S_NEW_ADDR

rm objcopy-out.txt

# ${PFX}objcopy --add-section .patch=patch.text --set-section-flags .patch=code,readonly,alloc target target_patch && mv target_patch target && rm target.text

# patch the section following .text
# S_ADDR=$(readelf -a target | grep ".text  " -A1 | tr -d '\n' | sed "s/  \+/\n/g" | sed -n 4p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
# S_OFF=$(readelf -a target | grep ".text  " -A1 | tr -d '\n' | sed "s/  \+/\n/g" | sed -n 6p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
# S_ALIGN=16
# RELOC=$(printf %x $((S_OFF+S_ALIGN)) | sed 's/^0*//;s/^/0x/')
# ${PFX}objcopy --change-section-vma .fini+$RELOC target target_patch && mv target_patch target
# PATCH_SECTION=$(${PFX}readelf -a target | grep ".fini  " | grep -oE "\[.*\]" | sed "s/\[//g;s/\]//g" | tr -d '\n') # change section here (plt for arm)
# ./modelf target --section $PATCH_SECTION --addr $RELOC --offset $RELOC && mv modelf-out.elf target

# sed -i "s|\x00\x00\x84\x11|\x00\x00\x92\x11|g" target .fini dynamic 0x1184 -> 0x1192
# sed -i "s|\x11\x00\x84\x11|\x11\x00\x92\x11|g" target .fini symtab 0x1184 -> 0x1192

${PFX}objcopy --add-symbol __patch=".text:${TARGET_TEXT_SZ_ORIG},global,function" target target_patch && mv target_patch target
# ${PFX}objcopy --add-symbol __patch=".patch:0,global,function" target target_patch && mv target_patch target

${PFX}readelf -a target > re-target_pst.txt
diff -ur re-target_pre.txt re-target_pst.txt

echo "==== target objdump start ===="
${PFX}objdump -d target
echo "==== target objdump end ===="
PFX=aarch64-linux-gnu-
PFX=

# Prepare Target Binary
cat << EOF > target.c
#include <stdio.h>
int main(){int a=0;asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");printf("%d\n",a);return 0;}
EOF
${PFX}gcc target.c -o target -g -Wall && rm target.c

# Dump .text section from Target
${PFX}objcopy --dump-section .text=target.text target
TARGET_TEXT_SZ_ORIG=$(printf %x $(stat -c '%s' target.text) | sed 's/^0*//;s/^/0x/')
echo "==== TARGET_TEXT_SZ_ORIG: $TARGET_TEXT_SZ_ORIG ===="

# Dump ELF data from Target
${PFX}readelf -a target > re-target_pre.txt

# Prepare Patch Code
cat << EOF > patch.S
.section .text
.globl __patch
.type __patch, @function
__patch:
    push   %rbp
    mov    %rsp,%rbp
    xor    %eax, %eax
    inc    %eax
    pop    %rbp
    ret
.size __patch, .-__patch
EOF
${PFX}as -c patch.S -o patch.o && rm patch.S

# Dump ELF data from Patch
${PFX}readelf -a patch.o > re-patch.txt

# Print .text section from Patch
echo "==== patch.o objdump start ===="
${PFX}objdump -d patch.o
echo "==== patch.o objdump end ===="

# Dump .text section from Patch
${PFX}objcopy --dump-section .text=patch.text patch.o && rm patch.o
PATCH_TEXT_SZ=$(printf %x $(stat -c '%s' patch.text) | sed 's/^0*//;s/^/0x/')
echo "==== PATCH_TEXT_SZ: $PATCH_TEXT_SZ ===="

# Merge .text section from Patch into Target
cat patch.text >> target.text && rm patch.text
TARGET_TEXT_SZ_PATCHED=0x$(printf %x $(stat -c '%s' target.text))
echo "==== TARGET_TEXT_SZ_PATCHED: $TARGET_TEXT_SZ_PATCHED ===="

# Compute address of section after .text (this will get resized)
S_ADDR=$(${PFX}readelf -a target | grep ".text  " -A3 | tail -n2 | tr -d '\n' | sed "s/  \+/\n/g"  | sed -n 5p | tr -d '\n' | sed 's/^0*//' | tac -rs .. | echo "$(tr -d '\n')")

# Compute .dynamic section address and offset
DYN_ADDR=$(${PFX}readelf -a target | grep ".dynamic  " -A1 | tr -d '\n' | sed "s/  \+/\n/g"  | sed -n 5p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
DYN_SIZE=$(${PFX}readelf -a target | grep ".dynamic  " -A1 | tr -d '\n' | sed "s/  \+/\n/g"  | sed -n 6p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
DYN_OLDHX=$(xxd -s $(printf %d $DYN_ADDR) -l $(printf %d $DYN_SIZE) -g0 target | grep -oE "[0-9a-f]{32}" | tr -d '\n' | grep -oE ".{,4}$S_ADDR.{,4}")

# Compute .symtab section address and offset
SYM_ADDR=$(${PFX}readelf -a target | grep ".symtab  " -A1 | tr -d '\n' | sed "s/  \+/\n/g"  | sed -n 5p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
SYM_SIZE=$(${PFX}readelf -a target | grep ".symtab  " -A1 | tr -d '\n' | sed "s/  \+/\n/g"  | sed -n 6p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
SYM_OLDHX=$(xxd -s $(printf %d $SYM_ADDR) -l $(printf %d $SYM_SIZE) -g0 target | grep -oE "[0-9a-f]{32}" | tr -d '\n' | grep -oE ".{,4}$S_ADDR.{,4}")

# Patch .dynamic and .symtab sections of section following .text
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

# Update .text section with new .text data
${PFX}objcopy --update-section .text=target.text target target_patch &> objcopy-out.txt && mv target_patch target && rm target.text

# Compute the new addr of section after .text and patch it's symtab and dynamic addresses
S_NEW_ADDR=$(cat objcopy-out.txt | grep -oE "0x[0-9a-f]+$" | sed "s/0x//g" | tac -rs .. | echo "$(tr -d '\n')")
patch_symtab_and_dynamic_sections $S_NEW_ADDR && rm objcopy-out.txt

# Add our new function in Patch to the symtab
${PFX}objcopy --add-symbol __patch=".text:${TARGET_TEXT_SZ_ORIG},global,function" target target_patch && mv target_patch target

# Dump ELF data of final file and diff
${PFX}readelf -a target > re-target_pst.txt
diff -ur re-target_pre.txt re-target_pst.txt

# Print obj data of final file
echo "==== target objdump start ===="
${PFX}objdump -d target
echo "==== target objdump end ===="
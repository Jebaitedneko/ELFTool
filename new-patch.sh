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
NEXT_ADDR=$(printf %x $(($PATCH_TEXT_SZ)) | sed 's/^0*//;s/^/0x/')
echo "NEXT_ADDR: $NEXT_ADDR"

${PFX}objcopy --update-section .text=target.text target target_patch && mv target_patch target && rm target.text
${PFX}objcopy --add-symbol __patch=".text:${TARGET_TEXT_SZ_ORIG},function" target target_patch && mv target_patch target

# patch the section following .text
S_ADDR=$(readelf -a target | grep ".text  " -A1 | tr -d '\n' | sed "s/  \+/\n/g" | sed -n 4p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
S_OFF=$(readelf -a target | grep ".text  " -A1 | tr -d '\n' | sed "s/  \+/\n/g" | sed -n 6p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
S_ALIGN=0x16
RELOC=$(printf %x $((S_ADDR+S_OFF+16)) | sed 's/^0*//;s/^/0x/')
PATCH_SECTION=$(${PFX}readelf -a target | grep ".fini  " | grep -oE "\[.*\]" | sed "s/\[//g;s/\]//g" | tr -d '\n') # change section here (plt for arm)
./modelf target --section $PATCH_SECTION --addr $RELOC
mv modelf-out.elf target

${PFX}readelf -a target > re-target_pst.txt
diff -ur re-target_pre.txt re-target_pst.txt

echo "==== target objdump start ===="
${PFX}objdump -d target
echo "==== target objdump end ===="
PFX=

cat << EOF > target.c
#include <stdio.h>
int main(){int a=0;asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");printf("%d\n",a);return 0;}
EOF
# cat << EOF > target.c
# #include <stdio.h>
# int main(){return 1;}
# EOF
${PFX}gcc target.c -o target -g -Wall
${PFX}objcopy --dump-section .text=target.text target
TARGET_TEXT_SZ=0x$(printf %x $(stat -c '%s' target.text))
${PFX}readelf -a target > re-target_pre.txt

cat << EOF > patch.S
.text
.global __patch
__patch:
    nop
EOF
# cat << EOF > patch.S
# .text
# .global __patch
# __patch:
#     push   %rbp
#     mov    %rsp,%rbp
#     pop    %rbp
#     ret
# EOF
${PFX}as patch.S -o patch.o
${PFX}readelf -a patch.o > re-patch.txt

${PFX}objdump -d patch.o

${PFX}objcopy --dump-section .text=patch.text patch.o
cat patch.text >> target.text

${PFX}objcopy --update-section .text=target.text target target_patch && mv target_patch target
${PFX}objcopy --add-symbol __patch=".text:${TARGET_TEXT_SZ},function,global" target target_patch && mv target_patch target
# ${PFX}objcopy --adjust-section-vma .fini=0x1185 target target_patch && mv target_patch target

${PFX}readelf -a target > re-target_pst.txt
diff -ur re-target_pre.txt re-target_pst.txt

${PFX}objdump -d target
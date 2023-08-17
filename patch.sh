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
${PFX}gcc target.c -o target -g -Wall

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
${PFX}objcopy --dump-section .text=patch.text patch.o
${PFX}objcopy --add-section .patch=patch.text --set-section-flags .patch=code,readonly,alloc target patched
${PFX}readelf -a target > readelf-target-premodelf.txt
${PFX}readelf -a patched > readelf-patched-premodelf.txt

TARGET_ADDR=$(${PFX}readelf -a target | grep -E "\[.*\] .note.gnu.b" | grep -oE "[0-9a-f]{8}$"  | sed 's/^0*//;s/^/0x/' | tr -d '\n')
if [[ $TARGET_ADDR -gt 0 ]]; then
    echo ".note.gnu.build-id FOUND"
else
    TARGET_ADDR=$(${PFX}readelf -a target | grep -E "\[.*\] .note" | grep -oE "[0-9a-f]{8}$"  | sed 's/^0*//;s/^/0x/' | tr -d '\n')
fi

PATCHSZ=$(stat -c '%s' patch.text)
PATCH_SECTION=$(${PFX}readelf -a patched | grep patch | grep -oE "\[.*\]" | sed "s/\[//g;s/\]//g" | tr -d '\n')

NOTES_SEGMENT=$(${PFX}readelf -a patched | grep -E "[0-9a-f]{2}[[:space:]]*.note.gnu.b" | sed "s/.*\([0-9][0-9]\)\(.*\)/\1/g" | sed 's/^0*//' | tr -d '\n' )
if [[ $NOTES_SEGMENT -gt 0 ]]; then
    echo ".note.gnu.build-id FOUND"
else
    NOTES_SEGMENT=$(${PFX}readelf -a patched | grep -E "[0-9a-f]{2}[[:space:]]*.note" | sed "s/.*\([0-9][0-9]\)\(.*\)/\1/g" | tr -d '\n')
fi

echo -e "TARGET_ADDR: $TARGET_ADDR\nPATCHSZ: $PATCHSZ\nPATCH_SECTION: $PATCH_SECTION\nNOTES_SEGMENT: $NOTES_SEGMENT"

./modelf patched --section $PATCH_SECTION --addr $TARGET_ADDR
mv modelf-out.elf patched
./modelf patched --segment $NOTES_SEGMENT --type 1 --align 1 --flags 0x6 # --offset $TARGET_ADDR --vaddr $TARGET_ADDR --paddr $TARGET_ADDR --filesz $PATCHSZ --memsz $PATCHSZ
# .rodata,alloc,load,readonly,data,contents
mv modelf-out.elf patched
${PFX}readelf -a patched > readelf-patched-pstmodelf.txt
# diff -ur readelf-patched-premodelf.txt readelf-patched-pstmodelf.txt
diff -ur readelf-target-premodelf.txt readelf-patched-pstmodelf.txt
chmod +x patched

# clear
# ${PFX}readelf -a target > readelf-target-premodelf.txt
# ${PFX}objcopy --update-section .note.gnu.build-id=patch.text --set-section-flags .note.gnu.build-id=code,readonly,alloc target patched
# ./modelf patched --segment 8 --type 1
# mv modelf-out.elf patched
# ${PFX}readelf -a patched > readelf-patched-pstmodelf.txt
# diff -ur readelf-target-premodelf.txt readelf-patched-pstmodelf.txt
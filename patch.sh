#!/bin/bash

PFX=$1

# Prepare Target Binary
cat << EOF > target.c
#include <stdio.h>
int main(){int a=0;asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");printf("%d\n",a);return 0;}
EOF
if [ ${#2} -gt 1 ]; then
    echo Custom target binary
    echo
else
    ${PFX}gcc target.c -o target -g -Wall && rm target.c
fi

# Dump .text section from Target
${PFX}objcopy --dump-section .text=target.text target
TARGET_TEXT_SZ_ORIG=$(printf %x $(stat -c '%s' target.text) | sed 's/^0*//;s/^/0x/')
echo "-------------------------------------------------------"
echo "| TARGET_TEXT_SZ_ORIG: $TARGET_TEXT_SZ_ORIG"

# Dump ELF data from Target
${PFX}readelf -a target > re-target_pre.txt

# Print obj data of initial target file
${PFX}objdump -d target > od-target-initial.txt

if [ ${#PFX} -gt 1 ]; then
# Prepare Patch Code
cat << EOF > patch.S
.section .text
.globl __patch
.type __patch, @function
__patch:
    mov w0, #1
    mov w0, #1
    mov w0, #1
    mov w0, #1
    mov w0, #1
    ret
.size __patch, .-__patch
EOF
else
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
fi
${PFX}as -c patch.S -o patch.o && rm patch.S

# Dump ELF data from Patch
${PFX}readelf -a patch.o > re-patch.txt

# Print .text section from Patch
${PFX}objdump -d patch.o > od-patch.txt

# Dump .text section from Patch
${PFX}objcopy --dump-section .text=patch.text patch.o && rm patch.o
PATCH_TEXT_SZ=$(printf %x $(stat -c '%s' patch.text) | sed 's/^0*//;s/^/0x/')
echo "| PATCH_TEXT_SZ: $PATCH_TEXT_SZ"

# Merge .text section from Patch into Target
cat patch.text >> target.text && rm patch.text
TARGET_TEXT_SZ_PATCHED=0x$(printf %x $(stat -c '%s' target.text))
echo "| TARGET_TEXT_SZ_PATCHED: $TARGET_TEXT_SZ_PATCHED"
echo "-------------------------------------------------------"
echo

# [PRE-RUN] Update .text section with new .text data
${PFX}objcopy --update-section .text=target.text target target.temp &> objcopy-out.txt && rm target.temp
S_CNT=$(cat objcopy-out.txt | wc -l)
S_DATA=$(cat objcopy-out.txt | cut -f3 -d: | sed "s/.*section //g;s/lma //g;s/adjusted to //g;s/\n/ /g;s/ /\n/g")
rm objcopy-out.txt

i=0
SECTIONS=()
ADDRS_OLD=()
ADDRS_NEW=()
while [ $i -lt $S_CNT ]; do

    i=$((i+1))

    SECTIONS+=( $(echo -e "$S_DATA" | head -n $((3*$i)) | tail -n3 | head -n1 | tail -n1) )

    ADDR_OLD_TMP=$(echo -e "$S_DATA" | head -n $((3*$i)) | tail -n3 | head -n2 | tail -n1)
    ADDR_OLD_TMP_SZ=$(echo $ADDR_OLD_TMP | tr -d '\n' | wc -c)
    if [ $(($ADDR_OLD_TMP_SZ%2)) -ne 0 ]; then
        ADDR_OLD_TMP=$( echo $ADDR_OLD_TMP | sed "s/0x/0x0/g" )
    fi
    ADDRS_OLD+=( $ADDR_OLD_TMP )

    ADDR_NEW_TMP=$(echo -e "$S_DATA" | head -n $((3*$i)) | tail -n3 | head -n3 | tail -n1)
    ADDR_NEW_TMP_SZ=$(echo $ADDR_NEW_TMP | tr -d '\n' | wc -c)
    if [ $(($ADDR_NEW_TMP_SZ%2)) -ne 0 ]; then
        ADDR_NEW_TMP=$( echo $ADDR_NEW_TMP | sed "s/0x/0x0/g" )
    fi
    ADDRS_NEW+=( $ADDR_NEW_TMP )

done

echo "-------------------------------------------------------"
echo "| SECTIONS: ${SECTIONS[@]}"
echo "| ADDRS_OLD: ${ADDRS_OLD[@]}"
echo "| ADDRS_NEW: ${ADDRS_NEW[@]}"

SECTION_IDS=()
for section in ${SECTIONS[@]}; do
    PATCH_SECTION=$(${PFX}readelf -t target | grep -E "\[[0-9a-f]{2}\] ${section}$| \[[0-9a-f]{2}\] $(echo ${section} | sed "s/^./_/g")$" | grep -oE "\[.*\]" | sed "s/\[//g;s/\]//g" | tr -d '\n')
    SECTION_IDS+=( $PATCH_SECTION )
done
echo "| SECTION_IDS: ${SECTION_IDS[@]}"

SECTION_IDS_LE_HEXES=()
for id in ${SECTION_IDS[@]}; do
    SECTION_IDS_HEX=$(printf %x $id)
    if [ $((${#SECTION_IDS_HEX}%2)) -ne 0 ]; then
        SECTION_IDS_HEX=$( echo $SECTION_IDS_HEX | sed "s/^/0/g" )
    fi
    if [ ${#SECTION_IDS_HEX} -le 2 ]; then
        SECTION_IDS_HEX=$( echo $SECTION_IDS_HEX | sed "s/^/00/g" )
    fi
    SECTION_IDS_LE_HEXES+=( $(echo $SECTION_IDS_HEX | tac -rs .. | echo "$(tr -d '\n')") )
done
echo "| SECTION_IDS_LE_HEXES: ${SECTION_IDS_LE_HEXES[@]}"
echo "-------------------------------------------------------"
echo

# Patch .dynamic and .symtab sections of section following .text
function patch_symtab_and_dynamic_sections() {

    echo "| MATCH ADDR: ${5}${4}${3}${1} SHIFT: $1 (LE) -> $2 (LE) SECTION ID: $3 (LE)"

    # Compute .dynamic section address and offset
    DYN_ADDR=$(${PFX}readelf -t target | grep -E "\[[0-9a-f ]{2}\] .dynamic" -A2  | tr -d '\n' | tr -s " " | tr ' ' '\n' | sed -n 6p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
    DYN_SIZE=$(${PFX}readelf -t target | grep -E "\[[0-9a-f ]{2}\] .dynamic" -A2  | tr -d '\n' | tr -s " " | tr ' ' '\n' | sed -n 8p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
    echo "| Dynamic Section at $DYN_ADDR of size $DYN_SIZE"
    xxd -s $(printf %d $DYN_ADDR) -l $(printf %d $DYN_SIZE) -g0 target | grep -oE "[0-9a-f]{32}" | tr -d '\n' | grep -oE [0-9a-f]{32} > hex-dyn.txt

    DYN_OLDHX=$(xxd -s $(printf %d $DYN_ADDR) -l $(printf %d $DYN_SIZE) -g0 target | grep -oE "[0-9a-f]{32}" | tr -d '\n' | grep -oE [0-9a-f]{32} | grep -oE ".{,16}$1.{,12}")
    if [ ${#DYN_OLDHX} -gt 2 ]; then
        DYN_PATCH=$(echo $DYN_OLDHX | sed "s/$1/$2/g")
        echo "| DYN_OLDHX: $DYN_OLDHX"
        echo "| DYN_PATCH: $DYN_PATCH"
        DYN_PATCH=$(echo $DYN_PATCH | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
        DYN_OLDHX=$(echo $DYN_OLDHX | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
        sed -i "s|$DYN_OLDHX|$DYN_PATCH|g" target
    fi

    # Compute .symtab section address and offset
    SYM_ADDR=$(${PFX}readelf -t target | grep -E "\[[0-9a-f ]{2}\] .symtab" -A2  | tr -d '\n' | tr -s " " | tr ' ' '\n' | sed -n 6p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
    SYM_SIZE=$(${PFX}readelf -t target | grep -E "\[[0-9a-f ]{2}\] .symtab" -A2  | tr -d '\n' | tr -s " " | tr ' ' '\n' | sed -n 8p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
    echo "| Symtab Section at $SYM_ADDR of size $SYM_SIZE"
    xxd -s $(printf %d $SYM_ADDR) -l $(printf %d $SYM_ADDR) -g0 target | grep -oE "[0-9a-f]{32}" | tr -d '\n' | grep -oE [0-9a-f]{48} > hex-sym.txt

    SYM_OLDHX=$(xxd -s $(printf %d $SYM_ADDR) -l $(printf %d $SYM_SIZE) -g0 target | grep -oE "[0-9a-f]{32}" | tr -d '\n' | grep -oE "[0-9a-f]{48}" | grep -oE ".{,8}${5}${4}${3}${1}.{,16}")
    if [ ${#SYM_OLDHX} -gt 2 ]; then
        SYM_PATCH=$(echo $SYM_OLDHX | sed "s/$1/$2/g")
        echo "| SYM_OLDHX: $SYM_OLDHX"
        echo "| SYM_PATCH: $SYM_PATCH"
        SYM_PATCH=$(echo $SYM_PATCH | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
        SYM_OLDHX=$(echo $SYM_OLDHX | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
        sed -i "s|$SYM_OLDHX|$SYM_PATCH|g" target
    fi
}

# Update .text section with new .text data
${PFX}objcopy --update-section .text=target.text target target_patch && mv target_patch target && rm target.text

# Add our new function in Patch to the symtab
${PFX}objcopy --add-symbol __patch=".text:${TARGET_TEXT_SZ_ORIG},global,function" target target_patch && mv target_patch target

i=0
while [ $i -lt $S_CNT ]; do
    echo
    echo "+ SYMTAB + DYNAMIC PATCHING"
    echo "| SECTIONS: ${SECTIONS[$i]}"
    # Compute the new addr of section after .text and patch it's symtab and dynamic addresses
    S_OLD_ADDR=$(echo ${ADDRS_OLD[$i]} | sed "s/0x//g" | tac -rs .. | echo "$(tr -d '\n')")
    S_NEW_ADDR=$(echo ${ADDRS_NEW[$i]} | sed "s/0x//g" | tac -rs .. | echo "$(tr -d '\n')")
    echo "|-> LOCAL | DEFAULT"
    patch_symtab_and_dynamic_sections $S_OLD_ADDR $S_NEW_ADDR ${SECTION_IDS_LE_HEXES[$i]} "00" "03" # LOCAL  DEFAULT
    echo "|-> GLOBAL | HIDDEN"
    patch_symtab_and_dynamic_sections $S_OLD_ADDR $S_NEW_ADDR ${SECTION_IDS_LE_HEXES[$i]} "02" "12" # GLOBAL HIDDEN
    i=$((i+1))
done
echo

SECTION_HDR_START=$(readelf -h target | grep -E "Start of section headers"  | cut -f2 -d: | sed 's/^[t ]*//g;s/ .*//g')
SECTION_HDR_WIDTH=$(readelf -h target | grep -E "Size of section headers"   | cut -f2 -d: | sed 's/^[t ]*//g;s/ .*//g')
SECTION_HDR_COUNT=$(readelf -h target | grep -E "Number of section headers" | cut -f2 -d: | sed 's/^[t ]*//g;s/ .*//g')
xxd -g0 -s $SECTION_HDR_START -l $(($SECTION_HDR_COUNT*$SECTION_HDR_WIDTH)) target | grep -oE "[0-9a-f]{32}" | tr -d '\n' > hex-section.txt

i=0
while [ $i -lt $S_CNT ]; do
    # patch section header address, set VMA=LMA
    echo "+ SECTION HEADER VMA=LMA PATCHING"
    echo "| SECTIONS: ${SECTIONS[$i]}"
    S_OLD_ADDR=$(echo ${ADDRS_OLD[$i]} | sed "s/0x//g" | tac -rs .. | echo "$(tr -d '\n')")
    S_NEW_ADDR=$(echo ${ADDRS_NEW[$i]} | sed "s/0x//g" | tac -rs .. | echo "$(tr -d '\n')")
    SH_OLD_HEX=$(echo "${S_OLD_ADDR}000000000000${S_NEW_ADDR}")
    FUZZY_END_HEX=$(cat hex-section.txt | grep -oE "${S_OLD_ADDR}000000000000[0-9a-f]{4}" | grep -oE "[0-9a-f]{4}$")
    if [ ${#FUZZY_END_HEX} -gt 0 ]; then
        echo "| FZEHSZ: ${#FUZZY_END_HEX}"
        SH_MATCH=$(echo "$(echo $SH_OLD_HEX | grep -oE "^[0-9a-f]{16}")$FUZZY_END_HEX" | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
        SH_PATCH=$(echo "${FUZZY_END_HEX}000000000000${FUZZY_END_HEX}" | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
    else
        SH_MATCH=$(echo "${S_OLD_ADDR}000000000000${S_NEW_ADDR}" | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
        SH_PATCH=$(echo "${S_NEW_ADDR}000000000000${S_NEW_ADDR}" | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
    fi
    echo "| SH_MATCH: $SH_MATCH"
    echo "| SH_PATCH: $SH_PATCH"
    echo
    sed -i "s|$SH_MATCH|$SH_PATCH|g" target
    i=$((i+1))
done

rm hex-section.txt

# Dump ELF data of final file and diff
${PFX}readelf -a target > re-target_pst.txt
diff -ur re-target_pre.txt re-target_pst.txt > re-diff.txt

# Print obj data of final file
${PFX}objdump -d target > od-target-final.txt
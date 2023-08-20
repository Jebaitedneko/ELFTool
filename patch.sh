#!/bin/bash

COMPILER=$1 # clang gcc
ARCH=$2 # x86_64 aarch64

if [[ $COMPILER =~ "clang" ]]; then
    PFX=${COMPILER/clang/llvm-}
fi

if [[ $COMPILER =~ "gcc" ]]; then
    PFX=${COMPILER/gcc/}
fi

# Prepare Target Binary
cat << EOF > target.c
#include <stdio.h>
int main(){int a=0;asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");printf("%d\n",a);return 0;}
EOF
if [ ${#3} -gt 1 ]; then
    echo Custom target binary
    echo
else
    $COMPILER target.c -o target -g -Wall && rm target.c
fi

# Dump .text section from Target
${PFX}objcopy --dump-section .text=target.text target
TARGET_TEXT_SZ_ORIG=$(printf %x $(stat -c '%s' target.text))
if [ $((${#TARGET_TEXT_SZ_ORIG}%2)) -ne 0 ]; then
    TARGET_TEXT_SZ_ORIG=$( echo $TARGET_TEXT_SZ_ORIG | sed "s/^/0/g" )
fi
if [ ${#TARGET_TEXT_SZ_ORIG} -le 2 ]; then
    TARGET_TEXT_SZ_ORIG=$( echo $TARGET_TEXT_SZ_ORIG | sed "s/^/00/g" )
fi
if [ ${#TARGET_TEXT_SZ_ORIG} -le 4 ]; then
    TARGET_TEXT_SZ_ORIG=$( echo $TARGET_TEXT_SZ_ORIG | sed "s/^/00/g" )
fi
if [ ${#TARGET_TEXT_SZ_ORIG} -le 6 ]; then
    TARGET_TEXT_SZ_ORIG=$( echo $TARGET_TEXT_SZ_ORIG | sed "s/^/00/g" )
fi
echo "-------------------------------------------------------"
echo "| TARGET_TEXT_SZ_ORIG: $TARGET_TEXT_SZ_ORIG"

# Dump ELF data from Target
${PFX}readelf -a target > re-target_pre.txt

# Print obj data of initial target file
${PFX}objdump -d target > od-target-initial.txt

if [[ $ARCH =~ "aarch64" ]]; then
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
if [[ $COMPILER =~ "clang" ]]; then
    # $COMPILER -c patch.S -o patch.o && rm patch.S
    aarch64-linux-gnu-as -c patch.S -o patch.o && rm patch.S
else
    ${PFX}as -c patch.S -o patch.o && rm patch.S
fi

# Dump ELF data from Patch
${PFX}readelf -a patch.o > re-patch.txt

# Print .text section from Patch
${PFX}objdump -d patch.o > od-patch.txt

# Dump .text section from Patch
${PFX}objcopy --dump-section .text=patch.text patch.o && rm patch.o
PATCH_TEXT_SZ=$(printf %x $(stat -c '%s' patch.text))
if [ $((${#PATCH_TEXT_SZ}%2)) -ne 0 ]; then
    PATCH_TEXT_SZ=$( echo $PATCH_TEXT_SZ | sed "s/^/0/g" )
fi
if [ ${#PATCH_TEXT_SZ} -le 2 ]; then
    PATCH_TEXT_SZ=$( echo $PATCH_TEXT_SZ | sed "s/^/00/g" )
fi
if [ ${#PATCH_TEXT_SZ} -le 4 ]; then
    PATCH_TEXT_SZ=$( echo $PATCH_TEXT_SZ | sed "s/^/00/g" )
fi
if [ ${#PATCH_TEXT_SZ} -le 6 ]; then
    PATCH_TEXT_SZ=$( echo $PATCH_TEXT_SZ | sed "s/^/00/g" )
fi
echo "| PATCH_TEXT_SZ: $PATCH_TEXT_SZ"

# Merge .text section from Patch into Target
cat patch.text >> target.text && rm patch.text
TARGET_TEXT_SZ_PATCHED=$(printf %x $(stat -c '%s' target.text))
if [ $((${#TARGET_TEXT_SZ_PATCHED}%2)) -ne 0 ]; then
    TARGET_TEXT_SZ_PATCHED=$( echo $TARGET_TEXT_SZ_PATCHED | sed "s/^/0/g" )
fi
if [ ${#TARGET_TEXT_SZ_PATCHED} -le 2 ]; then
    TARGET_TEXT_SZ_PATCHED=$( echo $TARGET_TEXT_SZ_PATCHED | sed "s/^/00/g" )
fi
if [ ${#TARGET_TEXT_SZ_PATCHED} -le 4 ]; then
    TARGET_TEXT_SZ_PATCHED=$( echo $TARGET_TEXT_SZ_PATCHED | sed "s/^/00/g" )
fi
if [ ${#TARGET_TEXT_SZ_PATCHED} -le 6 ]; then
    TARGET_TEXT_SZ_PATCHED=$( echo $TARGET_TEXT_SZ_PATCHED | sed "s/^/00/g" )
fi
echo "| TARGET_TEXT_SZ_PATCHED: $TARGET_TEXT_SZ_PATCHED"
echo "-------------------------------------------------------"
echo

if [[ $COMPILER =~ "clang" ]]; then

    TXT_ADDR=$(${PFX}readelf -t target | grep -E "\[[0-9a-f ]{2}\] .text" -A2 | sed "s/\[ /\[/g" | tr -d '\n' | tr -s " " | tr ' ' '\n' | sed -n 6p | tr -d '\n')
    if [ $((${#TXT_ADDR}%2)) -ne 0 ]; then
        TXT_ADDR=$( echo $TXT_ADDR | sed "s/^/0/g" )
    fi
    if [ ${#TXT_ADDR} -le 2 ]; then
        TXT_ADDR=$( echo $TXT_ADDR | sed "s/^/00/g" )
    fi
    if [ ${#TXT_ADDR} -le 4 ]; then
        TXT_ADDR=$( echo $TXT_ADDR | sed "s/^/00/g" )
    fi
    if [ ${#TXT_ADDR} -le 6 ]; then
        TXT_ADDR=$( echo $TXT_ADDR | sed "s/^/00/g" )
    fi
    TXT_ADDR_LE=$(echo $TXT_ADDR | tac -rs .. | echo "$(tr -d '\n')")
    echo "TXT_ADDR: $TXT_ADDR"
    echo "TXT_ADDR_LE: $TXT_ADDR_LE"
    echo
    TARGET_TEXT_SZ_ORIG_LE=$(echo "${TARGET_TEXT_SZ_ORIG}" | tac -rs .. | echo "$(tr -d '\n')")
    echo "TARGET_TEXT_SZ_ORIG_LE: $TARGET_TEXT_SZ_ORIG_LE"
    TARGET_TEXT_SZ_PATCHED_LE=$(echo "${TARGET_TEXT_SZ_PATCHED}" | tac -rs .. | echo "$(tr -d '\n')")
    echo "TARGET_TEXT_SZ_PATCHED_LE: $TARGET_TEXT_SZ_PATCHED_LE"
    echo
    # 00b00200 00000000 00b00200 00000000 f8000500
    xxd -g0 target | grep -oE "[0-9a-f]{32}" | tr -d '\n' > hex-target.txt
    TXT_MATCH=$(cat hex-target.txt | grep -oE "${TXT_ADDR_LE}00000000${TXT_ADDR_LE}00000000${TARGET_TEXT_SZ_ORIG_LE}" | head -n1 | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
    TXT_PATCH=$(echo "${TXT_ADDR_LE}00000000${TXT_ADDR_LE}00000000${TARGET_TEXT_SZ_PATCHED_LE}" | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
    echo "TXT_MATCH: $TXT_MATCH"
    echo "TXT_PATCH: $TXT_PATCH"
    sed -i "s|$TXT_MATCH|$TXT_PATCH|g" target
    rm hex-target.txt
    echo

fi

# [PRE-RUN] Update .text section with new .text data
${PFX}objcopy --update-section .text=target.text target target.temp &> objcopy-out.txt && rm target.temp
S_CNT=$(cat objcopy-out.txt | wc -l)
S_DATA=$(cat objcopy-out.txt | cut -f3 -d: | sed "s/.*section //g;s/lma //g;s/adjusted to //g;s/\n/ /g;s/ /\n/g")

if [[ $COMPILER =~ "clang" ]]; then
    aarch64-linux-gnu-objcopy --update-section .text=target.text target target.temp &> objcopy-out.txt && rm target.temp
    S_CNT=$(cat objcopy-out.txt | wc -l)
    S_DATA=$(cat objcopy-out.txt | cut -f3 -d: | sed "s/.*section //g;s/lma //g;s/adjusted to //g;s/\n/ /g;s/ /\n/g")
fi
rm objcopy-out.txt

i=0
SECTIONS=()
ADDRS_OLD=()
ADDRS_NEW=()
while [ $i -lt $S_CNT ]; do

    i=$((i+1))

    SECTIONS+=( $(echo -e "$S_DATA" | head -n $((3*$i)) | tail -n3 | head -n1 | tail -n1) )

    ADDR_OLD_TMP=$(echo -e "$S_DATA" | head -n $((3*$i)) | tail -n3 | head -n2 | tail -n1 | sed "s/^0x//g")
    if [ $((${#ADDR_OLD_TMP}%2)) -ne 0 ]; then
        ADDR_OLD_TMP=$( echo $ADDR_OLD_TMP | sed "s/^/0/g" )
    fi
    if [ ${#ADDR_OLD_TMP} -le 2 ]; then
        ADDR_OLD_TMP=$( echo $ADDR_OLD_TMP | sed "s/^/00/g" )
    fi
    if [ ${#ADDR_OLD_TMP} -le 4 ]; then
        ADDR_OLD_TMP=$( echo $ADDR_OLD_TMP | sed "s/^/00/g" )
    fi
    if [ ${#ADDR_OLD_TMP} -le 6 ]; then
        ADDR_OLD_TMP=$( echo $ADDR_OLD_TMP | sed "s/^/00/g" )
    fi
    if [ ${#ADDR_OLD_TMP} -lt 8 ]; then
        ADDR_OLD_TMP=$( echo $ADDR_OLD_TMP | sed "s/^/00/g" )
    fi
    # ADDR_OLD_TMP=$(echo $ADDR_OLD_TMP | sed 's/^/0x/')
    ADDRS_OLD+=( $ADDR_OLD_TMP )

    ADDR_NEW_TMP=$(echo -e "$S_DATA" | head -n $((3*$i)) | tail -n3 | head -n3 | tail -n1 | sed "s/^0x//g")
    if [ $((${#ADDR_NEW_TMP}%2)) -ne 0 ]; then
        ADDR_NEW_TMP=$( echo $ADDR_NEW_TMP | sed "s/^/0/g" )
    fi
    if [ ${#ADDR_NEW_TMP} -le 2 ]; then
        ADDR_NEW_TMP=$( echo $ADDR_NEW_TMP | sed "s/^/00/g" )
    fi
    if [ ${#ADDR_NEW_TMP} -le 4 ]; then
        ADDR_NEW_TMP=$( echo $ADDR_NEW_TMP | sed "s/^/00/g" )
    fi
    if [ ${#ADDR_NEW_TMP} -le 6 ]; then
        ADDR_NEW_TMP=$( echo $ADDR_NEW_TMP | sed "s/^/00/g" )
    fi
    if [ ${#ADDR_NEW_TMP} -lt 8 ]; then
        ADDR_NEW_TMP=$( echo $ADDR_NEW_TMP | sed "s/^/00/g" )
    fi
    # ADDR_NEW_TMP=$(echo $ADDR_NEW_TMP | sed 's/^/0x/')
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
    # clamped to 4 according to section header spec (8 bytes)
    SECTION_IDS_LE_HEXES+=( $(echo $SECTION_IDS_HEX | tac -rs .. | echo "$(tr -d '\n')") )
done
echo "| SECTION_IDS_LE_HEXES: ${SECTION_IDS_LE_HEXES[@]}"
echo "-------------------------------------------------------"
echo

# Patch .dynamic and .symtab sections of section following .text
function patch_symtab_and_dynamic_sections() {

    echo "| S_OLD_ADDR: $1"
    echo "| S_NEW_ADDR: $2"
    echo "| SECTION_IDS_LE_HEXES[i]: $3"
    echo "| ST_OTHER: $4"
    echo "| ST_INFO: $5"
    echo "| MATCH ADDR: ${5}${4}${3}${1} SHIFT: $1 (LE) -> $2 (LE) SECTION ID: $3 (LE)"

    # Compute .dynamic section address and offset
    if [[ $COMPILER =~ "clang" ]]; then
        SIZE_SELECT=7
    else
        SIZE_SELECT=8
    fi
    DYN_ADDR=$(${PFX}readelf -t target | grep -E "\[[0-9a-f ]{2}\] .dynamic" -A2 | sed "s/\[ /\[/g" | tr -d '\n' | tr -s " " | tr ' ' '\n' | sed -n 6p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
    DYN_SIZE=$(${PFX}readelf -t target | grep -E "\[[0-9a-f ]{2}\] .dynamic" -A2 | sed "s/\[ /\[/g" | tr -d '\n' | tr -s " " | tr ' ' '\n' | sed -n ${SIZE_SELECT}p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
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
    if [[ $COMPILER =~ "clang" ]]; then
        SIZE_SELECT=7
    else
        SIZE_SELECT=8
    fi
    SYM_ADDR=$(${PFX}readelf -t target | grep -E "\[[0-9a-f ]{2}\] .symtab" -A2 | sed "s/\[ /\[/g" | tr -d '\n' | tr -s " " | tr ' ' '\n' | sed -n 6p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
    SYM_SIZE=$(${PFX}readelf -t target | grep -E "\[[0-9a-f ]{2}\] .symtab" -A2 | sed "s/\[ /\[/g" | tr -d '\n' | tr -s " " | tr ' ' '\n' | sed -n ${SIZE_SELECT}p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
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

    # Compute .dynsym section address and offset
    if [[ $COMPILER =~ "clang" ]]; then
        SIZE_SELECT=7
    else
        SIZE_SELECT=8
    fi
    DYNSYM_ADDR=$(${PFX}readelf -t target | grep -E "\[[0-9a-f ]{2}\] .dynsym" -A2 | sed "s/\[ /\[/g" | tr -d '\n' | tr -s " " | tr ' ' '\n' | sed -n 6p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
    DYNSYM_SIZE=$(${PFX}readelf -t target | grep -E "\[[0-9a-f ]{2}\] .dynsym" -A2 | sed "s/\[ /\[/g" | tr -d '\n' | tr -s " " | tr ' ' '\n' | sed -n ${SIZE_SELECT}p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
    echo "| Dynsym Section at $DYNSYM_ADDR of size $DYNSYM_SIZE"
    xxd -s $(printf %d $DYNSYM_ADDR) -l $(printf %d $DYNSYM_SIZE) -g0 target | grep -oE "[0-9a-f]{32}" | tr -d '\n' | grep -oE [0-9a-f]{48} > hex-dynsym.txt

    DYNSYM_OLDHX=$(xxd -s $(printf %d $DYNSYM_ADDR) -l $(printf %d $DYNSYM_SIZE) -g0 target | grep -oE "[0-9a-f]{32}" | tr -d '\n' | grep -oE "[0-9a-f]{48}" | grep -oE ".{,12}${3}${1}.{,24}")
    if [ ${#DYNSYM_OLDHX} -gt 2 ]; then
        DYNSYM_PATCH=$(echo $DYNSYM_OLDHX | sed "s/$1/$2/g")
        echo "| DYNSYM_OLDHX: $DYNSYM_OLDHX"
        echo "| DYNSYM_PATCH: $DYNSYM_PATCH"
        DYNSYM_PATCH=$(echo $DYNSYM_PATCH | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
        DYNSYM_OLDHX=$(echo $DYNSYM_OLDHX | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
        sed -i "s|$DYNSYM_OLDHX|$DYNSYM_PATCH|g" target
    fi

    START_SEC=$(cat hex-dynsym.txt | grep -oE "^.{,12}1100.{,32}$" | cut -c17- | grep -oE "^[0-9a-f]{10}" | head -n1 | tail -n1 | tac -rs .. | tr -d '\n') # __start_section
    STOPS_SEC=$(cat hex-dynsym.txt | grep -oE "^.{,12}1100.{,32}$" | cut -c17- | grep -oE "^[0-9a-f]{10}" | head -n2 | tail -n1 | tac -rs .. | tr -d '\n') # __stop_section
    echo "START_SEC: $START_SEC"
    echo "STOPS_SEC: $STOPS_SEC"
    DELTA=$(printf %x $((0x$STOPS_SEC-0x$START_SEC)))
    echo "DELTA: $DELTA"

    STOP_ADDR=$(printf %x $(($(echo $2 | tac -rs .. | tr -d '\n' | sed "s/^/0x/g")+0x$DELTA)))
    if [ $((${#STOP_ADDR}%2)) -ne 0 ]; then
        STOP_ADDR=$( echo $STOP_ADDR | sed "s/^/0/g" )
    fi
    if [ ${#STOP_ADDR} -le 2 ]; then
        STOP_ADDR=$( echo $STOP_ADDR | sed "s/^/00/g" )
    fi
    if [ ${#STOP_ADDR} -le 4 ]; then
        STOP_ADDR=$( echo $STOP_ADDR | sed "s/^/00/g" )
    fi
    if [ ${#STOP_ADDR} -le 6 ]; then
        STOP_ADDR=$( echo $STOP_ADDR | sed "s/^/00/g" )
    fi
    if [ ${#STOP_ADDR} -lt 8 ]; then
        STOP_ADDR=$( echo $STOP_ADDR | sed "s/^/00/g" )
    fi

    NEW_ADDR=$(printf %x $((0x$STOP_ADDR+0x$DELTA)))
    if [ $((${#NEW_ADDR}%2)) -ne 0 ]; then
        NEW_ADDR=$( echo $NEW_ADDR | sed "s/^/0/g" )
    fi
    if [ ${#NEW_ADDR} -le 2 ]; then
        NEW_ADDR=$( echo $NEW_ADDR | sed "s/^/00/g" )
    fi
    if [ ${#NEW_ADDR} -le 4 ]; then
        NEW_ADDR=$( echo $NEW_ADDR | sed "s/^/00/g" )
    fi
    if [ ${#NEW_ADDR} -le 6 ]; then
        NEW_ADDR=$( echo $NEW_ADDR | sed "s/^/00/g" )
    fi
    if [ ${#NEW_ADDR} -lt 8 ]; then
        NEW_ADDR=$( echo $NEW_ADDR | sed "s/^/00/g" )
    fi
    STOP_ADDR=$(echo $STOP_ADDR | tac -rs .. | tr -d '\n')
    NEW_ADDR=$(echo $NEW_ADDR | tac -rs .. | tr -d '\n')
    echo "STOP_ADDR: $STOP_ADDR"
    echo "NEW_ADDR : $NEW_ADDR"

    DYNSYM_OLDHX=$(xxd -s $(printf %d $DYNSYM_ADDR) -l $(printf %d $DYNSYM_SIZE) -g0 target | grep -oE "[0-9a-f]{32}" | tr -d '\n' | grep -oE "[0-9a-f]{48}" | grep -oE ".{,12}${3}${STOP_ADDR}.{,24}")
    if [ ${#DYNSYM_OLDHX} -gt 2 ]; then
        echo "| patching __stop_symbol"
        DYNSYM_PATCH=$(echo $DYNSYM_OLDHX | sed "s/${STOP_ADDR}/${NEW_ADDR}/g")
        echo "| DYNSYM_OLDHX: $DYNSYM_OLDHX"
        echo "| DYNSYM_PATCH: $DYNSYM_PATCH"
        DYNSYM_PATCH=$(echo $DYNSYM_PATCH | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
        DYNSYM_OLDHX=$(echo $DYNSYM_OLDHX | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
        sed -i "s|$DYNSYM_OLDHX|$DYNSYM_PATCH|g" target
    fi
}

# Update .text section with new .text data
${PFX}objcopy --update-section .text=target.text target target_patch && mv target_patch target && rm target.text

# Add our new function in Patch to the symtab
TARGET_TEXT_SZ_ORIG_HEX=$(echo $TARGET_TEXT_SZ_ORIG | sed "s/^/0x/g")
${PFX}objcopy --add-symbol __patch=".text:${TARGET_TEXT_SZ_ORIG_HEX},global,function" target target_patch && mv target_patch target

i=0
while [ $i -lt $S_CNT ]; do
    echo
    echo "+ SYMTAB + DYNAMIC PATCHING"
    echo "| SECTIONS: ${SECTIONS[$i]}"
    # Compute the new addr of section after .text and patch it's symtab and dynamic addresses
    # These are 16 bytes everywhere.
    S_OLD_ADDR=$(echo ${ADDRS_OLD[$i]} | tac -rs .. | echo "$(tr -d '\n')")
    S_NEW_ADDR=$(echo ${ADDRS_NEW[$i]} | tac -rs .. | echo "$(tr -d '\n')")
    echo "|-> LOCAL | DEFAULT"
    patch_symtab_and_dynamic_sections $S_OLD_ADDR $S_NEW_ADDR ${SECTION_IDS_LE_HEXES[$i]} "00" "03" # LOCAL  DEFAULT
    echo "|-> GLOBAL | HIDDEN"
    patch_symtab_and_dynamic_sections $S_OLD_ADDR $S_NEW_ADDR ${SECTION_IDS_LE_HEXES[$i]} "02" "12" # GLOBAL HIDDEN
    i=$((i+1))
done
echo

SECTION_HDR_START=$(${PFX}readelf -h target | grep -E "Start of section headers"  | cut -f2 -d: | sed 's/^[t ]*//g;s/ .*//g')
SECTION_HDR_WIDTH=$(${PFX}readelf -h target | grep -E "Size of section headers"   | cut -f2 -d: | sed 's/^[t ]*//g;s/ .*//g')
SECTION_HDR_COUNT=$(${PFX}readelf -h target | grep -E "Number of section headers" | cut -f2 -d: | sed 's/^[t ]*//g;s/ .*//g')
xxd -g0 -s $SECTION_HDR_START -l $(($SECTION_HDR_COUNT*$SECTION_HDR_WIDTH)) target | grep -oE "[0-9a-f]{32}" | tr -d '\n' > hex-section.txt

i=0
while [ $i -lt $S_CNT ]; do
    # patch section header address, set VMA=LMA
    echo "+ SECTION HEADER VMA=LMA PATCHING"
    echo "| SECTIONS: ${SECTIONS[$i]}"
    S_OLD_ADDR=$(echo ${ADDRS_OLD[$i]} | tac -rs .. | echo "$(tr -d '\n')")
    S_NEW_ADDR=$(echo ${ADDRS_NEW[$i]} | tac -rs .. | echo "$(tr -d '\n')")
    echo "| S_OLD_ADDR: $S_OLD_ADDR"
    echo "| S_NEW_ADDR: $S_NEW_ADDR"
    # 00b10700 00000000 00b10700
    SH_OLD_HEX=$(echo "${S_OLD_ADDR}00000000${S_NEW_ADDR}")
    FUZZY_END_HEX=$(cat hex-section.txt | grep -oE "${S_OLD_ADDR}00000000[0-9a-f]{8}" | grep -oE "[0-9a-f]{8}$")
    if [ ${#FUZZY_END_HEX} -gt 0 ]; then
        echo "| FUZZY_END_HEX: ${FUZZY_END_HEX}"
        echo "| FUZZY_END_HEX_SZ: ${#FUZZY_END_HEX}"
        SH_MATCH=$(echo "$(echo $SH_OLD_HEX | grep -oE "^[0-9a-f]{16}")$FUZZY_END_HEX" | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
        SH_PATCH=$(echo "${FUZZY_END_HEX}00000000${FUZZY_END_HEX}" | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
        if [[ $COMPILER =~ "clang" ]]; then
            SH_PATCH=$(echo "${S_NEW_ADDR}00000000${S_NEW_ADDR}" | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
        fi
    else
        SH_MATCH=$(echo "${S_OLD_ADDR}00000000${S_NEW_ADDR}" | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
        SH_PATCH=$(echo "${S_NEW_ADDR}00000000${S_NEW_ADDR}" | sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g")
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

diff -ur <(cat od-target-initial.txt) <(cat od-target-final.txt) > od-diff.txt
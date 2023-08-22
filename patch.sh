#!/bin/bash

COMPILER=$1 # clang gcc
ARCH=$2 # x86_64 aarch64

if [[ $COMPILER =~ "clang" ]]; then
    PFX=$(echo "$COMPILER" | sed "s/clang$/llvm-/g")
fi

if [[ $COMPILER =~ "gcc" ]]; then
    PFX=$(echo "$COMPILER" | sed "s/gcc$//g")
fi

if [[ $ARCH =~ "aarch64" && $COMPILER =~ "clang" ]]; then
    COMPILER="${COMPILER} --target=aarch64-linux-gnu -fuse-ld=lld"
fi

function pad_variable_to_size() {
    temp=$1
    size=$2
    if [ $((${#temp}%2)) -ne 0 ]; then
        temp=$( echo "$temp" | sed "s/^/0/g" )
    fi
    i=2
    while [ $i -lt "$size" ]; do
        if [ ${#temp} -lt $i ]; then
            temp=$( echo "$temp" | sed "s/^/00/g" )
        fi
        i=$((i+2))
    done
    if [ ${#temp} -lt "$size" ]; then
        temp=$( echo "$temp" | sed "s/^/00/g" )
    fi
    echo "$temp"
}

function pad_variable_to_size_at_end() {
    temp=$1
    size=$2
    if [ $((${#temp}%2)) -ne 0 ]; then
        temp=$( echo "$temp" | sed "s/$/0/g" )
    fi
    i=2
    while [ $i -lt "$size" ]; do
        if [ ${#temp} -lt $i ]; then
            temp=$( echo "$temp" | sed "s/$/00/g" )
        fi
        i=$((i+2))
    done
    if [ ${#temp} -lt "$size" ]; then
        temp=$( echo "$temp" | sed "s/$/00/g" )
    fi
    echo "$temp"
}

function rawhex_to_escaped_hex() {
    sed "s/\([0-9a-f][0-9a-f]\)/\1 /g;s/ /\\\x/g;s/^/\\\x/g;s/\\\x$//g"
}

function change_endianness() {
    tac -rs .. | tr -d '\n'
}

# Prepare Target Binary
cat << EOF > target.c
#include <stdio.h>
#define ASM asm volatile
int main(){int a=0;ASM("nop");ASM("nop");ASM("nop");ASM("nop");ASM("nop");ASM("nop");ASM("nop");ASM("nop");printf("%d\n",a);return 0;}
EOF
if [ ${#3} -gt 1 ]; then
    echo Custom target binary
    echo
else
    $COMPILER target.c -o target -g -Wall && rm target.c
    [[ $? -ne 0 ]] && exit
fi

# Dump .text section from Target
"${PFX}"objcopy --dump-section .text=target.text target
TARGET_TEXT_SZ_ORIG=$(printf %x "$(stat -c '%s' target.text)")
TARGET_TEXT_SZ_ORIG=$(pad_variable_to_size "$TARGET_TEXT_SZ_ORIG" 8)
echo "-------------------------------------------------------"
echo "| TARGET_TEXT_SZ_ORIG: $TARGET_TEXT_SZ_ORIG"

# Dump ELF data from Target
"${PFX}"readelf -a target > re-target-initial.txt

# Print obj data of initial target file
"${PFX}"objdump -d target > od-target-initial.txt

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
$COMPILER -c patch.S -o patch.o && rm patch.S
[[ $? -ne 0 ]] && exit

# Dump ELF data from Patch
"${PFX}"readelf -a patch.o > re-patch.txt

# Print .text section from Patch
"${PFX}"objdump -d patch.o > od-patch.txt

# Dump .text section from Patch
"${PFX}"objcopy --dump-section .text=patch.text patch.o && rm patch.o
PATCH_TEXT_SZ=$(printf %x "$(stat -c '%s' patch.text)")
PATCH_TEXT_SZ=$(pad_variable_to_size "$PATCH_TEXT_SZ" 8)
echo "| PATCH_TEXT_SZ: $PATCH_TEXT_SZ"

# Merge .text section from Patch into Target
cat patch.text >> target.text && rm patch.text
TARGET_TEXT_SZ_PATCHED=$(printf %x "$(stat -c '%s' target.text)")
TARGET_TEXT_SZ_PATCHED=$(pad_variable_to_size "$TARGET_TEXT_SZ_PATCHED" 8)
echo "| TARGET_TEXT_SZ_PATCHED: $TARGET_TEXT_SZ_PATCHED"
echo "-------------------------------------------------------"
echo

SECTION_HDR_START=$("${PFX}"readelf -h target | grep -E "Start of section headers"  | cut -f2 -d: | sed 's/^[t ]*//g;s/ .*//g')
SECTION_HDR_WIDTH=$("${PFX}"readelf -h target | grep -E "Size of section headers"   | cut -f2 -d: | sed 's/^[t ]*//g;s/ .*//g')
SECTION_HDR_COUNT=$("${PFX}"readelf -h target | grep -E "Number of section headers" | cut -f2 -d: | sed 's/^[t ]*//g;s/ .*//g')
xxd -g0 -s "$SECTION_HDR_START" -l $((SECTION_HDR_COUNT*SECTION_HDR_WIDTH)) target | grep -oE "[0-9a-f]{32}" | tr -d '\n' | grep -oE "[0-9a-f]{128}" > hex-section.txt

if [[ $COMPILER =~ "clang" ]]; then

    # Compute .text section address and offset
    if [[ $COMPILER =~ "clang" ]]; then
        SIZE_SELECT=7
    else
        SIZE_SELECT=8
    fi
    TXT_ADDR=$("${PFX}"readelf -t target | grep -E "\[[0-9a-f ]{2}\] .text" -A2 | sed "s/\[ /\[/g" | tr -d '\n' | tr -s " " | tr ' ' '\n' | sed -n 6p | tr -d '\n')
    TXT_ADDR=$(pad_variable_to_size "$TXT_ADDR" 16)
    TXT_ADDR=$(echo "$TXT_ADDR" | change_endianness)
    TXT_SIZE=$("${PFX}"readelf -t target | grep -E "\[[0-9a-f ]{2}\] .text" -A2 | sed "s/\[ /\[/g" | tr -d '\n' | tr -s " " | tr ' ' '\n' | sed -n ${SIZE_SELECT}p | tr -d '\n')
    TXT_SIZE=$(pad_variable_to_size "$TXT_SIZE" 16)
    TXT_SIZE=$(echo "$TXT_SIZE" | change_endianness)
    TEXT_SZ_NEW=$(pad_variable_to_size "$TARGET_TEXT_SZ_PATCHED" 16)
    TEXT_SZ_NEW=$(echo "${TEXT_SZ_NEW}" | change_endianness)
    echo "TEXT_SZ_NEW: $TEXT_SZ_NEW"
    echo "TXT_ADDR: $TXT_ADDR"
    echo "TXT_SIZE: $TXT_SIZE"

    # for section header, addresses are 8 bytes (16 hex charas)
    TXT_SH_MATCH=$(grep -E ".{,8}.{,8}.{,16}.${TXT_ADDR}.{,16}.${TXT_SIZE}.{,8}.{,8}.{,16}.{,16}" hex-section.txt)
    TXT_SH_OFFST=$(echo "$TXT_SH_MATCH" | sed -r "s/^[0-9a-f]{48}//g"  | grep -oE "^[0-9a-f]{16}")
    TXT_SH_PATCH=${TXT_SH_MATCH/$TXT_SIZE/$TEXT_SZ_NEW}
    echo "TXT_SH_MATCH: $TXT_SH_MATCH"
    echo "TXT_SH_OFFST: $TXT_SH_OFFST"
    echo "TXT_SH_PATCH: $TXT_SH_PATCH"
    echo
    TXT_SH_MATCH=$(echo "$TXT_SH_MATCH" | rawhex_to_escaped_hex)
    TXT_SH_PATCH=$(echo "$TXT_SH_PATCH" | rawhex_to_escaped_hex)
    sed -i "s|$TXT_SH_MATCH|$TXT_SH_PATCH|g" target

fi

# [PRE-RUN] Update .text section with new .text data
# llvm-objcopy doesn't emit the verbose data that we need, so prefer gnu objcopy during this step
if [[ $COMPILER =~ "clang" && $ARCH =~ "aarch64" ]]; then
    ALT_PFX=aarch64-linux-gnu-
elif [[ $COMPILER =~ "clang" && $ARCH =~ "x86_64" ]]; then
    ALT_PFX=""
else
    ALT_PFX="$PFX"
fi
"$ALT_PFX"objcopy --update-section .text=target.text target target.temp &> objcopy-out.txt && rm target.temp
cat objcopy-out.txt
echo
S_CNT=$(wc -l < objcopy-out.txt)
S_DATA=$(cut -f3 -d: objcopy-out.txt | sed "s/.*section //g;s/lma //g;s/adjusted to //g;s/\n/ /g;s/ /\n/g")
rm objcopy-out.txt

i=0
SECTIONS=()
ADDRS_OLD=()
ADDRS_NEW=()
while [ $i -lt "$S_CNT" ]; do

    i=$((i+1))

    SECTIONS+=( "$(echo -e "$S_DATA" | head -n $((3*i)) | tail -n3 | head -n1 | tail -n1)" )

    ADDR_OLD_TMP=$(echo -e "$S_DATA" | head -n $((3*i)) | tail -n3 | head -n2 | tail -n1 | sed "s/^0x//g")
    ADDR_OLD_TMP=$(pad_variable_to_size "$ADDR_OLD_TMP" 8)
    ADDRS_OLD+=( "$ADDR_OLD_TMP" )

    ADDR_NEW_TMP=$(echo -e "$S_DATA" | head -n $((3*i)) | tail -n3 | head -n3 | tail -n1 | sed "s/^0x//g")
    ADDR_NEW_TMP=$(pad_variable_to_size "$ADDR_NEW_TMP" 8)
    ADDRS_NEW+=( "$ADDR_NEW_TMP" )

done

echo "-------------------------------------------------------"
echo "| SECTIONS: ${SECTIONS[*]}"
echo "| ADDRS_OLD: ${ADDRS_OLD[*]}"
echo "| ADDRS_NEW: ${ADDRS_NEW[*]}"

SECTION_IDS=()
for section in "${SECTIONS[@]}"; do
    PATCH_SECTION=$("${PFX}"readelf -t target | grep -E "\[[0-9a-f]{2}\] ${section}$" | grep -oE "\[.*\]" | sed "s/\[//g;s/\]//g" | tr -d '\n')
    SECTION_IDS+=( "$PATCH_SECTION" )
done
echo "| SECTION_IDS: ${SECTION_IDS[*]}"

SECTION_IDS_LE_HEXES=()
for id in "${SECTION_IDS[@]}"; do
    SECTION_IDS_HEX=$(printf %x "$id")
    SECTION_IDS_HEX=$(pad_variable_to_size "$SECTION_IDS_HEX" 4)
    # clamped to 4 according to section header spec (8 bytes)
    SECTION_IDS_LE_HEXES+=( "$(echo "$SECTION_IDS_HEX" | change_endianness)" )
done
echo "| SECTION_IDS_LE_HEXES: ${SECTION_IDS_LE_HEXES[*]}"
echo "-------------------------------------------------------"
echo

# Patch .dynamic and .symtab sections of section following .text
function patch_symtab_and_dynamic_sections() {

    # Compute .dynamic section address and offset
    if [[ $COMPILER =~ "clang" ]]; then
        SIZE_SELECT=7
    else
        SIZE_SELECT=8
    fi
    DYN_ADDR=$("${PFX}"readelf -t target | grep -E "\[[0-9a-f ]{2}\] .dynamic" -A2 | sed "s/\[ /\[/g" | tr -d '\n' | tr -s " " | tr ' ' '\n' | sed -n 6p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
    DYN_SIZE=$("${PFX}"readelf -t target | grep -E "\[[0-9a-f ]{2}\] .dynamic" -A2 | sed "s/\[ /\[/g" | tr -d '\n' | tr -s " " | tr ' ' '\n' | sed -n ${SIZE_SELECT}p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
    echo
    echo "+ Dynamic Section at $DYN_ADDR of size $DYN_SIZE"
    xxd -s "$(printf %d "$DYN_ADDR")" -l "$(printf %d "$DYN_SIZE")" -g0 target | grep -oE "[0-9a-f]{32}" | tr -d '\n' | grep -oE "[0-9a-f]{48}" > hex-dyn.txt

    DYN_VALUE=$(pad_variable_to_size_at_end "$1" 16)
    echo "| DYN_VALUE: $DYN_VALUE"
    DYN_OLDHX=$(grep -E "^.{,16}${DYN_VALUE}.{,16}$" hex-dyn.txt)
    if [ ${#DYN_OLDHX} -gt 0 ]; then
        DYN_PATCH=${DYN_OLDHX/$1/$2}
        echo "| DYN_OLDHX: $DYN_OLDHX"
        echo "| DYN_PATCH: $DYN_PATCH"
        DYN_PATCH=$(echo "$DYN_PATCH" | rawhex_to_escaped_hex)
        DYN_OLDHX=$(echo "$DYN_OLDHX" | rawhex_to_escaped_hex)
        sed -i "s|$DYN_OLDHX|$DYN_PATCH|g" target
    fi

    # Compute .symtab section address and offset
    if [[ $COMPILER =~ "clang" ]]; then
        SIZE_SELECT=7
    else
        SIZE_SELECT=8
    fi
    SYM_ADDR=$("${PFX}"readelf -t target | grep -E "\[[0-9a-f ]{2}\] .symtab" -A2 | sed "s/\[ /\[/g" | tr -d '\n' | tr -s " " | tr ' ' '\n' | sed -n 6p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
    SYM_SIZE=$("${PFX}"readelf -t target | grep -E "\[[0-9a-f ]{2}\] .symtab" -A2 | sed "s/\[ /\[/g" | tr -d '\n' | tr -s " " | tr ' ' '\n' | sed -n ${SIZE_SELECT}p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
    echo
    echo "+ Symtab Section at $SYM_ADDR of size $SYM_SIZE"
    xxd -s "$(printf %d "$SYM_ADDR")" -l "$(printf %d "$SYM_SIZE")" -g0 target | grep -oE "[0-9a-f]{32}" | tr -d '\n' | grep -oE "[0-9a-f]{48}" > hex-sym.txt

    HEXES=()
    while read -r hex; do
        HEXES+=("$hex")
    done < <(grep -E ".{,12}${3}${1}.{,16}" hex-sym.txt)
    for hex in "${HEXES[@]}"; do
        SYM_OLDHX="$hex"
        ST_NAME=$(echo "$SYM_OLDHX" | grep -oE "^[0-9a-f]{8}")
        ST_INFO=$(echo "$SYM_OLDHX" | sed -r "s/^[0-9a-f]{8}//g"  | grep -oE "^[0-9a-f]{2}")
        ST_OTHER=$(echo "$SYM_OLDHX" | sed -r "s/^[0-9a-f]{10}//g" | grep -oE "^[0-9a-f]{2}")
        echo "| ST_NAME:  $ST_NAME"
        echo "| ST_INFO:  $ST_INFO"
        echo "| ST_OTHER: $ST_OTHER"
        if [ ${#SYM_OLDHX} -gt 0 ]; then
            SYM_PATCH=${SYM_OLDHX/$1/$2}
            echo "| SYM_OLDHX: $SYM_OLDHX"
            echo "| SYM_PATCH: $SYM_PATCH"
            SYM_PATCH=$(echo "$SYM_PATCH" | rawhex_to_escaped_hex)
            SYM_OLDHX=$(echo "$SYM_OLDHX" | rawhex_to_escaped_hex)
            sed -i "s|$SYM_OLDHX|$SYM_PATCH|g" target
        fi
    done

    # Compute .dynsym section address and offset
    if [[ $COMPILER =~ "clang" ]]; then
        SIZE_SELECT=7
    else
        SIZE_SELECT=8
    fi
    DYNSYM_ADDR=$("${PFX}"readelf -t target | grep -E "\[[0-9a-f ]{2}\] .dynsym" -A2 | sed "s/\[ /\[/g" | tr -d '\n' | tr -s " " | tr ' ' '\n' | sed -n 6p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
    DYNSYM_SIZE=$("${PFX}"readelf -t target | grep -E "\[[0-9a-f ]{2}\] .dynsym" -A2 | sed "s/\[ /\[/g" | tr -d '\n' | tr -s " " | tr ' ' '\n' | sed -n ${SIZE_SELECT}p | tr -d '\n' | sed 's/^0*//;s/^/0x/')
    echo
    echo "+ Dynsym Section at $DYNSYM_ADDR of size $DYNSYM_SIZE"
    xxd -s "$(printf %d "$DYNSYM_ADDR")" -l "$(printf %d "$DYNSYM_SIZE")" -g0 target | grep -oE "[0-9a-f]{32}" | tr -d '\n' | grep -oE "[0-9a-f]{48}" > hex-dynsym.txt

    HEXES=()
    while read -r hex; do
        HEXES+=("$hex")
    done < <(grep -E ".{,12}${3}${1}.{,16}" hex-sym.txt)
    for hex in "${HEXES[@]}"; do
        DYNSYM_OLDHX="$hex"
        ST_NAME=$(echo "$DYNSYM_OLDHX" | grep -oE "^[0-9a-f]{8}")
        ST_INFO=$(echo "$DYNSYM_OLDHX" | sed -r "s/^[0-9a-f]{8}//g"  | grep -oE "^[0-9a-f]{2}")
        ST_OTHER=$(echo "$DYNSYM_OLDHX" | sed -r "s/^[0-9a-f]{10}//g" | grep -oE "^[0-9a-f]{2}")
        echo "| ST_NAME:  $ST_NAME"
        echo "| ST_INFO:  $ST_INFO"
        echo "| ST_OTHER: $ST_OTHER"
        if [ ${#DYNSYM_OLDHX} -gt 0 ]; then
            DYNSYM_PATCH=${DYNSYM_OLDHX/$1/$2}
            echo "| DYNSYM_OLDHX: $DYNSYM_OLDHX"
            echo "| DYNSYM_PATCH: $DYNSYM_PATCH"
            DYNSYM_PATCH=$(echo "$DYNSYM_PATCH" | rawhex_to_escaped_hex)
            DYNSYM_OLDHX=$(echo "$DYNSYM_OLDHX" | rawhex_to_escaped_hex)
            sed -i "s|$DYNSYM_OLDHX|$DYNSYM_PATCH|g" target
        fi

        # __start_section and __stop_section
        START_SEC=$(grep -E ".{,12}${3}.{,32}" hex-dynsym.txt | sed -r "s/^[0-9a-f]{16}//g" | grep -oE "^[0-9a-f]{10}" | head -n1 | tail -n1 | change_endianness)
        STOPS_SEC=$(grep -E ".{,12}${3}.{,32}" hex-dynsym.txt | sed -r "s/^[0-9a-f]{16}//g" | grep -oE "^[0-9a-f]{10}" | head -n2 | tail -n1 | change_endianness)
        if [[ ${#START_SEC} -gt 0 && ${#STOPS_SEC} -gt 0 && $(printf %d 0x"$STOPS_SEC") -ge $(printf %d 0x"$START_SEC") ]]; then
            echo "| START_SEC: $START_SEC"
            echo "| STOPS_SEC: $STOPS_SEC"
            DELTA=$(printf %x $((0x$STOPS_SEC-0x$START_SEC)))
            echo "| DELTA: $DELTA"

            STOP_ADDR=$(printf %x $(($(echo "$2" | change_endianness | sed "s/^/0x/g")+0x$DELTA)))
            STOP_ADDR=$(pad_variable_to_size "$STOP_ADDR" 8)

            NEW_ADDR=$(printf %x $((0x$STOP_ADDR+0x$DELTA)))
            NEW_ADDR=$(pad_variable_to_size "$NEW_ADDR" 8)

            STOP_ADDR=$(echo "$STOP_ADDR" | change_endianness)
            NEW_ADDR=$(echo "$NEW_ADDR" | change_endianness)
            echo "| STOP_ADDR: $STOP_ADDR"
            echo "| NEW_ADDR:  $NEW_ADDR"

            DYNSYM_OLDHX=$(grep -oE ".{,12}${3}${STOP_ADDR}.{,24}" hex-dynsym.txt)
            if [ ${#DYNSYM_OLDHX} -gt 0 ]; then
                echo "| patching __stop_symbol"
                DYNSYM_PATCH=${DYNSYM_OLDHX/${STOP_ADDR}/${NEW_ADDR}}
                echo "| DYNSYM_OLDHX: $DYNSYM_OLDHX"
                echo "| DYNSYM_PATCH: $DYNSYM_PATCH"
                DYNSYM_PATCH=$(echo "$DYNSYM_PATCH" | rawhex_to_escaped_hex)
                DYNSYM_OLDHX=$(echo "$DYNSYM_OLDHX" | rawhex_to_escaped_hex)
                sed -i "s|$DYNSYM_OLDHX|$DYNSYM_PATCH|g" target
            fi
        fi
    done
}

# Update .text section with new .text data
"${PFX}"objcopy --update-section .text=target.text target target_patch && mv target_patch target && rm target.text
[[ $? -ne 0 ]] && exit

# Add our new function in Patch to the symtab
TARGET_TEXT_SZ_ORIG_HEX=$(echo "$TARGET_TEXT_SZ_ORIG" | sed "s/^/0x/g")
"${PFX}"objcopy --add-symbol __patch=".text:${TARGET_TEXT_SZ_ORIG_HEX},global,function" target target_patch && mv target_patch target
[[ $? -ne 0 ]] && exit

i=0
while [ $i -lt "$S_CNT" ]; do
    echo
    echo "+ SYMTAB + DYNAMIC PATCHING"
    # Compute the new addr of section after .text and patch it's symtab and dynamic addresses
    # These are 16 bytes everywhere.
    S_OLD_ADDR=$(echo "${ADDRS_OLD[$i]}" | change_endianness)
    S_NEW_ADDR=$(echo "${ADDRS_NEW[$i]}" | change_endianness)
    echo "| SECTIONS: ${SECTIONS[$i]}"
    echo "| S_OLD_ADDR: $S_OLD_ADDR"
    echo "| S_NEW_ADDR: $S_NEW_ADDR"
    echo "| SECTION_IDS_LE_HEXES[$i]: ${SECTION_IDS_LE_HEXES[$i]}"
    patch_symtab_and_dynamic_sections "$S_OLD_ADDR" "$S_NEW_ADDR" "${SECTION_IDS_LE_HEXES[$i]}"
    i=$((i+1))
done
echo

i=0
while [ $i -lt "$S_CNT" ]; do
    # patch section header address, set VMA=LMA
    echo "+ SECTION HEADER VMA=LMA PATCHING"
    echo "| SECTIONS: ${SECTIONS[$i]}"
    # for section header, addresses are 8 bytes (16 hex charas)
    ADDRS_OLD[$i]=$(pad_variable_to_size "${ADDRS_OLD[$i]}" 16)
    ADDRS_NEW[$i]=$(pad_variable_to_size "${ADDRS_NEW[$i]}" 16)
    S_OLD_ADDR=$(echo "${ADDRS_OLD[$i]}" | change_endianness)
    S_NEW_ADDR=$(echo "${ADDRS_NEW[$i]}" | change_endianness)
    echo "| S_OLD_ADDR: $S_OLD_ADDR"
    echo "| S_NEW_ADDR: $S_NEW_ADDR"
    SH_MATCH=$(grep -E ".{,8}.{,8}.{,16}.${S_OLD_ADDR}.{,16}.{,16}.{,8}.{,8}.{,16}.{,16}" hex-section.txt)
    SH_OFFST=$(echo "$SH_MATCH" | sed -r "s/^[0-9a-f]{48}//g"  | grep -oE "^[0-9a-f]{16}")
    SH_PATCH=$(echo "$SH_MATCH" | sed "s/$S_OLD_ADDR/$S_NEW_ADDR/g;s/$SH_OFFST/$S_NEW_ADDR/g")
    echo "| SH_MATCH: $SH_MATCH"
    echo "| SH_OFFST: $SH_OFFST"
    echo "| SH_PATCH: $SH_PATCH"
    echo
    SH_MATCH=$(echo "$SH_MATCH" | rawhex_to_escaped_hex)
    SH_PATCH=$(echo "$SH_PATCH" | rawhex_to_escaped_hex)
    sed -i "s|$SH_MATCH|$SH_PATCH|g" target
    i=$((i+1))
done

# Dump ELF data of final file and diff
"${PFX}"readelf -a target > re-target-final.txt
diff -ur re-target-initial.txt re-target-final.txt > re-diff.txt

# Print obj data of final file
"${PFX}"objdump -d target > od-target-final.txt

diff -ur <(cat od-target-initial.txt) <(cat od-target-final.txt) > od-diff.txt
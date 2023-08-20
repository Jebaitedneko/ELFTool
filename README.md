Built-in example for aarch64:

Command:
`./patch.sh aarch64-linux-gnu-gcc aarch64`

```
-------------------------------------------------------
| TARGET_TEXT_SZ_ORIG: 0000015c
| PATCH_TEXT_SZ: 00000018
| TARGET_TEXT_SZ_PATCHED: 00000174
-------------------------------------------------------

-------------------------------------------------------
| SECTIONS: .fini .rodata .eh_frame_hdr .eh_frame
| ADDRS_OLD: 0000079c 000007b0 000007bc 000007f8
| ADDRS_NEW: 000007b4 000007c8 000007d4 00000810
| SECTION_IDS: 14 15 16 17
| SECTION_IDS_LE_HEXES: 0e00 0f00 1000 1100
-------------------------------------------------------

aarch64-linux-gnu-objcopy: target_patch: section .fini lma 0x79c adjusted to 0x7b4
aarch64-linux-gnu-objcopy: target_patch: section .rodata lma 0x7b0 adjusted to 0x7c8
aarch64-linux-gnu-objcopy: target_patch: section .eh_frame_hdr lma 0x7bc adjusted to 0x7d4
aarch64-linux-gnu-objcopy: target_patch: section .eh_frame lma 0x7f8 adjusted to 0x810

+ SYMTAB + DYNAMIC PATCHING
| SECTIONS: .fini
|-> LOCAL | DEFAULT
| S_OLD_ADDR: 9c070000
| S_NEW_ADDR: b4070000
| SECTION_IDS_LE_HEXES[i]: 0e00
| ST_OTHER: 00
| ST_INFO: 03
| MATCH ADDR: 03000e009c070000 SHIFT: 9c070000 (LE) -> b4070000 (LE) SECTION ID: 0e00 (LE)
| Dynamic Section at 0xda0 of size 0x1f0
| DYN_OLDHX: 0d000000000000009c07000000000000
| DYN_PATCH: 0d00000000000000b407000000000000
| Symtab Section at 0x1340 of size 0x8e8
| SYM_OLDHX: 0000000003000e009c0700000000000000000000
| SYM_PATCH: 0000000003000e00b40700000000000000000000
|-> GLOBAL | HIDDEN
| S_OLD_ADDR: 9c070000
| S_NEW_ADDR: b4070000
| SECTION_IDS_LE_HEXES[i]: 0e00
| ST_OTHER: 02
| ST_INFO: 12
| MATCH ADDR: 12020e009c070000 SHIFT: 9c070000 (LE) -> b4070000 (LE) SECTION ID: 0e00 (LE)
| Dynamic Section at 0xda0 of size 0x1f0
| Symtab Section at 0x1340 of size 0x8e8
| SYM_OLDHX: 7901000012020e009c0700000000000000000000
| SYM_PATCH: 7901000012020e00b40700000000000000000000

+ SYMTAB + DYNAMIC PATCHING
| SECTIONS: .rodata
|-> LOCAL | DEFAULT
| S_OLD_ADDR: b0070000
| S_NEW_ADDR: c8070000
| SECTION_IDS_LE_HEXES[i]: 0f00
| ST_OTHER: 00
| ST_INFO: 03
| MATCH ADDR: 03000f00b0070000 SHIFT: b0070000 (LE) -> c8070000 (LE) SECTION ID: 0f00 (LE)
| Dynamic Section at 0xda0 of size 0x1f0
| Symtab Section at 0x1340 of size 0x8e8
| SYM_OLDHX: 0000000003000f00b00700000000000000000000
| SYM_PATCH: 0000000003000f00c80700000000000000000000
|-> GLOBAL | HIDDEN
| S_OLD_ADDR: b0070000
| S_NEW_ADDR: c8070000
| SECTION_IDS_LE_HEXES[i]: 0f00
| ST_OTHER: 02
| ST_INFO: 12
| MATCH ADDR: 12020f00b0070000 SHIFT: b0070000 (LE) -> c8070000 (LE) SECTION ID: 0f00 (LE)
| Dynamic Section at 0xda0 of size 0x1f0
| Symtab Section at 0x1340 of size 0x8e8

+ SYMTAB + DYNAMIC PATCHING
| SECTIONS: .eh_frame_hdr
|-> LOCAL | DEFAULT
| S_OLD_ADDR: bc070000
| S_NEW_ADDR: d4070000
| SECTION_IDS_LE_HEXES[i]: 1000
| ST_OTHER: 00
| ST_INFO: 03
| MATCH ADDR: 03001000bc070000 SHIFT: bc070000 (LE) -> d4070000 (LE) SECTION ID: 1000 (LE)
| Dynamic Section at 0xda0 of size 0x1f0
| Symtab Section at 0x1340 of size 0x8e8
| SYM_OLDHX: 0000000003001000bc0700000000000000000000
| SYM_PATCH: 0000000003001000d40700000000000000000000
|-> GLOBAL | HIDDEN
| S_OLD_ADDR: bc070000
| S_NEW_ADDR: d4070000
| SECTION_IDS_LE_HEXES[i]: 1000
| ST_OTHER: 02
| ST_INFO: 12
| MATCH ADDR: 12021000bc070000 SHIFT: bc070000 (LE) -> d4070000 (LE) SECTION ID: 1000 (LE)
| Dynamic Section at 0xda0 of size 0x1f0
| Symtab Section at 0x1340 of size 0x8e8

+ SYMTAB + DYNAMIC PATCHING
| SECTIONS: .eh_frame
|-> LOCAL | DEFAULT
| S_OLD_ADDR: f8070000
| S_NEW_ADDR: 10080000
| SECTION_IDS_LE_HEXES[i]: 1100
| ST_OTHER: 00
| ST_INFO: 03
| MATCH ADDR: 03001100f8070000 SHIFT: f8070000 (LE) -> 10080000 (LE) SECTION ID: 1100 (LE)
| Dynamic Section at 0xda0 of size 0x1f0
| Symtab Section at 0x1340 of size 0x8e8
| SYM_OLDHX: 0000000003001100f80700000000000000000000
| SYM_PATCH: 0000000003001100100800000000000000000000
|-> GLOBAL | HIDDEN
| S_OLD_ADDR: f8070000
| S_NEW_ADDR: 10080000
| SECTION_IDS_LE_HEXES[i]: 1100
| ST_OTHER: 02
| ST_INFO: 12
| MATCH ADDR: 12021100f8070000 SHIFT: f8070000 (LE) -> 10080000 (LE) SECTION ID: 1100 (LE)
| Dynamic Section at 0xda0 of size 0x1f0
| Symtab Section at 0x1340 of size 0x8e8

+ SECTION HEADER VMA=LMA PATCHING
| SECTIONS: .fini
| S_OLD_ADDR: 9c070000
| S_NEW_ADDR: b4070000
| FUZZY_END_HEX: b4070000
| FUZZY_END_HEX_SZ: 8
| SH_MATCH: \x9c\x07\x00\x00\x00\x00\x00\x00\xb4\x07\x00\x00
| SH_PATCH: \xb4\x07\x00\x00\x00\x00\x00\x00\xb4\x07\x00\x00

+ SECTION HEADER VMA=LMA PATCHING
| SECTIONS: .rodata
| S_OLD_ADDR: b0070000
| S_NEW_ADDR: c8070000
| FUZZY_END_HEX: c8070000
| FUZZY_END_HEX_SZ: 8
| SH_MATCH: \xb0\x07\x00\x00\x00\x00\x00\x00\xc8\x07\x00\x00
| SH_PATCH: \xc8\x07\x00\x00\x00\x00\x00\x00\xc8\x07\x00\x00

+ SECTION HEADER VMA=LMA PATCHING
| SECTIONS: .eh_frame_hdr
| S_OLD_ADDR: bc070000
| S_NEW_ADDR: d4070000
| FUZZY_END_HEX: d4070000
| FUZZY_END_HEX_SZ: 8
| SH_MATCH: \xbc\x07\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00
| SH_PATCH: \xd4\x07\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00

+ SECTION HEADER VMA=LMA PATCHING
| SECTIONS: .eh_frame
| S_OLD_ADDR: f8070000
| S_NEW_ADDR: 10080000
| FUZZY_END_HEX: 10080000
| FUZZY_END_HEX_SZ: 8
| SH_MATCH: \xf8\x07\x00\x00\x00\x00\x00\x00\x10\x08\x00\x00
| SH_PATCH: \x10\x08\x00\x00\x00\x00\x00\x00\x10\x08\x00\x00
```

Built-in example for x86_64:

Command:
`./patch.sh gcc x86_64`

```
-------------------------------------------------------
| TARGET_TEXT_SZ_ORIG: 00000124
| PATCH_TEXT_SZ: 0000000a
| TARGET_TEXT_SZ_PATCHED: 0000012e
-------------------------------------------------------

-------------------------------------------------------
| SECTIONS: .fini
| ADDRS_OLD: 00001184
| ADDRS_NEW: 0000118e
| SECTION_IDS: 17
| SECTION_IDS_LE_HEXES: 1100
-------------------------------------------------------

objcopy: target_patch: section .fini lma 0x1184 adjusted to 0x118e

+ SYMTAB + DYNAMIC PATCHING
| SECTIONS: .fini
|-> LOCAL | DEFAULT
| S_OLD_ADDR: 84110000
| S_NEW_ADDR: 8e110000
| SECTION_IDS_LE_HEXES[i]: 1100
| ST_OTHER: 00
| ST_INFO: 03
| MATCH ADDR: 0300110084110000 SHIFT: 84110000 (LE) -> 8e110000 (LE) SECTION ID: 1100 (LE)
| Dynamic Section at 0x2dc8 of size 0x1f0
| DYN_OLDHX: 0d000000000000008411000000000000
| DYN_PATCH: 0d000000000000008e11000000000000
| Symtab Section at 0x3340 of size 0x378
|-> GLOBAL | HIDDEN
| S_OLD_ADDR: 84110000
| S_NEW_ADDR: 8e110000
| SECTION_IDS_LE_HEXES[i]: 1100
| ST_OTHER: 02
| ST_INFO: 12
| MATCH ADDR: 1202110084110000 SHIFT: 84110000 (LE) -> 8e110000 (LE) SECTION ID: 1100 (LE)
| Dynamic Section at 0x2dc8 of size 0x1f0
| Symtab Section at 0x3340 of size 0x378
| SYM_OLDHX: 3001000012021100841100000000000000000000
| SYM_PATCH: 30010000120211008e1100000000000000000000

+ SECTION HEADER VMA=LMA PATCHING
| SECTIONS: .fini
| S_OLD_ADDR: 84110000
| S_NEW_ADDR: 8e110000
| FUZZY_END_HEX: 8e110000
| FUZZY_END_HEX_SZ: 8
| SH_MATCH: \x84\x11\x00\x00\x00\x00\x00\x00\x8e\x11\x00\x00
| SH_PATCH: \x8e\x11\x00\x00\x00\x00\x00\x00\x8e\x11\x00\x00
```

Invoke the newly added function via the following patch:

`diff -ur <(objdump -d target_o) <(objdump -d target_p)`

```
 Disassembly of section .init:
@@ -118,15 +118,13 @@
     114e:      48 89 e5                mov    %rsp,%rbp
     1151:      48 83 ec 10             sub    $0x10,%rsp
     1155:      c7 45 fc 00 00 00 00    movl   $0x0,-0x4(%rbp)
-    115c:      90                      nop
-    115d:      90                      nop
-    115e:      90                      nop
-    115f:      90                      nop
-    1160:      90                      nop
+    115c:      e8 23 00 00 00          call   1184 <__patch>
     1161:      90                      nop
     1162:      90                      nop
     1163:      90                      nop
-    1164:      8b 45 fc                mov    -0x4(%rbp),%eax
+    1164:      90                      nop
+    1165:      90                      nop
+    1166:      90                      nop
     1167:      89 c6                   mov    %eax,%esi
     1169:      48 8d 05 94 0e 00 00    lea    0xe94(%rip),%rax        # 2004 <_IO_stdin_used+0x4>
     1170:      48 89 c7                mov    %rax,%rdi
```
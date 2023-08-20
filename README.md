Built-in example for aarch64:

Command:
`./patch.sh aarch64-linux-gnu-`

```
-------------------------------------------------------
| TARGET_TEXT_SZ_ORIG: 0x15c
| PATCH_TEXT_SZ: 0x18
| TARGET_TEXT_SZ_PATCHED: 0x174
-------------------------------------------------------

-------------------------------------------------------
| SECTIONS: .fini .rodata .eh_frame_hdr .eh_frame
| ADDRS_OLD: 0x079c 0x07b0 0x07bc 0x07f8
| ADDRS_NEW: 0x07b4 0x07c8 0x07d4 0x0810
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
| MATCH ADDR: 03000e009c07 SHIFT: 9c07 (LE) -> b407 (LE) SECTION ID: 0e00 (LE)
| Dynamic Section at 0xda0 of size 0x1f0
| DYN_OLDHX: 0d000000000000009c07000000000000
| DYN_PATCH: 0d00000000000000b407000000000000
| Symtab Section at 0x1340 of size 0x8e8
| SYM_OLDHX: 0000000003000e009c070000000000000000
| SYM_PATCH: 0000000003000e00b4070000000000000000
|-> GLOBAL | HIDDEN
| MATCH ADDR: 12020e009c07 SHIFT: 9c07 (LE) -> b407 (LE) SECTION ID: 0e00 (LE)
| Dynamic Section at 0xda0 of size 0x1f0
| Symtab Section at 0x1340 of size 0x8e8
| SYM_OLDHX: 7901000012020e009c070000000000000000
| SYM_PATCH: 7901000012020e00b4070000000000000000

+ SYMTAB + DYNAMIC PATCHING
| SECTIONS: .rodata
|-> LOCAL | DEFAULT
| MATCH ADDR: 03000f00b007 SHIFT: b007 (LE) -> c807 (LE) SECTION ID: 0f00 (LE)
| Dynamic Section at 0xda0 of size 0x1f0
| Symtab Section at 0x1340 of size 0x8e8
| SYM_OLDHX: 0000000003000f00b0070000000000000000
| SYM_PATCH: 0000000003000f00c8070000000000000000
|-> GLOBAL | HIDDEN
| MATCH ADDR: 12020f00b007 SHIFT: b007 (LE) -> c807 (LE) SECTION ID: 0f00 (LE)
| Dynamic Section at 0xda0 of size 0x1f0
| Symtab Section at 0x1340 of size 0x8e8

+ SYMTAB + DYNAMIC PATCHING
| SECTIONS: .eh_frame_hdr
|-> LOCAL | DEFAULT
| MATCH ADDR: 03001000bc07 SHIFT: bc07 (LE) -> d407 (LE) SECTION ID: 1000 (LE)
| Dynamic Section at 0xda0 of size 0x1f0
| Symtab Section at 0x1340 of size 0x8e8
| SYM_OLDHX: 0000000003001000bc070000000000000000
| SYM_PATCH: 0000000003001000d4070000000000000000
|-> GLOBAL | HIDDEN
| MATCH ADDR: 12021000bc07 SHIFT: bc07 (LE) -> d407 (LE) SECTION ID: 1000 (LE)
| Dynamic Section at 0xda0 of size 0x1f0
| Symtab Section at 0x1340 of size 0x8e8

+ SYMTAB + DYNAMIC PATCHING
| SECTIONS: .eh_frame
|-> LOCAL | DEFAULT
| MATCH ADDR: 03001100f807 SHIFT: f807 (LE) -> 1008 (LE) SECTION ID: 1100 (LE)
| Dynamic Section at 0xda0 of size 0x1f0
| Symtab Section at 0x1340 of size 0x8e8
| SYM_OLDHX: 0000000003001100f8070000000000000000
| SYM_PATCH: 000000000300110010080000000000000000
|-> GLOBAL | HIDDEN
| MATCH ADDR: 12021100f807 SHIFT: f807 (LE) -> 1008 (LE) SECTION ID: 1100 (LE)
| Dynamic Section at 0xda0 of size 0x1f0
| Symtab Section at 0x1340 of size 0x8e8

+ SECTION HEADER VMA=LMA PATCHING
| SECTIONS: .fini
| FZEHSZ: 4
| SH_MATCH: \x9c\x07\x00\x00\x00\x00\x00\x00\xb4\x07
| SH_PATCH: \xb4\x07\x00\x00\x00\x00\x00\x00\xb4\x07

+ SECTION HEADER VMA=LMA PATCHING
| SECTIONS: .rodata
| FZEHSZ: 4
| SH_MATCH: \xb0\x07\x00\x00\x00\x00\x00\x00\xc8\x07
| SH_PATCH: \xc8\x07\x00\x00\x00\x00\x00\x00\xc8\x07

+ SECTION HEADER VMA=LMA PATCHING
| SECTIONS: .eh_frame_hdr
| FZEHSZ: 4
| SH_MATCH: \xbc\x07\x00\x00\x00\x00\x00\x00\xd4\x07
| SH_PATCH: \xd4\x07\x00\x00\x00\x00\x00\x00\xd4\x07

+ SECTION HEADER VMA=LMA PATCHING
| SECTIONS: .eh_frame
| FZEHSZ: 4
| SH_MATCH: \xf8\x07\x00\x00\x00\x00\x00\x00\x10\x08
| SH_PATCH: \x10\x08\x00\x00\x00\x00\x00\x00\x10\x08
```

Built-in example for x86_64:

Command:
`./patch.sh`

```
-------------------------------------------------------
| TARGET_TEXT_SZ_ORIG: 0x124
| PATCH_TEXT_SZ: 0xa
| TARGET_TEXT_SZ_PATCHED: 0x12e
-------------------------------------------------------

-------------------------------------------------------
| SECTIONS: .fini
| ADDRS_OLD: 0x1184
| ADDRS_NEW: 0x118e
| SECTION_IDS: 17
| SECTION_IDS_LE_HEXES: 1100
-------------------------------------------------------

objcopy: target_patch: section .fini lma 0x1184 adjusted to 0x118e

+ SYMTAB + DYNAMIC PATCHING
| SECTIONS: .fini
|-> LOCAL | DEFAULT
| MATCH ADDR: 030011008411 SHIFT: 8411 (LE) -> 8e11 (LE) SECTION ID: 1100 (LE)
| Dynamic Section at 0x2dc8 of size 0x1f0
| DYN_OLDHX: 0d000000000000008411000000000000
| DYN_PATCH: 0d000000000000008e11000000000000
| Symtab Section at 0x3340 of size 0x378
|-> GLOBAL | HIDDEN
| MATCH ADDR: 120211008411 SHIFT: 8411 (LE) -> 8e11 (LE) SECTION ID: 1100 (LE)
| Dynamic Section at 0x2dc8 of size 0x1f0
| Symtab Section at 0x3340 of size 0x378
| SYM_OLDHX: 300100001202110084110000000000000000
| SYM_PATCH: 30010000120211008e110000000000000000

+ SECTION HEADER VMA=LMA PATCHING
| SECTIONS: .fini
| FZEHSZ: 4
| SH_MATCH: \x84\x11\x00\x00\x00\x00\x00\x00\x8e\x11
| SH_PATCH: \x8e\x11\x00\x00\x00\x00\x00\x00\x8e\x11
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
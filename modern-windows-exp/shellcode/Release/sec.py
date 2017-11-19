# -*- coding: cp936 -*-
# Shellcode 提取工具 by Massimiliano Tomassoli (2015)


import sys
import os
import datetime
import pefile


author = 'Massimiliano Tomassoli'

year = datetime.date.today().year




def dword_to_bytes(value):
    return [value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >> 24) & 0xff]



def bytes_to_dword(bytes):
    return (bytes[0] & 0xff) | ((bytes[1] & 0xff) << 8) | \
           ((bytes[2] & 0xff) << 16) | ((bytes[3] & 0xff) << 24)


def get_cstring(data, offset):
    '''

    提取C字符串 (即. 以空字符结尾的字符串).

    '''

    pos = data.find('\0', offset)
    if pos == -1:
        return None

    return data[offset:pos+1]


def get_shellcode_len(map_file):
    '''

    通过分析map文件得到shellcode的长度 (通过VS2015生成map文件)

    '''

    try:
        with open(map_file, 'r') as f:
            lib_object = None
            shellcode_len = None

            for line in f:
                parts = line.split()
                if lib_object is not None:
                    if parts[-1] == lib_object:
                        raise Exception('_main is not the last function of %s' % lib_object)
                    else:
                        break
                elif (len(parts) > 2 and parts[1] == '_main'):
                    # 格式:
                    # 0001:00000274  _main   00401274 f   shellcode.obj
                    shellcode_len = int(parts[0].split(':')[1], 16)
                    lib_object = parts[-1]

            if shellcode_len is None:
                raise Exception('Cannot determine shellcode length')

    except IOError:
        print '[!] get_shellcode_len: Cannot open "%s"' % map_file
        return None

    except Exception as e:
        print '[!] get_shellcode_len: %s' % e.message
        return None

    return shellcode_len

def get_shellcode_and_relocs(exe_file, shellcode_len):
    '''

    从exe文件中.text节中提取shellcode和重定位的字符串.

    返回三个东西 (shellcode, 重定位, 字符串).

    '''

    try:
        # 提取shellcode.
        pe = pefile.PE(exe_file)
        shellcode = None
        rdata = None

        for s in pe.sections:
            if s.Name == '.text\0\0\0':
                if s.SizeOfRawData < shellcode_len:
                    raise Exception('.text section too small')
                shellcode_start = s.VirtualAddress
                shellcode_end = shellcode_start + shellcode_len
                shellcode = pe.get_data(s.VirtualAddress, shellcode_len)
            elif s.Name == '.rdata\0\0':
                rdata_start = s.VirtualAddress
                rdata_end = rdata_start + s.Misc_VirtualSize
                rdata = pe.get_data(rdata_start, s.Misc_VirtualSize)

        if shellcode is None:
            raise Exception('.text section not found')
        if rdata is None:
            raise Exception('.rdata section not found')



        # 定位到shellcode中需要重定位字符串的位置,通过这些位置在.rdata中定位到相应的字符串并将它们提取出来.
        relocs = []
        addr_to_strings = {}
        for rel_data in pe.DIRECTORY_ENTRY_BASERELOC:
            for entry in rel_data.entries[:-1]:         # the last element's rvs is the base_rva (why?)
                if shellcode_start <= entry.rva < shellcode_end:
                    # 重定位的位置在shellcode中
                    relocs.append(entry.rva - shellcode_start)      # 相对shellcode起始处的偏移
                    string_va = pe.get_dword_at_rva(entry.rva)
                    string_rva = string_va - pe.OPTIONAL_HEADER.ImageBase

                    if string_rva < rdata_start or string_rva >= rdata_end:
                        raise Exception('shellcode references a section other than .rdata')

                    str = get_cstring(rdata, string_rva - rdata_start)
                    if str is None:
                        raise Exception('Cannot extract string from .rdata')

                    addr_to_strings[string_va] = str

        return (shellcode, relocs, addr_to_strings)

    except WindowsError:
        print '[!] get_shellcode: Cannot open "%s"' % exe_file
        return None
    except Exception as e:
        print '[!] get_shellcode: %s' % e.message
        return None

def dword_to_string(dword):
    return ''.join([chr(x) for x in dword_to_bytes(dword)])

def add_loader_to_shellcode(shellcode, relocs, addr_to_strings):
    if len(relocs) == 0:
        return shellcode                # 没有待重定位的地址

    # 新shellcode的格式:
    #       call    here
    #   here:
    #       ...
    #   shellcode_start:
    #       <shellcode>         (包含strX的偏移 (偏移是相对"here"标签而言的))
    #   relocs:
    #       off1|off2|...       (待重定位地址的偏移(偏移是相对"here"标签而言的))
    #       str1|str2|...

    delta = 21                                      # shellcode_start - here

    # 构建第一个部分.
    x = dword_to_bytes(delta + len(shellcode))
    y = dword_to_bytes(len(relocs))

    code = [
        0xE8, 0x00, 0x00, 0x00, 0x00,               #   CALL here
                                                    # here:
        0x5E,                                       #   POP ESI
        0x8B, 0xFE,                                 #   MOV EDI, ESI
        0x81, 0xC6, x[0], x[1], x[2], x[3],         #   ADD ESI, shellcode_start + len(shellcode) - here
        0xB9, y[0], y[1], y[2], y[3],               #   MOV ECX, len(relocs)
        0xFC,                                       #   CLD
                                                    # again:
        0xAD,                                       #   LODSD
        0x01, 0x3C, 0x07,                           #   ADD [EDI+EAX], EDI
        0xE2, 0xFA                                  #   LOOP again
                                                    # shellcode_start:
    ]

    # 构建最后一部分 (offX 和 strX).
    offset = delta + len(shellcode) + len(relocs) * 4           # 偏移是相对"here"标签而言的
    final_part = [dword_to_string(r + delta) for r in relocs]
    addr_to_offset = {}

    for addr in addr_to_strings.keys():
        str = addr_to_strings[addr]
        final_part.append(str)
        addr_to_offset[addr] = offset
        offset += len(str)

    # 最后一部分:修复shellcode,好让待重定位的地址能够指向正确的字符串
    byte_shellcode = [ord(c) for c in shellcode]
    for off in relocs:
        addr = bytes_to_dword(byte_shellcode[off:off+4])
        byte_shellcode[off:off+4] = dword_to_bytes(addr_to_offset[addr])

    return ''.join([chr(b) for b in (code + byte_shellcode)]) + ''.join(final_part)

def dump_shellcode(shellcode):
    '''

    Prints shellcode in C format ('\x12\x23...')

    '''

    shellcode_len = len(shellcode)
    sc_array = []
    bytes_per_row = 16

    for i in range(shellcode_len):
        pos = i % bytes_per_row
        str = ''
        if pos == 0:
            str += '"'

        str += '\\x%02x' % ord(shellcode[i])
        if i == shellcode_len - 1:
            str += '";\n'
        elif pos == bytes_per_row - 1:

            str += '"\n'

        sc_array.append(str)

    shellcode_str = ''.join(sc_array)
    print shellcode_str

def get_xor_values(value):
    '''

    Finds x and y such that:

    1) x xor y == value

    2) x and y doesn't contain null bytes

    Returns x and y as arrays of bytes starting from the lowest significant byte.

    '''

    # Finds a non-null missing bytes.
    bytes = dword_to_bytes(value)
    missing_byte = [b for b in range(1, 256) if b not in bytes][0]

    xor1 = [b ^ missing_byte for b in bytes]
    xor2 = [missing_byte] * 4

    return (xor1, xor2)

def get_fixed_shellcode_single_block(shellcode):
    '''

    返回无空字符的shellcode其中一个版本,如果剔除空字符失败的话,

    就返回None

    如果该函数失败, 则调用get_fixed_shellcode().

    '''

    # Finds one non-null byte not present, if any.
    bytes = set([ord(c) for c in shellcode])
    missing_bytes = [b for b in range(1, 256) if b not in bytes]

    if len(missing_bytes) == 0:

        return None                             # 该shellcode无法被修复

    missing_byte = missing_bytes[0]

    (xor1, xor2) = get_xor_values(len(shellcode))

    code = [
        0xE8, 0xFF, 0xFF, 0xFF, 0xFF,                       #   CALL $ + 4
                                                            # here:
        0xC0,                                               #   (FF)C0 = INC EAX
        0x5F,                                               #   POP EDI
        0xB9, xor1[0], xor1[1], xor1[2], xor1[3],           #   MOV ECX, <xor value 1 for shellcode len>
        0x81, 0xF1, xor2[0], xor2[1], xor2[2], xor2[3],     #   XOR ECX, <xor value 2 for shellcode len>
        0x83, 0xC7, 29,                                     #   ADD EDI, shellcode_begin - here
        0x33, 0xF6,                                         #   XOR ESI, ESI
        0xFC,                                               #   CLD
                                                            # loop1:
        0x8A, 0x07,                                         #   MOV AL, BYTE PTR [EDI]
        0x3C, missing_byte,                                 #   CMP AL, <missing byte>
        0x0F, 0x44, 0xC6,                                   #   CMOVE EAX, ESI
        0xAA,                                               #   STOSB
        0xE2, 0xF6                                          #   LOOP loop1
                                                            # shellcode_begin:
    ]

    return ''.join([chr(x) for x in code]) + shellcode.replace('\0', chr(missing_byte))

def get_fixed_shellcode(shellcode):
    '''

    返回不含空字节shellcode的其中一个版本.这个版本将shellcode分割为若干块

    当get_fixed_shellcode_single_block()不起作用的时候,我们才会使用该函数

    '''

    # 字节分段的格式是
    #   [missing_byte1, number_of_blocks1,
    #    missing_byte2, number_of_blocks2, ...]
    # 这里的missing_byteX是用于覆盖shellcode中空字节的，
    # 而这里的number_of_blocksX是使用missing_byteX对应分段(占254个字节)的数目,

    bytes_blocks = []
    shellcode_len = len(shellcode)
    i = 0

    while i < shellcode_len:
        num_blocks = 0
        missing_bytes = list(range(1, 256))

        # 尝试找到尽可能多的占254个字节的连续分段(至少存在一个非空字节)
        while True:
            if i >= shellcode_len or num_blocks == 255:
                bytes_blocks += [missing_bytes[0], num_blocks]
                break

            bytes = set([ord(c) for c in shellcode[i:i+254]])
            new_missing_bytes = [b for b in missing_bytes if b not in bytes]

            if len(new_missing_bytes) != 0:         # 添加新分段
                missing_bytes = new_missing_bytes
                num_blocks += 1
                i += 254
            else:
                bytes += [missing_bytes[0], num_blocks]
                break

    if len(bytes_blocks) > 0x7f - 5:
        # Can't assemble "LEA EBX, [EDI + (bytes-here)]" or "JMP skip_bytes".
        return None

    (xor1, xor2) = get_xor_values(len(shellcode))

    code = ([
        0xEB, len(bytes_blocks)] +                          #   JMP SHORT skip_bytes
                                                            # bytes:
        bytes_blocks + [                                    #   ...
                                                            # skip_bytes:
        0xE8, 0xFF, 0xFF, 0xFF, 0xFF,                       #   CALL $ + 4
                                                            # here:
        0xC0,                                               #   (FF)C0 = INC EAX
        0x5F,                                               #   POP EDI
        0xB9, xor1[0], xor1[1], xor1[2], xor1[3],           #   MOV ECX, <xor value 1 for shellcode len>
        0x81, 0xF1, xor2[0], xor2[1], xor2[2], xor2[3],     #   XOR ECX, <xor value 2 for shellcode len>
        0x8D, 0x5F, -(len(bytes_blocks) + 5) & 0xFF,        #   LEA EBX, [EDI + (bytes - here)]
        0x83, 0xC7, 0x30,                                   #   ADD EDI, shellcode_begin - here
                                                            # loop1:
        0xB0, 0xFE,                                         #   MOV AL, 0FEh
        0xF6, 0x63, 0x01,                                   #   MUL AL, BYTE PTR [EBX+1]
        0x0F, 0xB7, 0xD0,                                   #   MOVZX EDX, AX
        0x33, 0xF6,                                         #   XOR ESI, ESI
        0xFC,                                               #   CLD
                                                            # loop2:
        0x8A, 0x07,                                         #   MOV AL, BYTE PTR [EDI]
        0x3A, 0x03,                                         #   CMP AL, BYTE PTR [EBX]
        0x0F, 0x44, 0xC6,                                   #   CMOVE EAX, ESI
        0xAA,                                               #   STOSB
        0x49,                                               #   DEC ECX
        0x74, 0x07,                                         #   JE shellcode_begin
        0x4A,                                               #   DEC EDX
        0x75, 0xF2,                                         #   JNE loop2
        0x43,                                               #   INC EBX
        0x43,                                               #   INC EBX
        0xEB, 0xE3                                          #   JMP loop1
                                                            # shellcode_begin:
    ])

    new_shellcode_pieces = []
    pos = 0

    for i in range(len(bytes_blocks) / 2):
        missing_char = chr(bytes_blocks[i*2])
        num_bytes = 254 * bytes_blocks[i*2 + 1]
        new_shellcode_pieces.append(shellcode[pos:pos+num_bytes].replace('\0', missing_char))
        pos += num_bytes

    return ''.join([chr(x) for x in code]) + ''.join(new_shellcode_pieces)


def main():
    print "Shellcode Extractor by %s (%d)\n" % (author, year)

    if len(sys.argv) != 3:
        print 'Usage:\n' + \
              '  %s <exe file> <map file>\n' % os.path.basename(sys.argv[0])
        return

    exe_file = sys.argv[1]
    map_file = sys.argv[2]

    print 'Extracting shellcode length from "%s"...' % os.path.basename(map_file)
    shellcode_len = get_shellcode_len(map_file)
    if shellcode_len is None:
        return

    print 'shellcode length: %d' % shellcode_len

    print 'Extracting shellcode from "%s" and analyzing relocations...' % os.path.basename(exe_file)

    result = get_shellcode_and_relocs(exe_file, shellcode_len)
    if result is None:

        return

    (shellcode, relocs, addr_to_strings) = result

    if len(relocs) != 0:
        print 'Found %d reference(s) to %d string(s) in .rdata' % (len(relocs), len(addr_to_strings))
        print 'Strings:'

        for s in addr_to_strings.values():
            print '  ' + s[:-1]
        print ''
        shellcode = add_loader_to_shellcode(shellcode, relocs, addr_to_strings)
    else:
        print 'No relocations found'


    if shellcode.find('\0') == -1:
        print 'Unbelievable: the shellcode does not need to be fixed!'
        fixed_shellcode = shellcode
    else:
        # shellcode 包含空字节需要修复.
        print 'Fixing the shellcode...'
        fixed_shellcode = get_fixed_shellcode_single_block(shellcode)

        if fixed_shellcode is None:             # 如果shellcode没有修复...
            fixed_shellcode = get_fixed_shellcode(shellcode)
            if fixed_shellcode is None:
                print '[!] Cannot fix the shellcode'


    print 'final shellcode length: %d\n' % len(fixed_shellcode)
    print 'char shellcode[] = '

    dump_shellcode(fixed_shellcode)

main()


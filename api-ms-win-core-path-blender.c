/*
 * Copyright 2024 Alan Wong(okt04175/alan2350)
 * 
 * Licensed under LGPL 2.1; see notice below
 * 
 * Original code copyright:
 * 
 * Copyright 2021 Alexandru Naiman
 * Copyright 2018 Nikolay Sivov
 * Copyright 2018 Zhiyi Zhang
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 * 
 */
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windows.h"
#include "winbase.h"
#include "winnls.h"
#include "winternl.h"
#include "winerror.h"
#include "ddk/wdm.h"

#include "kernelbase.h"

//#include <memoryapi.h>
//#pragma comment(lib, "memoryapi.lib")

#ifdef _WIN64
#define DLLAPI
#else
#define DLLAPI	__stdcall
#endif

#define FILE_MAP_COPY                           0x00000001
#define FILE_MAP_WRITE                          0x00000002
#define FILE_MAP_READ                           0x00000004
#define FILE_MAP_ALL_ACCESS                     0x000f001f
#define FILE_MAP_EXECUTE                        0x00000020
#define FILE_MAP_RESERVE                        0x80000000
#define FILE_MAP_TARGETS_INVALID                0x40000000
#define FILE_MAP_LARGE_PAGES                    0x20000000

#define FILE_CACHE_FLAGS_DEFINED
#define FILE_CACHE_MAX_HARD_ENABLE              0x00000001
#define FILE_CACHE_MAX_HARD_DISABLE             0x00000002
#define FILE_CACHE_MIN_HARD_ENABLE              0x00000004
#define FILE_CACHE_MIN_HARD_DISABLE             0x00000008

typedef enum WIN32_MEMORY_INFORMATION_CLASS
{
    MemoryRegionInfo
} WIN32_MEMORY_INFORMATION_CLASS;

typedef struct WIN32_MEMORY_REGION_INFORMATION
{
    PVOID AllocationBase;
    ULONG AllocationProtect;
    union
    {
        ULONG Flags;
        struct
        {
            ULONG Private : 1;
            ULONG MappedDataFile : 1;
            ULONG MappedImage : 1;
            ULONG MappedPageFile : 1;
            ULONG MappedPhysical : 1;
            ULONG DirectMapped : 1;
            ULONG Reserved : 26;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    SIZE_T RegionSize;
    SIZE_T CommitSize;
} WIN32_MEMORY_REGION_INFORMATION;

DWORD WINAPI DiscardVirtualMemory(void *addr, SIZE_T size);
BOOL WINAPI QueryVirtualMemoryInformation(HANDLE process,const void *addr,
        WIN32_MEMORY_INFORMATION_CLASS info_class, void *info, SIZE_T size, SIZE_T *ret_size);

#define STRSAFE_E_INSUFFICIENT_BUFFER ((HRESULT)0x8007007AL)

#define CreateFileMapping CreateFileMappingW
#define IsBadStringPtr IsBadStringPtrW
#define OpenFileMapping OpenFileMappingW

BOOL DLLAPI MapUserPhysicalPages(PVOID,ULONG_PTR,PULONG_PTR);
LPVOID DLLAPI MapViewOfFile(HANDLE,DWORD,DWORD,DWORD,SIZE_T);
LPVOID DLLAPI MapViewOfFile3(HANDLE,HANDLE,PVOID,ULONG64,SIZE_T,ULONG,ULONG,MEM_EXTENDED_PARAMETER*,ULONG);
LPVOID DLLAPI MapViewOfFileEx(HANDLE,DWORD,DWORD,DWORD,SIZE_T,LPVOID);
LPVOID DLLAPI MapViewOfFileFromApp(HANDLE,ULONG,ULONG64,SIZE_T);
BOOL DLLAPI UnmapViewOfFile(LPCVOID);
BOOL DLLAPI UnmapViewOfFile2(HANDLE,PVOID,ULONG);
BOOL DLLAPI UnmapViewOfFileEx(PVOID,ULONG);
LPVOID DLLAPI VirtualAlloc(LPVOID,SIZE_T,DWORD,DWORD);
LPVOID DLLAPI VirtualAlloc2(HANDLE,LPVOID,SIZE_T,DWORD,DWORD,MEM_EXTENDED_PARAMETER*,ULONG);
LPVOID DLLAPI VirtualAlloc2FromApp(HANDLE,LPVOID,SIZE_T,DWORD,DWORD,MEM_EXTENDED_PARAMETER*,ULONG);
LPVOID DLLAPI VirtualAllocEx(HANDLE,LPVOID,SIZE_T,DWORD,DWORD);
LPVOID DLLAPI VirtualAllocExNuma(HANDLE,void*,SIZE_T,DWORD,DWORD,DWORD);
LPVOID DLLAPI VirtualAllocFromApp(LPVOID,SIZE_T,DWORD,DWORD);
BOOL DLLAPI VirtualFree(LPVOID,SIZE_T,DWORD);
BOOL DLLAPI VirtualFreeEx(HANDLE,LPVOID,SIZE_T,DWORD);
BOOL DLLAPI VirtualLock(LPVOID,SIZE_T);
BOOL DLLAPI VirtualProtect(LPVOID,SIZE_T,DWORD,LPDWORD);
BOOL DLLAPI VirtualProtectEx(HANDLE,LPVOID,SIZE_T,DWORD,LPDWORD);
SIZE_T DLLAPI VirtualQuery(LPCVOID,PMEMORY_BASIC_INFORMATION,SIZE_T);
SIZE_T DLLAPI VirtualQueryEx(HANDLE,LPVOID,SIZE_T,DWORD,LPDWORD);
BOOL DLLAPI VirtualUnlock(LPVOID,SIZE_T);
BOOL DLLAPI FlushViewOfFile(LPVOID,SIZE_T);
BOOL DLLAPI FlushInstructionCache(HANDLE,LPCVOID,SIZE_T);
HANDLE DLLAPI CreateFileMappingW(HANDLE,LPSECURITY_ATTRIBUTES,DWORD,DWORD,DWORD,LPCWSTR);
HANDLE DLLAPI CreateFileMappingFromApp(HANDLE,PSECURITY_ATTRIBUTES,ULONG,ULONG64,PCWSTR);
HANDLE DLLAPI OpenFileMappingW(DWORD,BOOL,LPCWSTR);
HANDLE DLLAPI OpenFileMappingFromApp(ULONG,BOOL,LPCWSTR);
VOID DLLAPI GetNativeSystemInfo(LPSYSTEM_INFO);
VOID DLLAPI GetSystemInfo(LPSYSTEM_INFO);
UINT DLLAPI GetWriteWatch(DWORD,LPVOID,SIZE_T,LPVOID*,ULONG_PTR*,ULONG*);
UINT DLLAPI ResetWriteWatch(LPVOID,SIZE_T*);
BOOL DLLAPI ReadProcessMemory(HANDLE,LPCVOID,LPVOID,SIZE_T,SIZE_T*);
BOOL DLLAPI WriteProcessMemory(HANDLE,LPVOID,LPCVOID,SIZE_T,SIZE_T*);
BOOL DLLAPI IsBadStringPtrA(LPCSTR,UINT_PTR);
BOOL DLLAPI IsBadStringPtrW(LPCWSTR,UINT_PTR);
HANDLE DLLAPI CreateMemoryResourceNotification(MEMORY_RESOURCE_NOTIFICATION_TYPE);
BOOL DLLAPI QueryMemoryResourceNotification(HANDLE,PBOOL);
BOOL DLLAPI GetLogicalProcessorInformation(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION,PDWORD);
BOOL DLLAPI GetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP,PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,PDWORD);
BOOL DLLAPI GetSystemCpuSetInformation(SYSTEM_CPU_SET_INFORMATION*,ULONG,ULONG*,HANDLE,ULONG);
BOOL DLLAPI GetNumaNodeProcessorMaskEx(USHORT,PGROUP_AFFINITY);
BOOL DLLAPI GetNumaProximityNodeEx(ULONG,PUSHORT);


/***********************************************************************
 * Virtual memory functions
 ***********************************************************************/

static const SIZE_T page_mask = 0xfff;
#define ROUND_ADDR(addr) ((void *)((UINT_PTR)(addr) & ~page_mask))
#define ROUND_SIZE(addr,size) (((SIZE_T)(size) + ((UINT_PTR)(addr) & page_mask) + page_mask) & ~page_mask)

/***********************************************************************
 *             DiscardVirtualMemory   (kernelbase.@)
 */
DWORD WINAPI DECLSPEC_HOTPATCH DiscardVirtualMemory( void *addr, SIZE_T size )
{
    NTSTATUS status;
    LPVOID ret = addr;

    status = NtAllocateVirtualMemory( GetCurrentProcess(), &ret, 0, &size, MEM_RESET, PAGE_NOACCESS );
    return RtlNtStatusToDosError( status );
}


/***********************************************************************
 *             FlushViewOfFile   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH FlushViewOfFile( const void *base, SIZE_T size )
{
    NTSTATUS status = NtFlushVirtualMemory( GetCurrentProcess(), &base, &size, 0 );

    if (status == STATUS_NOT_MAPPED_DATA) status = STATUS_SUCCESS;
    return set_ntstatus( status );
}


/****************************************************************************
 *           FlushInstructionCache   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH FlushInstructionCache( HANDLE process, LPCVOID addr, SIZE_T size )
{
    CROSS_PROCESS_WORK_LIST *list;

    if ((list = open_cross_process_connection( process )))
    {
        send_cross_process_notification( list, CrossProcessFlushCache, addr, size, 0 );
        close_cross_process_connection( list );
    }
    return set_ntstatus( NtFlushInstructionCache( process, addr, size ));
}


/***********************************************************************
 *          GetLargePageMinimum   (kernelbase.@)
 */
SIZE_T WINAPI GetLargePageMinimum(void)
{
    return 2 * 1024 * 1024;
}


static void fill_system_info( SYSTEM_INFO *si, const SYSTEM_BASIC_INFORMATION *basic_info,
                              const SYSTEM_CPU_INFORMATION *cpu_info )
{
    si->wProcessorArchitecture      = cpu_info->ProcessorArchitecture;
    si->wReserved                   = 0;
    si->dwPageSize                  = basic_info->PageSize;
    si->lpMinimumApplicationAddress = basic_info->LowestUserAddress;
    si->lpMaximumApplicationAddress = basic_info->HighestUserAddress;
    si->dwActiveProcessorMask       = basic_info->ActiveProcessorsAffinityMask;
    si->dwNumberOfProcessors        = basic_info->NumberOfProcessors;
    si->dwAllocationGranularity     = basic_info->AllocationGranularity;
    si->wProcessorLevel             = cpu_info->ProcessorLevel;
    si->wProcessorRevision          = cpu_info->

    switch (cpu_info->ProcessorArchitecture)
    {
    case PROCESSOR_ARCHITECTURE_INTEL:
        switch (cpu_info->ProcessorLevel)
        {
        case 3:  si->dwProcessorType = PROCESSOR_INTEL_386;     break;
        case 4:  si->dwProcessorType = PROCESSOR_INTEL_486;     break;
        case 5:
        case 6:  si->dwProcessorType = PROCESSOR_INTEL_PENTIUM; break;
        default: si->dwProcessorType = PROCESSOR_INTEL_PENTIUM; break;
        }
        break;
    case PROCESSOR_ARCHITECTURE_AMD64:
        si->dwProcessorType = PROCESSOR_AMD_X8664;
        break;
    case PROCESSOR_ARCHITECTURE_ARM:
        switch (cpu_info->ProcessorLevel)
        {
        case 4:  si->dwProcessorType = PROCESSOR_ARM_7TDMI;     break;
        default: si->dwProcessorType = PROCESSOR_ARM920;
        }
        break;
    case PROCESSOR_ARCHITECTURE_ARM64:
        si->dwProcessorType = 0;
        break;
    default:
        FIXME( "Unknown processor architecture %x\n", cpu_info->ProcessorArchitecture );
        si->dwProcessorType = 0;
        break;
    }
}


/***********************************************************************
 *          GetNativeSystemInfo   (kernelbase.@)
 */
void WINAPI DECLSPEC_HOTPATCH GetNativeSystemInfo( SYSTEM_INFO *si )
{
    SYSTEM_BASIC_INFORMATION basic_info;
    SYSTEM_CPU_INFORMATION cpu_info;

    if (is_wow64)
    {
        USHORT current_machine, native_machine;

        RtlWow64GetProcessMachines( 0, &current_machine, &native_machine );
        if (native_machine != IMAGE_FILE_MACHINE_AMD64)
        {
            GetSystemInfo( si );
            si->wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
            return;
        }
    }

    if (!set_ntstatus( RtlGetNativeSystemInformation( SystemBasicInformation,
                                                      &basic_info, sizeof(basic_info), NULL )) ||
        !set_ntstatus( RtlGetNativeSystemInformation( SystemCpuInformation,
                                                      &cpu_info, sizeof(cpu_info), NULL )))
        return;

    fill_system_info( si, &basic_info, &cpu_info );
}


/***********************************************************************
 *          GetSystemInfo   (kernelbase.@)
 */
void WINAPI DECLSPEC_HOTPATCH GetSystemInfo( SYSTEM_INFO *si )
{
    SYSTEM_BASIC_INFORMATION basic_info;
    SYSTEM_CPU_INFORMATION cpu_info;

    if (!set_ntstatus( NtQuerySystemInformation( SystemBasicInformation,
                                                 &basic_info, sizeof(basic_info), NULL )) ||
        !set_ntstatus( NtQuerySystemInformation( SystemCpuInformation,
                                                 &cpu_info, sizeof(cpu_info), NULL )))
        return;

    fill_system_info( si, &basic_info, &cpu_info );
}


/***********************************************************************
 *          GetSystemFileCacheSize   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH GetSystemFileCacheSize( SIZE_T *mincache, SIZE_T *maxcache, DWORD *flags )
{
    FIXME( "stub: %p %p %p\n", mincache, maxcache, flags );
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return FALSE;
}


/***********************************************************************
 *             GetWriteWatch   (kernelbase.@)
 */
UINT WINAPI DECLSPEC_HOTPATCH GetWriteWatch( DWORD flags, void *base, SIZE_T size, void **addresses,
                                             ULONG_PTR *count, ULONG *granularity )
{
    if (!set_ntstatus( NtGetWriteWatch( GetCurrentProcess(), flags, base, size,
                                        addresses, count, granularity )))
        return ~0u;
    return 0;
}


/***********************************************************************
 *             MapViewOfFile   (kernelbase.@)
 */
LPVOID WINAPI DECLSPEC_HOTPATCH MapViewOfFile( HANDLE mapping, DWORD access, DWORD offset_high,
                                               DWORD offset_low, SIZE_T count )
{
    return MapViewOfFileEx( mapping, access, offset_high, offset_low, count, NULL );
}


/***********************************************************************
 *             MapViewOfFileEx   (kernelbase.@)
 */
LPVOID WINAPI DECLSPEC_HOTPATCH MapViewOfFileEx( HANDLE handle, DWORD access, DWORD offset_high,
                                                 DWORD offset_low, SIZE_T count, LPVOID addr )
{
    NTSTATUS status;
    LARGE_INTEGER offset;
    ULONG protect;
    BOOL exec;

    offset.u.LowPart  = offset_low;
    offset.u.HighPart = offset_high;

    exec = access & FILE_MAP_EXECUTE;
    access &= ~FILE_MAP_EXECUTE;

    if (access == FILE_MAP_COPY)
        protect = exec ? PAGE_EXECUTE_WRITECOPY : PAGE_WRITECOPY;
    else if (access & FILE_MAP_WRITE)
        protect = exec ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
    else if (access & FILE_MAP_READ)
        protect = exec ? PAGE_EXECUTE_READ : PAGE_READONLY;
    else protect = PAGE_NOACCESS;

    if ((status = NtMapViewOfSection( handle, GetCurrentProcess(), &addr, 0, 0, &offset,
                                      &count, ViewShare, 0, protect )) < 0)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        addr = NULL;
    }
    return addr;
}


/***********************************************************************
 *             MapViewOfFileFromApp   (kernelbase.@)
 */
LPVOID WINAPI DECLSPEC_HOTPATCH MapViewOfFileFromApp( HANDLE handle, ULONG access, ULONG64 offset, SIZE_T size )
{
    return MapViewOfFile( handle, access, offset << 32, offset, size );
}


/***********************************************************************
 *             MapViewOfFile3   (kernelbase.@)
 */
LPVOID WINAPI DECLSPEC_HOTPATCH MapViewOfFile3( HANDLE handle, HANDLE process, PVOID baseaddr, ULONG64 offset,
        SIZE_T size, ULONG alloc_type, ULONG protection, MEM_EXTENDED_PARAMETER *params, ULONG params_count )
{
    LARGE_INTEGER off;
    void *addr;

    if (!process) process = GetCurrentProcess();

    addr = baseaddr;
    off.QuadPart = offset;
    if (!set_ntstatus( NtMapViewOfSectionEx( handle, process, &addr, &off, &size, alloc_type, protection,
            params, params_count )))
    {
        return NULL;
    }
    return addr;
}

/***********************************************************************
 *	       ReadProcessMemory   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH ReadProcessMemory( HANDLE process, const void *addr, void *buffer,
                                                 SIZE_T size, SIZE_T *bytes_read )
{
    return set_ntstatus( NtReadVirtualMemory( process, addr, buffer, size, bytes_read ));
}


/***********************************************************************
 *             ResetWriteWatch   (kernelbase.@)
 */
UINT WINAPI DECLSPEC_HOTPATCH ResetWriteWatch( void *base, SIZE_T size )
{
    if (!set_ntstatus( NtResetWriteWatch( GetCurrentProcess(), base, size )))
        return ~0u;
    return 0;
}


/***********************************************************************
 *          SetSystemFileCacheSize   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH SetSystemFileCacheSize( SIZE_T mincache, SIZE_T maxcache, DWORD flags )
{
    FIXME( "stub: %Id %Id %ld\n", mincache, maxcache, flags );
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return FALSE;
}


/***********************************************************************
 *             UnmapViewOfFile   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH UnmapViewOfFile( const void *addr )
{
    if (GetVersion() & 0x80000000)
    {
        MEMORY_BASIC_INFORMATION info;
        if (!VirtualQuery( addr, &info, sizeof(info) ) || info.AllocationBase != addr)
        {
            SetLastError( ERROR_INVALID_ADDRESS );
            return FALSE;
        }
    }
    return set_ntstatus( NtUnmapViewOfSection( GetCurrentProcess(), (void *)addr ));
}


/***********************************************************************
 *             UnmapViewOfFile2   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH UnmapViewOfFile2( HANDLE process, void *addr, ULONG flags )
{
    return set_ntstatus( NtUnmapViewOfSectionEx( process, addr, flags ));
}


/***********************************************************************
 *             UnmapViewOfFileEx   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH UnmapViewOfFileEx( void *addr, ULONG flags )
{
    return set_ntstatus( NtUnmapViewOfSectionEx( GetCurrentProcess(), addr, flags ));
}


/***********************************************************************
 *             VirtualAlloc   (kernelbase.@)
 */
LPVOID WINAPI DECLSPEC_HOTPATCH VirtualAlloc( void *addr, SIZE_T size, DWORD type, DWORD protect )
{
    return VirtualAllocEx( GetCurrentProcess(), addr, size, type, protect );
}


/***********************************************************************
 *             VirtualAllocEx   (kernelbase.@)
 */
LPVOID WINAPI DECLSPEC_HOTPATCH VirtualAllocEx( HANDLE process, void *addr, SIZE_T size,
                                                DWORD type, DWORD protect )
{
    LPVOID ret = addr;

    if (!set_ntstatus( NtAllocateVirtualMemory( process, &ret, 0, &size, type, protect ))) return NULL;
    return ret;
}


/***********************************************************************
 *             VirtualAlloc2   (kernelbase.@)
 */
LPVOID WINAPI DECLSPEC_HOTPATCH VirtualAlloc2( HANDLE process, void *addr, SIZE_T size,
                                               DWORD type, DWORD protect,
                                               MEM_EXTENDED_PARAMETER *parameters, ULONG count )
{
    LPVOID ret = addr;

    if (!process) process = GetCurrentProcess();
    if (!set_ntstatus( NtAllocateVirtualMemoryEx( process, &ret, &size, type, protect, parameters, count )))
        return NULL;
    return ret;
}

static BOOL is_exec_prot( DWORD protect )
{
    return protect == PAGE_EXECUTE || protect == PAGE_EXECUTE_READ || protect == PAGE_EXECUTE_READWRITE
            || protect == PAGE_EXECUTE_WRITECOPY;
}

/***********************************************************************
 *             VirtualAlloc2FromApp   (kernelbase.@)
 */
LPVOID WINAPI DECLSPEC_HOTPATCH VirtualAlloc2FromApp( HANDLE process, void *addr, SIZE_T size,
        DWORD type, DWORD protect, MEM_EXTENDED_PARAMETER *parameters, ULONG count )
{
    LPVOID ret = addr;

    TRACE_(virtual)( "addr %p, size %p, type %#lx, protect %#lx, params %p, count %lu.\n", addr, (void *)size, type, protect,
            parameters, count );

    if (is_exec_prot( protect ))
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return NULL;
    }

    if (!process) process = GetCurrentProcess();
    if (!set_ntstatus( NtAllocateVirtualMemoryEx( process, &ret, &size, type, protect, parameters, count )))
        return NULL;
    return ret;
}


/***********************************************************************
 *             VirtualAllocFromApp   (kernelbase.@)
 */
LPVOID WINAPI DECLSPEC_HOTPATCH VirtualAllocFromApp( void *addr, SIZE_T size,
                                                DWORD type, DWORD protect )
{
    LPVOID ret = addr;

    TRACE_(virtual)( "addr %p, size %p, type %#lx, protect %#lx.\n", addr, (void *)size, type, protect );

    if (is_exec_prot( protect ))
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return NULL;
    }

    if (!set_ntstatus( NtAllocateVirtualMemory( GetCurrentProcess(), &ret, 0, &size, type, protect ))) return NULL;
    return ret;
}


/***********************************************************************
 *             PrefetchVirtualMemory   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH PrefetchVirtualMemory( HANDLE process, ULONG_PTR count,
                                                     WIN32_MEMORY_RANGE_ENTRY *addresses, ULONG flags )
{
    return set_ntstatus( NtSetInformationVirtualMemory( process, VmPrefetchInformation,
                                                        count, (PMEMORY_RANGE_ENTRY)addresses,
                                                        &flags, sizeof(flags) ));
}


/***********************************************************************
 *             VirtualFree   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH VirtualFree( void *addr, SIZE_T size, DWORD type )
{
    return VirtualFreeEx( GetCurrentProcess(), addr, size, type );
}


/***********************************************************************
 *             VirtualFreeEx   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH VirtualFreeEx( HANDLE process, void *addr, SIZE_T size, DWORD type )
{
    if (type == MEM_RELEASE && size)
    {
        WARN( "Trying to release memory with specified size.\n" );
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }
    return set_ntstatus( NtFreeVirtualMemory( process, &addr, &size, type ));
}


/***********************************************************************
 *             VirtualLock   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH  VirtualLock( void *addr, SIZE_T size )
{
    return set_ntstatus( NtLockVirtualMemory( GetCurrentProcess(), &addr, &size, 1 ));
}


/***********************************************************************
 *             VirtualProtect   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH VirtualProtect( void *addr, SIZE_T size, DWORD new_prot, DWORD *old_prot )
{
    return VirtualProtectEx( GetCurrentProcess(), addr, size, new_prot, old_prot );
}


/***********************************************************************
 *             VirtualProtectEx   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH VirtualProtectEx( HANDLE process, void *addr, SIZE_T size,
                                                DWORD new_prot, DWORD *old_prot )
{
    DWORD prot;

    /* Win9x allows passing NULL as old_prot while this fails on NT */
    if (!old_prot && (GetVersion() & 0x80000000)) old_prot = &prot;
    return set_ntstatus( NtProtectVirtualMemory( process, &addr, &size, new_prot, old_prot ));
}


/***********************************************************************
 *             VirtualQuery   (kernelbase.@)
 */
SIZE_T WINAPI DECLSPEC_HOTPATCH VirtualQuery( LPCVOID addr, PMEMORY_BASIC_INFORMATION info, SIZE_T len )
{
    return VirtualQueryEx( GetCurrentProcess(), addr, info, len );
}


/***********************************************************************
 *             VirtualQueryEx   (kernelbase.@)
 */
SIZE_T WINAPI DECLSPEC_HOTPATCH VirtualQueryEx( HANDLE process, LPCVOID addr,
                                                PMEMORY_BASIC_INFORMATION info, SIZE_T len )
{
    SIZE_T ret;

    if (!set_ntstatus( NtQueryVirtualMemory( process, addr, MemoryBasicInformation, info, len, &ret )))
        return 0;
    return ret;
}


/***********************************************************************
 *             VirtualUnlock   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH VirtualUnlock( void *addr, SIZE_T size )
{
    return set_ntstatus( NtUnlockVirtualMemory( GetCurrentProcess(), &addr, &size, 1 ));
}


/***********************************************************************
 *             WriteProcessMemory    (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH WriteProcessMemory( HANDLE process, void *addr, const void *buffer,
                                                  SIZE_T size, SIZE_T *bytes_written )
{
    CROSS_PROCESS_WORK_LIST *list = open_cross_process_connection( process );
    DWORD old_prot, prot = PAGE_TARGETS_NO_UPDATE | PAGE_ENCLAVE_NO_CHANGE;
    MEMORY_BASIC_INFORMATION info;
    void *base_addr;
    SIZE_T region_size;
    NTSTATUS status, status2;

    if (!VirtualQueryEx( process, addr, &info, sizeof(info) ))
    {
        close_cross_process_connection( list );
        return FALSE;
    }

    switch (info.Protect & ~(PAGE_GUARD | PAGE_NOCACHE))
    {
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        /* already writable */
        if ((status = NtWriteVirtualMemory( process, addr, buffer, size, bytes_written ))) break;
        send_cross_process_notification( list, CrossProcessFlushCache, addr, size, 0 );
        NtFlushInstructionCache( process, addr, size );
        break;

    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
        /* make it writable */
        base_addr = ROUND_ADDR( addr );
        region_size = ROUND_SIZE( addr, size );
        region_size = min( region_size,  (char *)info.BaseAddress + info.RegionSize - (char *)base_addr );
        prot |= (info.Type == MEM_PRIVATE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_WRITECOPY;

        send_cross_process_notification( list, CrossProcessPreVirtualProtect,
                                         base_addr, region_size, 1, prot );
        status = NtProtectVirtualMemory( process, &base_addr, &region_size, prot, &old_prot );
        send_cross_process_notification( list, CrossProcessPostVirtualProtect,
                                         base_addr, region_size, 2, prot, status );
        if (status) break;

        status = NtWriteVirtualMemory( process, addr, buffer, size, bytes_written );
        if (!status)
        {
            send_cross_process_notification( list, CrossProcessFlushCache, addr, size, 0 );
            NtFlushInstructionCache( process, addr, size );
        }

        prot = PAGE_TARGETS_NO_UPDATE | PAGE_ENCLAVE_NO_CHANGE | old_prot;
        send_cross_process_notification( list, CrossProcessPreVirtualProtect,
                                         base_addr, region_size, 1, prot );
        status2 = NtProtectVirtualMemory( process, &base_addr, &region_size, prot, &old_prot );
        send_cross_process_notification( list, CrossProcessPostVirtualProtect,
                                         base_addr, region_size, 2, prot, status2 );
        break;

    default:
        /* not writable */
        status = STATUS_ACCESS_VIOLATION;
        break;
    }

    close_cross_process_connection( list );
    return set_ntstatus( status );
}


/* IsBadStringPtrA replacement for kernelbase, to catch exception in debug traces. */
BOOL WINAPI IsBadStringPtrA( LPCSTR str, UINT_PTR max )
{
    if (!str) return TRUE;
    __TRY
    {
        volatile const char *p = str;
        while (p != str + max) if (!*p++) break;
    }
    __EXCEPT_PAGE_FAULT
    {
        return TRUE;
    }
    __ENDTRY
    return FALSE;
}


/* IsBadStringPtrW replacement for kernelbase, to catch exception in debug traces. */
BOOL WINAPI IsBadStringPtrW( LPCWSTR str, UINT_PTR max )
{
    if (!str) return TRUE;
    __TRY
    {
        volatile const WCHAR *p = str;
        while (p != str + max) if (!*p++) break;
    }
    __EXCEPT_PAGE_FAULT
    {
        return TRUE;
    }
    __ENDTRY
    return FALSE;
}


/***********************************************************************
 * Memory resource functions
 ***********************************************************************/


/***********************************************************************
 *           CreateMemoryResourceNotification   (kernelbase.@)
 */
HANDLE WINAPI DECLSPEC_HOTPATCH CreateMemoryResourceNotification( MEMORY_RESOURCE_NOTIFICATION_TYPE type )
{
    HANDLE ret;
    UNICODE_STRING nameW;
    OBJECT_ATTRIBUTES attr;

    switch (type)
    {
    case LowMemoryResourceNotification:
        RtlInitUnicodeString( &nameW, L"\\KernelObjects\\LowMemoryCondition" );
        break;
    case HighMemoryResourceNotification:
        RtlInitUnicodeString( &nameW, L"\\KernelObjects\\HighMemoryCondition" );
        break;
    default:
        SetLastError( ERROR_INVALID_PARAMETER );
        return 0;
    }

    InitializeObjectAttributes( &attr, &nameW, 0, 0, NULL );
    if (!set_ntstatus( NtOpenEvent( &ret, EVENT_ALL_ACCESS, &attr ))) return 0;
    return ret;
}

/***********************************************************************
 *          QueryMemoryResourceNotification   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH QueryMemoryResourceNotification( HANDLE handle, BOOL *state )
{
    switch (WaitForSingleObject( handle, 0 ))
    {
    case WAIT_OBJECT_0:
        *state = TRUE;
        return TRUE;
    case WAIT_TIMEOUT:
        *state = FALSE;
        return TRUE;
    }
    SetLastError( ERROR_INVALID_PARAMETER );
    return FALSE;
}


/***********************************************************************
 * NUMA functions
 ***********************************************************************/


/***********************************************************************
 *             AllocateUserPhysicalPagesNuma   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH AllocateUserPhysicalPagesNuma( HANDLE process, ULONG_PTR *pages,
                                                             ULONG_PTR *userarray, DWORD node )
{
    if (node) FIXME( "Ignoring preferred node %lu\n", node );
    return AllocateUserPhysicalPages( process, pages, userarray );
}


/***********************************************************************
 *             CreateFileMappingNumaW   (kernelbase.@)
 */
HANDLE WINAPI DECLSPEC_HOTPATCH CreateFileMappingNumaW( HANDLE file, LPSECURITY_ATTRIBUTES sa,
                                                        DWORD protect, DWORD size_high, DWORD size_low,
                                                        LPCWSTR name, DWORD node )
{
    if (node) FIXME( "Ignoring preferred node %lu\n", node );
    return CreateFileMappingW( file, sa, protect, size_high, size_low, name );
}


/***********************************************************************
 *           GetLogicalProcessorInformation   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH GetLogicalProcessorInformation( SYSTEM_LOGICAL_PROCESSOR_INFORMATION *buffer,
                                                              DWORD *len )
{
    NTSTATUS status;

    if (!len)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }
    status = NtQuerySystemInformation( SystemLogicalProcessorInformation, buffer, *len, len );
    if (status == STATUS_INFO_LENGTH_MISMATCH) status = STATUS_BUFFER_TOO_SMALL;
    return set_ntstatus( status );
}


/***********************************************************************
 *           GetLogicalProcessorInformationEx   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH GetLogicalProcessorInformationEx( LOGICAL_PROCESSOR_RELATIONSHIP relationship,
                                            SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *buffer, DWORD *len )
{
    NTSTATUS status;

    if (!len)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }
    status = NtQuerySystemInformationEx( SystemLogicalProcessorInformationEx, &relationship,
                                         sizeof(relationship), buffer, *len, len );
    if (status == STATUS_INFO_LENGTH_MISMATCH) status = STATUS_BUFFER_TOO_SMALL;
    return set_ntstatus( status );
}


/***********************************************************************
 *           GetSystemCpuSetInformation   (kernelbase.@)
 */
BOOL WINAPI GetSystemCpuSetInformation(SYSTEM_CPU_SET_INFORMATION *info, ULONG buffer_length, ULONG *return_length,
                                            HANDLE process, ULONG flags)
{
    if (flags)
        FIXME("Unsupported flags %#lx.\n", flags);

    *return_length = 0;

    return set_ntstatus( NtQuerySystemInformationEx( SystemCpuSetInformation, &process, sizeof(process), info,
            buffer_length, return_length ));
}


/***********************************************************************
 *           SetThreadSelectedCpuSets   (kernelbase.@)
 */
BOOL WINAPI SetThreadSelectedCpuSets(HANDLE thread, const ULONG *cpu_set_ids, ULONG count)
{
    FIXME( "thread %p, cpu_set_ids %p, count %lu stub.\n", thread, cpu_set_ids, count );

    return TRUE;
}


/***********************************************************************
 *           SetProcessDefaultCpuSets   (kernelbase.@)
 */
BOOL WINAPI SetProcessDefaultCpuSets(HANDLE process, const ULONG *cpu_set_ids, ULONG count)
{
    FIXME( "process %p, cpu_set_ids %p, count %lu stub.\n", process, cpu_set_ids, count );

    return TRUE;
}


/**********************************************************************
 *             GetNumaHighestNodeNumber   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH GetNumaHighestNodeNumber( ULONG *node )
{
    FIXME( "semi-stub: %p\n", node );
    *node = 0;
    return TRUE;
}


/**********************************************************************
 *             GetNumaNodeProcessorMaskEx   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH GetNumaNodeProcessorMaskEx( USHORT node, GROUP_AFFINITY *mask )
{
    FIXME( "stub: %hu %p\n", node, mask );
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return FALSE;
}


/***********************************************************************
 *             GetNumaProximityNodeEx   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH GetNumaProximityNodeEx( ULONG proximity_id, USHORT *node )
{
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return FALSE;
}


/***********************************************************************
 *             MapViewOfFileExNuma   (kernelbase.@)
 */
LPVOID WINAPI DECLSPEC_HOTPATCH MapViewOfFileExNuma( HANDLE handle, DWORD access, DWORD offset_high,
                                                     DWORD offset_low, SIZE_T count, LPVOID addr,
                                                     DWORD node )
{
    if (node) FIXME( "Ignoring preferred node %lu\n", node );
    return MapViewOfFileEx( handle, access, offset_high, offset_low, count, addr );
}


/***********************************************************************
 *             VirtualAllocExNuma   (kernelbase.@)
 */
LPVOID WINAPI DECLSPEC_HOTPATCH VirtualAllocExNuma( HANDLE process, void *addr, SIZE_T size,
                                                    DWORD type, DWORD protect, DWORD node )
{
    if (node) FIXME( "Ignoring preferred node %lu\n", node );
    return VirtualAllocEx( process, addr, size, type, protect );
}


/***********************************************************************
 *             QueryVirtualMemoryInformation   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH QueryVirtualMemoryInformation( HANDLE process, const void *addr,
        WIN32_MEMORY_INFORMATION_CLASS info_class, void *info, SIZE_T size, SIZE_T *ret_size)
{
    switch (info_class)
    {
        case MemoryRegionInfo:
            return set_ntstatus( NtQueryVirtualMemory( process, addr, MemoryRegionInformation, info, size, ret_size ));
        default:
            FIXME("Unsupported info class %u.\n", info_class);
            return FALSE;
    }
}



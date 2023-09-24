#pragma once

#include <wdm.h>
#include <ntimage.h>

#include "definitions.h"

#ifdef _DEBUG
#define KD_PRINT(format, ...)               \
   DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s:%d] %s: " format,         \
             __FILE__,                      \
             __LINE__,                      \
             __FUNCTION__,                  \
             ##__VA_ARGS__)
#else
#define KD_PRINT(format, ...)
#endif

#define KD_LOG(format, ...)               \
   DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] " format,         \
               ##__VA_ARGS__)

namespace utils
{
    inline NTSTATUS get_kernel_module_base( const char* module_name, void** base, size_t* m_size )
    {
        ULONG size { };
        ZwQuerySystemInformation( kernel::SystemModuleInformation, nullptr, 0, &size );

        if ( !size )
            return STATUS_UNSUCCESSFUL;

        const auto modules {
            static_cast< kernel::_RTL_PROCESS_MODULES* >( ExAllocatePoolZero( NonPagedPool, size, ' MPR' ) )
        };

        if ( !modules )
        {
            ExFreePool( modules );
            return STATUS_UNSUCCESSFUL;
        }

        ZwQuerySystemInformation( kernel::SystemModuleInformation, modules, size, &size );

        for ( ULONG i = 0; i < modules->NumberOfModules; i++ )
        {
            if ( strstr( reinterpret_cast< const char* >( modules->Modules[ i ].FullPathName ), module_name ) !=
                nullptr )
            {
                *base = modules->Modules[ i ].ImageBase;
                *m_size = modules->Modules[ i ].ImageSize;
            }
        }

        ExFreePool( modules );

        if ( !size || !*base )
            return STATUS_UNSUCCESSFUL;

        return STATUS_SUCCESS;
    }

    inline uintptr_t get_kernel_base( )
    {
        uintptr_t base { };
        size_t size { };
        auto res = get_kernel_module_base( "ntoskrnl.exe", reinterpret_cast< void** >( &base ), &size );
        if ( !NT_SUCCESS( res ) )
        {
            res = get_kernel_module_base( "ntoskrnl.exe", reinterpret_cast< void** >( &base ), &size );
            if ( !NT_SUCCESS( res ) )
            {
                KD_PRINT( "Failed to get ntoskrnl base address (0x%08X)", res );
                return 0;
            }
        }

        return base;
    }

    inline bool pattern_at( const char* current, const char* pattern, const char* mask )
    {
        for ( ; *mask; ++mask, ++current, ++pattern )
            if ( *mask == 'x' && *current != *pattern )
                return false;

        return ( *mask ) == 0;
    }

    inline void* find_pattern_raw( const char* start, const char* end, const char* pattern, const char* mask )
    {
        if ( start == end || end <= start )
            return nullptr;

        auto current = const_cast< char* >( start );
        while ( current != end )
        {
            if ( pattern_at( current, pattern, mask ) )
                return current;

            current++;
        }

        return nullptr;
    }
}

#pragma once
#include <ntstatus.h>
#include <Ntstrsafe.h>
#include <wdm.h>

#include "utils.h"

namespace gds
{
    typedef PEPROCESS ( __fastcall*mm_get_session_by_id_t )( int session_id );
    constexpr ULONG mm_get_session_by_id_offset { 0x297320 };
    mm_get_session_by_id_t mm_get_session_by_id { };

    typedef NTSTATUS ( __fastcall*mi_attach_session_t )( kernel::_MM_SESSION_SPACE* session_space );
    constexpr ULONG mi_attach_session_offset { 0x2E9E38 };
    mi_attach_session_t mi_attach_session { };

    kernel::_MM_SESSION_SPACE* system_space { };
    kernel::_MM_SESSION_SPACE* session_space { };

    void init( )
    {
        const auto kernel_base = utils::get_kernel_base( );
        if ( !kernel_base )
        {
            KD_PRINT( "Failed to get kernel base\n" );
            return;
        }

        mm_get_session_by_id = reinterpret_cast< mm_get_session_by_id_t >( kernel_base + mm_get_session_by_id_offset );
        KD_PRINT( "mm_get_session_by_id: 0x%p\n", mm_get_session_by_id );

        mi_attach_session = reinterpret_cast< mi_attach_session_t >( kernel_base + mi_attach_session_offset );
        KD_PRINT( "mi_attach_session: 0x%p\n", mi_attach_session );

        PEPROCESS process = mm_get_session_by_id( 0 );
        PEPROCESS process_session_1 = mm_get_session_by_id( 1 );

        KD_PRINT( "process: 0x%p\n", process );
        KD_PRINT( "process_session_1: 0x%p\n", process_session_1 );

        system_space = *reinterpret_cast< kernel::_MM_SESSION_SPACE** >( reinterpret_cast<
            uintptr_t >( process ) + 0x558 );
        session_space = *reinterpret_cast< kernel::_MM_SESSION_SPACE** >( reinterpret_cast<
            uintptr_t >( process_session_1 ) + 0x558 );
    }

    uintptr_t get_guard_dispatch_icall_addr( const uintptr_t base,
                                             const size_t size )
    {
        return reinterpret_cast< uintptr_t >( utils::find_pattern_raw( reinterpret_cast< char* >( base ),
                                                                       reinterpret_cast< char* >( base + size ),
                                                                       "\x4C\x8B\x1D\x00\x00\x00\x00\x48\x85\xC0",
                                                                       "xxx????xxx" ) );
    }

    uintptr_t get_next_dispatch_call( uintptr_t start, const size_t n_bytes, const uintptr_t guard_dispatch_addr )
    {
        constexpr auto call_dispatch_size { 5 };
        auto current { reinterpret_cast< PUCHAR >( start ) };
        const auto end { reinterpret_cast< PUCHAR >( start + n_bytes - call_dispatch_size ) };
        while ( current < end )
        {
            if ( *current == 0xE8 )
            {
                const auto offset { *reinterpret_cast< int* >( current + 1 ) };
                const uintptr_t call_addr { reinterpret_cast< uintptr_t >( current + 5 + offset ) };

                if ( call_addr == guard_dispatch_addr )
                    return call_addr;
            }

            current++;
        }

        return NULL;
    }

    inline bool is_move_rax( const PUCHAR address )
    {
        return address[ 0 ] == 0x48 && address[ 1 ] == 0x8B && address[ 2 ] == 0x05;
    }

    void scan_module( const char* module_name, const uintptr_t base, const size_t size )
    {
        if ( base == 0 || size == 0 )
        {
            KD_PRINT( "Invalid module (%s) base or size\n", module_name );
            return;
        }

        // find _guard_dispatch_icall address
        const auto guard_dispatch_addr { get_guard_dispatch_icall_addr( base, size ) };
        if ( !guard_dispatch_addr )
            return;

        auto start { reinterpret_cast< PUCHAR >( base ) };
        const auto end { ( start + size ) - 0x20 };

        size_t count { 0 };

        // 0xC is the minimum size for a mov rax, <rel_32> and a call _guard_dispatch_icall
        while ( start < end )
        {
            if ( is_move_rax( start ) )
            {
                const auto offset { *reinterpret_cast< int* >( start + 3 ) };
                const auto data_pointer { start + 7 + offset };

                ( data_pointer );

                const auto next_dispatch_call {
                    get_next_dispatch_call( reinterpret_cast< uintptr_t >( start ), 0x20, guard_dispatch_addr )
                };

                if ( !next_dispatch_call )
                {
                    start++;
                    continue;
                }

                count++;
            }

            start++;
        }

        KD_PRINT( "Found %d calls to _guard_dispatch_icall\n\n", count );
    }

    void iterate_kernel_modules( )
    {
        ULONG size { };
        ZwQuerySystemInformation( kernel::SystemModuleInformation, nullptr, 0, &size );

        if ( !size )
            return;

        const auto modules {
            static_cast< kernel::_RTL_PROCESS_MODULES* >( ExAllocatePoolZero( NonPagedPool, size, ' MPR' ) )
        };

        if ( !modules )
            return;

        ZwQuerySystemInformation( kernel::SystemModuleInformation, modules, size, &size );

        for ( ULONG i = 0; i < modules->NumberOfModules; i++ )
        {
            if ( strstr( reinterpret_cast< const char* >( modules->Modules[ i ].FullPathName ),
                         "GuardDispatchScanner.sys" ) != nullptr )
            {
                KD_PRINT( "Skipping module: %s\n", modules->Modules[ i ].FullPathName );
                continue;
            }

            const auto base = reinterpret_cast< uintptr_t >( modules->Modules[ i ].ImageBase );

            const auto dos_header { reinterpret_cast< kernel::PIMAGE_DOS_HEADER >( base ) };
            const auto nt_headers { reinterpret_cast< kernel::PIMAGE_NT_HEADERS64 >( base + dos_header->e_lfanew ) };

            const auto n_sections = nt_headers->FileHeader.NumberOfSections;
            for ( auto j = 0; j < n_sections; j++ )
            {
                const auto section = IMAGE_FIRST_SECTION( nt_headers ) + j;
                const auto memory_start { base + section->VirtualAddress };
                const auto section_size { section->SizeOfRawData };

                if ( strstr( reinterpret_cast< const char* >( section->Name ), ".text" ) != nullptr )
                {
                    const auto mdl {
                        IoAllocateMdl( reinterpret_cast< PVOID >( memory_start ), section_size, false, false, nullptr )
                    };

                    MmProbeAndLockPages( mdl, KernelMode, IoReadAccess );

                    scan_module( reinterpret_cast< const char* >( modules->Modules[ i ].FullPathName ), memory_start,
                                 section_size );

                    MmUnlockPages( mdl );
                }
            }
        }

        ExFreePool( modules );
    }
}

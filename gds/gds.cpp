#include "gds.h"

namespace gds
{
    GdScanner::GdScanner( )
    {
        kernel_base_ = utils::get_kernel_base( );
        if ( !kernel_base_ )
            return;

        mm_get_session_by_id_ = reinterpret_cast< mm_get_session_by_id_t >( kernel_base_ +
            mm_get_session_by_id_offset_ );
        if ( !mm_get_session_by_id_ )
            return;

        mi_attach_session_ = reinterpret_cast< mi_attach_session_t >( kernel_base_ + mi_attach_session_offset_ );
        if ( !mi_attach_session_ )
            return;

        const auto proc_0 = mm_get_session_by_id_( 0 );
        const auto proc_1 = mm_get_session_by_id_( 1 );

        if ( !proc_0 || !proc_1 )
            return;

        system_space_ = *reinterpret_cast< kernel::MM_SESSION_SPACE** >( reinterpret_cast< uintptr_t >( proc_0 ) +
            0x558 );
        session_space_ = *reinterpret_cast< kernel::MM_SESSION_SPACE** >( reinterpret_cast< uintptr_t >( proc_1 ) +
            0x558 );
    }

    GdScanner::~GdScanner( ) = default;

    uintptr_t GdScanner::get_next_dispatch_call( const uintptr_t start, const size_t n_bytes,
                                                 const uintptr_t guard_dispatch_addr )
    {
        constexpr auto call_dispatch_size { 5 };

        auto current { reinterpret_cast< PUCHAR >( start ) };
        const auto end { reinterpret_cast< PUCHAR >( start + n_bytes - call_dispatch_size ) };

        while ( current < end )
        {
            // jmp
            if ( *current == 0xE8 )
            {
                const auto offset { *reinterpret_cast< int* >( current + 1 ) };
                const uintptr_t callee { reinterpret_cast< uintptr_t >( current + 5 + offset ) };

                if ( callee == guard_dispatch_addr )
                    return reinterpret_cast< uintptr_t >( current );
            }
            current++;
        }

        return NULL;
    }

    uintptr_t GdScanner::get_guard_dispatch_icall_addr( const uintptr_t base, const size_t size )
    {
        return reinterpret_cast< uintptr_t >( utils::find_pattern_raw( reinterpret_cast< char* >( base ),
                                                                       reinterpret_cast< char* >( base + size ),
                                                                       "\x4C\x8B\x1D\x00\x00\x00\x00\x48\x85\xC0",
                                                                       "xxx????xxx" ) );
    }

    void GdScanner::scan_all( ) const
    {
        // attach to session space so all session modules become available
        mi_attach_session_( session_space_ );

        ULONG size { };
        ZwQuerySystemInformation( kernel::SystemModuleInformation, nullptr, size, &size );
        if ( !size )
            return;

        const auto modules {
            static_cast< kernel::_RTL_PROCESS_MODULES* >( ExAllocatePoolZero( NonPagedPoolNx, size, ' sdg' ) )
        };
        if ( !modules )
            return;

        ZwQuerySystemInformation( kernel::SystemModuleInformation, modules, size, &size );


        for ( ULONG i = 0; i < modules->NumberOfModules; i++ )
        {
            if ( strstr( reinterpret_cast< const char* >( modules->Modules[ i ].FullPathName ),
                         "GuardDispatchScanner.sys" ) != nullptr )
                continue;

            KD_PRINT( "Scanning %s\n", modules->Modules[ i ].FullPathName );

            //
            // Only need to scan .text section of each loaded module
            //
            const auto base { reinterpret_cast< uintptr_t >( modules->Modules[ i ].ImageBase ) };

            const auto dos_header { reinterpret_cast< PIMAGE_DOS_HEADER >( base ) };
            const auto nt_headers { reinterpret_cast< PIMAGE_NT_HEADERS64 >( base + dos_header->e_lfanew ) };

            const auto n_sections = nt_headers->FileHeader.NumberOfSections;
            for ( auto j = 0; j < n_sections; j++ )
            {
                const auto section = IMAGE_FIRST_SECTION( nt_headers ) + j;

                if ( strstr( reinterpret_cast< const char* >( section->Name ), ".text" ) != nullptr )
                {
                    const auto start { base + section->VirtualAddress };
                    const auto section_size { section->SizeOfRawData };

                    const auto mdl {
                        IoAllocateMdl( reinterpret_cast< PVOID >( start ), static_cast< ULONG >( section_size ), FALSE,
                                       FALSE, nullptr )
                    };
                    MmProbeAndLockPages( mdl, KernelMode, IoReadAccess );

                    scan_module( reinterpret_cast< const char* >( modules->Modules[ i ].FullPathName ), start,
                                 section_size );

                    MmUnlockPages( mdl );
                    IoFreeMdl( mdl );
                }
            }
        }

        mi_attach_session_( system_space_ );

        ExFreePool( modules );
    }

    void GdScanner::scan_module( const char* module_name, const uintptr_t base, const size_t size )
    {
        if ( !base || !size )
            return;

        const auto guard_dispatch_addr { get_guard_dispatch_icall_addr( base, size ) };
        if ( !guard_dispatch_addr )
            return;

        // 0x20 is an arbitrary value. We don't want to scan over the limit when looking for calls to _guard_dispatch_icall
        constexpr auto final_padding { 0x20 };

        auto current { reinterpret_cast< PUCHAR >( base ) };
        const auto end { ( current + size ) - final_padding };

        size_t count { 0 };

        const auto is_mov_rax = [ ] ( const PUCHAR address ) -> bool
        {
            return address[ 0 ] == 0x48 && address[ 1 ] == 0x8B && address[ 2 ] == 0x05;
        };

        while ( current < end )
        {
            if ( is_mov_rax( current ) )
            {
                const auto offset { *reinterpret_cast< int* >( current + 3 ) };
                const auto data_pointer { current + 7 + offset };

                const auto next_dispatch {
                    get_next_dispatch_call( reinterpret_cast< uintptr_t >( current ), final_padding,
                                            guard_dispatch_addr )
                };

                if ( next_dispatch && data_pointer )
                    count++;
            }

            current++;
        }

        if ( count )
            KD_LOG( "Found %d calls to _guard_dispatch_icall in %s\n", count, module_name );
    }
}

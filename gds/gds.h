#pragma once
#include <ntstatus.h>
#include <Ntstrsafe.h>
#include <wdm.h>

#include "..\utils\utils.h"

namespace gds
{
    class GdScanner
    {
    public:
        GdScanner( );
        ~GdScanner( );

        // delete copy/move semantics
        GdScanner( const GdScanner& ) = delete;
        GdScanner( GdScanner&& ) = delete;
        GdScanner& operator=( const GdScanner& ) = delete;
        GdScanner& operator=( GdScanner&& ) = delete;

        void scan_all( ) const;

    private:
        static uintptr_t get_next_dispatch_call( uintptr_t start, size_t n_bytes, uintptr_t guard_dispatch_addr );
        static uintptr_t get_guard_dispatch_icall_addr( uintptr_t base, size_t size );
        static void scan_module( const char* module_name, uintptr_t base, size_t size );

        static bool in_any_module_range( uintptr_t addr );

        uintptr_t kernel_base_ { };

        typedef PEPROCESS ( __fastcall*mm_get_session_by_id_t )( int session_id );
        ULONG mm_get_session_by_id_offset_ { 0x297320 };
        mm_get_session_by_id_t mm_get_session_by_id_ { };

        typedef NTSTATUS ( __fastcall*mi_attach_session_t )( kernel::_MM_SESSION_SPACE* session_space );
        ULONG mi_attach_session_offset_ { 0x2E9E38 };
        mi_attach_session_t mi_attach_session_ { };

        kernel::_MM_SESSION_SPACE* system_space_ { };
        kernel::_MM_SESSION_SPACE* session_space_ { };
    };
}

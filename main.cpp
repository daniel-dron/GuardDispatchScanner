#include <ntifs.h>
#include <ntddk.h>

#include <Ntstrsafe.h>

#include "gds.h"

void driver_unload( const PDRIVER_OBJECT driver_object )
{
    UNICODE_STRING sym_link_name = RTL_CONSTANT_STRING( L"\\??\\GDS" );

    IoDeleteSymbolicLink( &sym_link_name );
    IoDeleteDevice( driver_object->DeviceObject );
}

NTSTATUS initialize_driver( const PDRIVER_OBJECT driver_object )
{
    PDEVICE_OBJECT device_object { nullptr };

    UNICODE_STRING device_name = RTL_CONSTANT_STRING( L"\\Device\\GDS" );
    UNICODE_STRING symlink_name = RTL_CONSTANT_STRING( L"\\??\\GDS" );

    driver_object->DriverUnload = driver_unload;

    NTSTATUS status = IoCreateDevice( driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
                                      FALSE, &device_object );

    if ( !NT_SUCCESS( status ) )
    {
        KD_PRINT( "Failed to create device object (0x%08X)", status );
        return status;
    }

    status = IoCreateSymbolicLink( &symlink_name, &device_name );
    if ( !NT_SUCCESS( status ) )
    {
        KD_PRINT( "Failed to create symbolic link (0x%08X)", status );
        if ( device_object )
            IoDeleteDevice( device_object );
        return status;
    }

    KD_PRINT( "Driver loaded\n", 0 );
    KD_PRINT( "Device name: %wZ\n", &device_name );

    gds::init( );

    gds::mi_attach_session( gds::session_space );
    gds::iterate_kernel_modules( );
    gds::mi_attach_session( gds::system_space );

    return status;
}

extern "C" NTSTATUS DriverEntry( const PDRIVER_OBJECT driver_object, const PUNICODE_STRING registry_path )
{
    UNREFERENCED_PARAMETER( registry_path );

    return initialize_driver( driver_object );
}

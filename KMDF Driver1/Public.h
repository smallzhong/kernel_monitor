/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_KMDFDriver1,
    0x4a1b7273,0xd9a3,0x4bfe,0x9d,0x5d,0xe9,0xdf,0xd6,0x7a,0x3c,0x5d);
// {4a1b7273-d9a3-4bfe-9d5d-e9dfd67a3c5d}

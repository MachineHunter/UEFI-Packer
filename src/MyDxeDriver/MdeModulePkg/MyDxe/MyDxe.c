#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiRuntimeServicesTableLib.h>


EFI_STATUS EFIAPI MyDxeEntry(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
	UINT32 myvarSize      = 30;
	CHAR8  myvarValue[30] = {0};
	CHAR16 myvarName[30]  = L"MyDxeStatus";
	EFI_TIME time;

	// eefbd379-9f5c-4a92-a157-ae4079eb1448
	EFI_GUID myvarGUID = { 0xeefbd379, 0x9f5c, 0x4a92, { 0xa1, 0x57, 0xae, 0x40, 0x79, 0xeb, 0x14, 0x48 }};

	gRT->GetTime(&time, NULL);

	AsciiSPrint(myvarValue, 12, "%2d/%2d %2d:%2d", time.Month, time.Day, time.Hour, time.Minute);

	gRT->SetVariable(
			myvarName,
			&myvarGUID,
			EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
			myvarSize,
			myvarValue);

	return EFI_SUCCESS;
}

#include "MyDxe2.h"

// Difference from MyDxe
// 1: defines protocol
// 2: measure clock cycle
// 3: defines depex
	
UINT32 myvarSize      = 30;
CHAR8  myvarValue[30] = {0};
CHAR16 myvarName[30]  = L"MyDxeStatus";

// eefbd379-9f5c-4a92-a157-ae4079eb1448
EFI_GUID myvarGUID = { 0xeefbd379, 0x9f5c, 0x4a92, { 0xa1, 0x57, 0xae, 0x40, 0x79, 0xeb, 0x14, 0x48 }};

EFI_HANDLE mDummyHandle = NULL;

EFI_STATUS EFIAPI DummyFunc1() {
	AsciiSPrint(myvarValue, 18, "DummyFunc1 called");
	gRT->SetVariable(
			myvarName,
			&myvarGUID,
			EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
			myvarSize,
			myvarValue);
	return EFI_SUCCESS;
}

EFI_STATUS EFIAPI DummyFunc2() {
	AsciiSPrint(myvarValue, 18, "DummyFunc2 called");
	gRT->SetVariable(
			myvarName,
			&myvarGUID,
			EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
			myvarSize,
			myvarValue);
	return EFI_SUCCESS;
}

EFI_DUMMY_PROTOCOL mDummy = {
	DummyFunc1,
	DummyFunc2
};

EFI_STATUS EFIAPI MyDxeEntry(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
	gBS->InstallMultipleProtocolInterfaces(&mDummyHandle, &gEfiDummyProtocolGuid, &mDummy, NULL);

	EFI_TIME time;

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

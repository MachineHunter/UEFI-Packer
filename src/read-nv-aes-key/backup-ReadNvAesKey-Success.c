#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Tcg2Protocol.h>
#include <IndustryStandard/Tpm20.h>
#include <Library/BaseMemoryLib.h>

#pragma pack(1)
	typedef struct {
		TPMI_SH_AUTH_SESSION sessionHandle;
		UINT16 nonceSizeZero;
		TPMA_SESSION sessionAttributes;
		UINT16 hmacSizeZero;
	} ORIG_AUTH_AREA;

	typedef struct {
		TPM2_COMMAND_HEADER Header;
		TPMI_RH_NV_AUTH authHandle;
		TPMI_RH_NV_INDEX nvIndex;
		UINT32 authSize;
		ORIG_AUTH_AREA authArea;
		UINT16 size;
		UINT16 offset;
	} TPM2_NV_READ_COMMAND;

	typedef struct {
		TPM2_RESPONSE_HEADER Header;
		UINT32 parameterSize;
		TPM2B_MAX_NV_BUFFER data;
	} TPM2_NV_READ_RESPONSE;
#pragma pack()

EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
	// AesKeyNvIndex and KeyLength should be same as CreateNvAesKey!
	TPMI_RH_NV_INDEX AesKeyNvIndex = NV_INDEX_FIRST;
	UINT16 keyLength = 16;
	
	EFI_TCG2_PROTOCOL *Tcg2Protocol;
	SystemTable->BootServices->LocateProtocol(&gEfiTcg2ProtocolGuid, NULL, (VOID**)&Tcg2Protocol);


	// Auth Area
	UINT32 authSize;
	ORIG_AUTH_AREA authArea;
	authArea.sessionHandle = SwapBytes32(TPM_RS_PW);
	authArea.nonceSizeZero = SwapBytes16(0);
	authArea.sessionAttributes.continueSession = 0;
	authArea.sessionAttributes.auditExclusive  = 0;
	authArea.sessionAttributes.auditReset      = 0;
	authArea.sessionAttributes.reserved3_4     = 0;
	authArea.sessionAttributes.decrypt         = 0;
	authArea.sessionAttributes.encrypt         = 0;
	authArea.sessionAttributes.audit           = 0;
	authArea.hmacSizeZero = SwapBytes16(0);
	authSize = sizeof(authArea);


	TPM2_NV_READ_COMMAND CmdBuffer;
	UINT32 CmdBufferSize;
	TPM2_NV_READ_RESPONSE RecvBuffer;
	UINT32 RecvBufferSize;

	// set send parameters
	CmdBuffer.Header.tag         = SwapBytes16(TPM_ST_SESSIONS);
	CmdBuffer.Header.commandCode = SwapBytes32(TPM_CC_NV_Read);
	CmdBuffer.authHandle         = SwapBytes32(AesKeyNvIndex);
	CmdBuffer.nvIndex            = SwapBytes32(AesKeyNvIndex);
	CmdBuffer.authSize           = SwapBytes32(authSize);
	CmdBuffer.authArea           = authArea;
	CmdBuffer.size               = SwapBytes16(keyLength);
	CmdBuffer.offset             = SwapBytes16(0);
	CmdBufferSize = sizeof(CmdBuffer.Header) + sizeof(CmdBuffer.authHandle) + sizeof(CmdBuffer.nvIndex) + sizeof(CmdBuffer.authSize) + sizeof(CmdBuffer.authArea) + sizeof(CmdBuffer.size) + sizeof(CmdBuffer.offset);
	CmdBuffer.Header.paramSize = SwapBytes32(CmdBufferSize);

	Print(L"sending TPM command...\r\n");


	// send TPM command
	RecvBufferSize = sizeof(RecvBuffer);
	EFI_STATUS stats = Tcg2Protocol->SubmitCommand(Tcg2Protocol, CmdBufferSize, (UINT8*)&CmdBuffer, RecvBufferSize, (UINT8*)&RecvBuffer);
	if(stats==EFI_SUCCESS)
		Print(L"SubmitCommand Success!\r\n");
	else
		Print(L"stats: 0x%x (EFI_DEVICE_ERROR:0x%x, EFI_INVALID_PARAMETER:0x%x, EFI_BUFFER_TOO_SMALL:0x%x)\r\n", stats, EFI_DEVICE_ERROR, EFI_INVALID_PARAMETER, EFI_BUFFER_TOO_SMALL);


	// parse response
	UINT32 res = SwapBytes32(RecvBuffer.Header.responseCode);
	Print(L"ResponseCode is %d (%X)\r\n", res, res);

	UINT16 readDataSize = SwapBytes16(RecvBuffer.data.size);
	Print(L"%d bytes read (which should be the key size)\r\n", readDataSize);

	UINT16 i;
	Print(L"AES key read; ");
	for(i=0; i<readDataSize; i++) {
		Print(L"%X", RecvBuffer.data.buffer[readDataSize-i-1]);
	}
	Print(L"\r\n");

	while(1);

	return 0;
}

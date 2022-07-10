#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Tcg2Protocol.h>
#include <IndustryStandard/Tpm20.h>
#include <Library/BaseMemoryLib.h>


static inline __attribute__((always_inline))
UINT16 EFIAPI swapBytes16(IN UINT16  Value) {
  return (UINT16)((Value<< 8) | (Value>> 8));
}

static inline __attribute__((always_inline))
UINT32 EFIAPI swapBytes32(IN UINT32 Value) {
  UINT32 LowerBytes  = (UINT32)swapBytes16 ((UINT16)Value);
  UINT32 HigherBytes = (UINT32)swapBytes16 ((UINT16)(Value >> 16));
  return (LowerBytes << 16 | HigherBytes);
}

static inline __attribute__((always_inline))
UINT64 EFIAPI swapBytes64(IN UINT64 Value) {
  UINT64 LowerBytes  = (UINT64)swapBytes32 ((UINT32)Value);
  UINT64 HigherBytes = (UINT64)swapBytes32 ((UINT32)(Value >> 32));
  return (LowerBytes << 32 | HigherBytes);
}


EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
	// AesKeyNvIndex and KeyLength should be same as CreateNvAesKey!
	TPMI_RH_NV_INDEX AesKeyNvIndex = NV_INDEX_FIRST;
	UINT16 keyLength = 16;
	
	EFI_GUID _gEfiTcg2ProtocolGuid = {0x607f766c, 0x7455, 0x42be, { 0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f }};
	EFI_TCG2_PROTOCOL *Tcg2Protocol;

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

	SystemTable->BootServices->LocateProtocol(&_gEfiTcg2ProtocolGuid, NULL, (VOID**)&Tcg2Protocol);

	// Auth Area
	UINT32 authSize;
	ORIG_AUTH_AREA authArea;
	authArea.sessionHandle = swapBytes32(TPM_RS_PW);
	authArea.nonceSizeZero = swapBytes16(0);
	authArea.sessionAttributes.continueSession = 0;
	authArea.sessionAttributes.auditExclusive  = 0;
	authArea.sessionAttributes.auditReset      = 0;
	authArea.sessionAttributes.reserved3_4     = 0;
	authArea.sessionAttributes.decrypt         = 0;
	authArea.sessionAttributes.encrypt         = 0;
	authArea.sessionAttributes.audit           = 0;
	authArea.hmacSizeZero = swapBytes16(0);
	authSize = sizeof(authArea);


	TPM2_NV_READ_COMMAND CmdBuffer;
	UINT32 CmdBufferSize;
	TPM2_NV_READ_RESPONSE RecvBuffer;
	UINT32 RecvBufferSize;

	// set send parameters
	CmdBuffer.Header.tag         = swapBytes16(TPM_ST_SESSIONS);
	CmdBuffer.Header.commandCode = swapBytes32(TPM_CC_NV_Read);
	CmdBuffer.authHandle         = swapBytes32(AesKeyNvIndex);
	CmdBuffer.nvIndex            = swapBytes32(AesKeyNvIndex);
	CmdBuffer.authSize           = swapBytes32(authSize);
	CmdBuffer.authArea           = authArea;
	CmdBuffer.size               = swapBytes16(keyLength);
	CmdBuffer.offset             = swapBytes16(0);
	CmdBufferSize = sizeof(CmdBuffer.Header) + sizeof(CmdBuffer.authHandle) + sizeof(CmdBuffer.nvIndex) + sizeof(CmdBuffer.authSize) + sizeof(CmdBuffer.authArea) + sizeof(CmdBuffer.size) + sizeof(CmdBuffer.offset);
	CmdBuffer.Header.paramSize = swapBytes32(CmdBufferSize);

	// send TPM command
	RecvBufferSize = sizeof(RecvBuffer);
	Tcg2Protocol->SubmitCommand(Tcg2Protocol, CmdBufferSize, (UINT8*)&CmdBuffer, RecvBufferSize, (UINT8*)&RecvBuffer);

	// check response
	BYTE *out = RecvBuffer.data.buffer;
	BYTE key[16];
	UINT8 i;
	for(i=0; i<16; i++) {
		key[16-i-1] = out[i];
	}
	if( key[0]==0x30 && key[1]==0xEE && key[15]==0x59 ) {
		UINT64 buf = 0x0000004100420043;
		CHAR16 *msg = (CHAR16*)&buf;
		SystemTable->ConOut->OutputString(SystemTable->ConOut, msg);
	}
	else {
		UINT64 buf = 0x0000004400450046;
		CHAR16 *msg = (CHAR16*)&buf;
		SystemTable->ConOut->OutputString(SystemTable->ConOut, msg);
	}

	while(1);

	return 0;
}

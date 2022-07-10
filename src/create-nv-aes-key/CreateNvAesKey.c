#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Tcg2Protocol.h>
#include <IndustryStandard/Tpm20.h>
#include <Library/BaseMemoryLib.h>

#pragma pack(1)
	typedef struct {
		TPM2_COMMAND_HEADER Header;
		UINT16 bytesRequested;
	} TPM2_GET_RANDOM_COMMAND;

	typedef struct {
		TPM2_RESPONSE_HEADER Header;
		TPM2B_DIGEST randomBytes;
	} TPM2_GET_RANDOM_RESPONSE;


	typedef struct {
		TPMI_SH_AUTH_SESSION sessionHandle;
		UINT16 nonceSizeZero;
		TPMA_SESSION sessionAttributes;
		UINT16 hmacSizeZero;
	} ORIG_AUTH_AREA;

	typedef struct {
		UINT16 size;
		TPMI_RH_NV_INDEX nvIndex;
		TPMI_ALG_HASH nameAlg;
		/*TPMA_NV attributes;*/
		UINT32 attributes;
		UINT16 authPolicySizeZero;
		UINT16 dataSize;
	} ORIG_NV_PUBLIC;

	typedef struct {
		UINT16 size;
		BYTE buffer[9];
	} ORIG_AUTH;

	typedef struct {
		TPM2_COMMAND_HEADER Header;
		TPMI_RH_PROVISION authHandle;
		UINT32 authSize;
		ORIG_AUTH_AREA authArea;
		/*TPM2B_AUTH auth;*/
		/*ORIG_AUTH auth;*/
		UINT16 authSizeZero;
		/*TPM2B_NV_PUBLIC publicInfo;*/
		ORIG_NV_PUBLIC publicInfo;
	} TPM2_NV_DEFINE_SPACE_COMMAND;

	typedef struct {
		TPM2_RESPONSE_HEADER Header;
		BYTE auth_area_buf[200];
	} TPM2_NV_DEFINE_SPACE_RESPONSE;


	typedef struct {
		UINT16 size;
    BYTE buffer[16]; 
	} ORIG_MAX_NV_BUFFER;

	typedef struct {
		TPM2_COMMAND_HEADER Header;
		TPMI_RH_NV_AUTH authHandle;
		TPMI_RH_NV_INDEX nvIndex;
		UINT32 authSize;
		ORIG_AUTH_AREA authArea;
		/*TPM2B_MAX_NV_BUFFER data;*/
		ORIG_MAX_NV_BUFFER data;
		UINT16 offset;
	} TPM2_NV_WRITE_COMMAND;

	typedef struct {
		TPM2_RESPONSE_HEADER Header;
		BYTE auth_area_buf[200];
	} TPM2_NV_WRITE_RESPONSE;
#pragma pack()

EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
	TPMI_RH_NV_INDEX AesKeyNvIndex = NV_INDEX_FIRST; // this is the nvIndex to store AES key. in this case, NV_INDEX_FIRST
	UINT16 keyLength = 16; // AES-128 key so 128bit=16bytes
												 // REMEMBER when changing keyLength, change ORIG_MAX_NV_BUFFER in typedef above too!
	
	EFI_TCG2_PROTOCOL *Tcg2Protocol;
	SystemTable->BootServices->LocateProtocol(&gEfiTcg2ProtocolGuid, NULL, (VOID**)&Tcg2Protocol);


	// ---------------------------------------------------- TPM2_NV_GetRandom ------------------------------------------------------

	TPM2_GET_RANDOM_COMMAND CmdBuffer;
	UINT32 CmdBufferSize;
	TPM2_GET_RANDOM_RESPONSE RecvBuffer;
	UINT32 RecvBufferSize;

	// set send parameters
	CmdBuffer.Header.tag         = SwapBytes16(TPM_ST_NO_SESSIONS);
	CmdBuffer.Header.commandCode = SwapBytes32(TPM_CC_GetRandom);
	CmdBuffer.bytesRequested     = SwapBytes16(keyLength);
	CmdBufferSize = sizeof(CmdBuffer.Header) + sizeof(CmdBuffer.bytesRequested);
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
	UINT16 res = SwapBytes32(RecvBuffer.Header.responseCode);
	Print(L"ResponseCode is %d (%X)\r\n", res, res);

	UINT16 keysize = SwapBytes16(RecvBuffer.randomBytes.size);
	if(keysize!=keyLength) {
		Print(L"generated key length is not %d!\r\n", keyLength);
		while(1);
	}
	UINT16 i;
	Print(L"generated AES key: ");
	for(i=0; i<keysize; i++) {
		Print(L"%X", RecvBuffer.randomBytes.buffer[keysize-i-1]);
	}
	Print(L"\r\n");


	// ---------------------------------------------------- TPM2_NV_DefineSpace ------------------------------------------------------
	

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


	// auth parameter area (password)
	/*
	ORIG_AUTH auth;
	// **Remember if you change password, change ORIG_AUTH buffer size in typedef too!!!**
	// password used to write to nv in BIG ENDIAN
	BYTE password[] = {0x55, 0x65, 0x66, 0x69, 0x50, 0x61, 0x63, 0x6b, 0x00}; // "UefiPack\0" NOT wide char
	auth.size = SwapBytes16(sizeof(password));
	CopyMem(auth.buffer, password, SwapBytes16(auth.size));
	*/


	// publicInfo area
	ORIG_NV_PUBLIC publicInfo;
	publicInfo.nvIndex = SwapBytes32(AesKeyNvIndex);
	publicInfo.nameAlg = SwapBytes16(TPM_ALG_SHA1);
	/*
	 *TPMA_NV attributes;
	 *attributes.TPMA_NV_PPWRITE        = 1; // part2 tpma_nv の最初の説明文の内容が気になる
	 *attributes.TPMA_NV_OWNERWRITE     = 1;
   *attributes.TPMA_NV_AUTHWRITE      = 1;
   *attributes.TPMA_NV_POLICYWRITE    = 1;
   *attributes.TPMA_NV_COUNTER        = 0;
   *attributes.TPMA_NV_BITS           = 0;
   *attributes.TPMA_NV_EXTEND         = 0;
   *attributes.reserved7_9            = 000;
   *attributes.TPMA_NV_POLICY_DELETE  = 0;
   *attributes.TPMA_NV_WRITELOCKED    = 0;
   *attributes.TPMA_NV_WRITEALL       = 1;
   *attributes.TPMA_NV_WRITEDEFINE    = 0;
   *attributes.TPMA_NV_WRITE_STCLEAR  = 1;
   *attributes.TPMA_NV_GLOBALLOCK     = 0;
   *attributes.TPMA_NV_PPREAD         = 1;
   *attributes.TPMA_NV_OWNERREAD      = 1;
   *attributes.TPMA_NV_AUTHREAD       = 1;
   *attributes.TPMA_NV_POLICYREAD     = 1;
   *attributes.reserved20_24          = 00000;
   *attributes.TPMA_NV_NO_DA          = 1; // 後ほど検討
   *attributes.TPMA_NV_ORDERLY        = 0;
   *attributes.TPMA_NV_CLEAR_STCLEAR  = 0;
   *attributes.TPMA_NV_READLOCKED     = 0;
   *attributes.TPMA_NV_WRITTEN        = 0;
   *attributes.TPMA_NV_PLATFORMCREATE = 0;
   *attributes.TPMA_NV_READ_STCLEAR   = 0; // 検討
   * => 00000010000011110101000000001111
	 * => 0x20f500f
	 */
	publicInfo.attributes = SwapBytes32(0x20f500f);
	publicInfo.authPolicySizeZero = SwapBytes16(0);
	publicInfo.dataSize = SwapBytes16(keyLength); // byte? bit?
	publicInfo.size = SwapBytes16(sizeof(publicInfo) - sizeof(publicInfo.size));


	TPM2_NV_DEFINE_SPACE_COMMAND CmdBuffer2;
	UINT32 CmdBuffer2Size;
	TPM2_NV_DEFINE_SPACE_RESPONSE RecvBuffer2;
	UINT32 RecvBuffer2Size;

	// set send parameters
	CmdBuffer2.Header.tag         = SwapBytes16(TPM_ST_SESSIONS);
	CmdBuffer2.Header.commandCode = SwapBytes32(TPM_CC_NV_DefineSpace);
	CmdBuffer2.authHandle         = SwapBytes32(TPM_RH_OWNER);
	CmdBuffer2.authSize           = SwapBytes32(authSize);
	CmdBuffer2.authArea           = authArea;
	/*CmdBuffer2.auth               = auth;*/
	CmdBuffer2.authSizeZero       = SwapBytes16(0);
	CmdBuffer2.publicInfo         = publicInfo;
	CmdBuffer2Size = sizeof(CmdBuffer2.Header) + sizeof(CmdBuffer2.authHandle) + sizeof(CmdBuffer2.authSize) + sizeof(CmdBuffer2.authArea) + sizeof(CmdBuffer2.authSizeZero) + sizeof(CmdBuffer2.publicInfo);
	CmdBuffer2.Header.paramSize = SwapBytes32(CmdBuffer2Size);

	Print(L"sending TPM command...\r\n");


	// send TPM command
	RecvBuffer2Size = sizeof(RecvBuffer2);
	stats = Tcg2Protocol->SubmitCommand(Tcg2Protocol, CmdBuffer2Size, (UINT8*)&CmdBuffer2, RecvBuffer2Size, (UINT8*)&RecvBuffer2);
	if(stats==EFI_SUCCESS)
		Print(L"SubmitCommand Success!\r\n");
	else
		Print(L"stats: 0x%x (EFI_DEVICE_ERROR:0x%x, EFI_INVALID_PARAMETER:0x%x, EFI_BUFFER_TOO_SMALL:0x%x)\r\n", stats, EFI_DEVICE_ERROR, EFI_INVALID_PARAMETER, EFI_BUFFER_TOO_SMALL);
	
	res = SwapBytes32(RecvBuffer2.Header.responseCode);
	UINT32 resSize = SwapBytes32(RecvBuffer2.Header.paramSize);
	Print(L"ResponseCode is %d, Size is %d (0x%x)\r\n", res, resSize);
	if(res==332) {
		Print(L"[332] NV Index or persistent object already defined\r\n");
	}
	else if(res!=0) {
		Print(L"NV_DefineSpace failed\r\n");
		while(1);
	}


	// ---------------------------------------------------- TPM2_NV_Write ------------------------------------------------------

	TPM2_NV_WRITE_COMMAND CmdBuffer3;
	UINT32 CmdBuffer3Size;
	TPM2_NV_WRITE_RESPONSE RecvBuffer3;
	UINT32 RecvBuffer3Size;

	// data parameter area (AES key data)
	ORIG_MAX_NV_BUFFER data;
	// AES key is already generated with getrandom
	data.size = SwapBytes16(keyLength);
	CopyMem(data.buffer, RecvBuffer.randomBytes.buffer, data.size);

	// set send parameters
	CmdBuffer3.Header.tag         = SwapBytes16(TPM_ST_SESSIONS);
	CmdBuffer3.Header.commandCode = SwapBytes32(TPM_CC_NV_Write);
	CmdBuffer3.authHandle         = SwapBytes32(AesKeyNvIndex);
	CmdBuffer3.nvIndex            = SwapBytes32(AesKeyNvIndex);
	CmdBuffer3.authSize           = SwapBytes32(authSize);
	CmdBuffer3.authArea           = authArea;
	CmdBuffer3.data               = data;
	CmdBuffer3.offset             = SwapBytes16(0);
	CmdBuffer3Size = sizeof(CmdBuffer3.Header) + sizeof(CmdBuffer3.authHandle) + sizeof(CmdBuffer3.nvIndex) + sizeof(CmdBuffer3.authSize) + sizeof(CmdBuffer3.authArea) + sizeof(CmdBuffer3.data) + sizeof(CmdBuffer3.offset);
	CmdBuffer3.Header.paramSize = SwapBytes32(CmdBuffer3Size);

	Print(L"sending TPM command...\r\n");


	// send TPM command
	RecvBuffer3Size = sizeof(RecvBuffer3);
	stats = Tcg2Protocol->SubmitCommand(Tcg2Protocol, CmdBuffer3Size, (UINT8*)&CmdBuffer3, RecvBuffer3Size, (UINT8*)&RecvBuffer3);
	if(stats==EFI_SUCCESS)
		Print(L"SubmitCommand Success!\r\n");
	else
		Print(L"stats: 0x%x (EFI_DEVICE_ERROR:0x%x, EFI_INVALID_PARAMETER:0x%x, EFI_BUFFER_TOO_SMALL:0x%x)\r\n", stats, EFI_DEVICE_ERROR, EFI_INVALID_PARAMETER, EFI_BUFFER_TOO_SMALL);

	// parse response
	res = SwapBytes32(RecvBuffer3.Header.responseCode);
	Print(L"ResponseCode is %d (%X)\r\n", res, res);

	while(1);

	return 0;
}

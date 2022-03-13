#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Protocol/Tcg2Protocol.h>
#include <IndustryStandard/Tpm20.h>

// chose this value because the key was here in my pc
#define EK_HANDLE 0x81010001

// structures should be packed due to canonicalization of TPM
#pragma pack(1)
	typedef struct {
		TPM2_COMMAND_HEADER Header;
		TPMI_DH_OBJECT objectHandle;
	} TPM2_READ_PUBLIC_COMMAND;

	typedef struct {
		TPM2_RESPONSE_HEADER Header;
		TPM2B_PUBLIC outPublic;
		TPM2B_NAME name;
		TPM2B_NAME qualifiedName;
	} TPM2_READ_PUBLIC_RESPONSE;

	typedef struct {
		TPMU_PUBLIC_PARMS parameters;
		TPMU_PUBLIC_ID unique;
	} TEMP;

	typedef struct {
		TPMI_RSA_KEY_BITS keyBits;
		UINT32 exponent;
		TPMU_PUBLIC_ID unique;
	} TEMP2;
#pragma pack()


EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
	EFI_TCG2_PROTOCOL *Tcg2Protocol;

	SystemTable->BootServices->LocateProtocol(&gEfiTcg2ProtocolGuid, NULL, (VOID**)&Tcg2Protocol);

	TPM2_READ_PUBLIC_COMMAND CmdBuffer;
	UINT32 CmdBufferSize;
	TPM2_READ_PUBLIC_RESPONSE RecvBuffer;
	UINT32 RecvBufferSize;

	// set send parameters
	CmdBuffer.Header.tag         = SwapBytes16(TPM_ST_NO_SESSIONS);
	CmdBuffer.Header.commandCode = SwapBytes32(TPM_CC_ReadPublic);
	CmdBuffer.objectHandle       = SwapBytes32(EK_HANDLE);
	CmdBufferSize                = sizeof(CmdBuffer.Header) + sizeof(CmdBuffer.objectHandle);
	CmdBuffer.Header.paramSize   = SwapBytes32(CmdBufferSize);

	// send TPM command
	RecvBufferSize = sizeof(RecvBuffer);
	Tcg2Protocol->SubmitCommand(Tcg2Protocol, CmdBufferSize, (UINT8*)&CmdBuffer, RecvBufferSize, (UINT8*)&RecvBuffer);


	// parse response manually
	//  - structure that start with `TPMB_` has dynamic size
	//  - structure that start with `TPMI_` has conditional types (some members will be omitted depending on types)
	TEMP* temp = (TEMP*)( (void*)(&(RecvBuffer.outPublic.publicArea.authPolicy)) + SwapBytes16(RecvBuffer.outPublic.publicArea.authPolicy.size) + 0x2);
	UINT16 scheme = SwapBytes16(temp->parameters.rsaDetail.scheme.scheme);
	TEMP2* temp2 = NULL;
	if(scheme==TPM_ALG_NULL) {         // should be TPM_ALG_NULL here ...
		Print(L"scheme was TPM_ALG_NULL [0x%X]\r\n", scheme);
		temp2 = (TEMP2*)(&(temp->parameters.rsaDetail.scheme.details));
	}


	// show the results (to check if response parsing is correct)
	UINT16 algorithm = SwapBytes16(temp->parameters.rsaDetail.symmetric.algorithm);
	Print(L"algorithm: 0x%X\r\n", algorithm); // 0x6 TPM_ALG_AES
	UINT16 keyb = SwapBytes16(temp->parameters.rsaDetail.symmetric.keyBits.sym);
	Print(L"keybits: 0x%X (%d)\r\n", keyb, keyb); // 0x80 (128bit)
	UINT16 mode = SwapBytes16(temp->parameters.rsaDetail.symmetric.mode.sym);
	Print(L"mode: 0x%X\r\n", mode); // 0x43 CFB (Cypher Feed Back)
	UINT32 keyBits = SwapBytes16(temp2->keyBits);
	Print(L"keyBits: 0x%X (%d)\r\n", keyBits, keyBits); // 0x800 (2048bit = 256Byte)
	UINT32 exp = SwapBytes32(temp2->exponent);
	Print(L"exponent value: 0x%X\r\n", exp); // 0x10001 (e=65537)
	UINT16 pubkey_size = SwapBytes16(temp2->unique.rsa.size);
	Print(L"pubkey_size: 0x%X (%d)\r\n", pubkey_size, pubkey_size); // 0x100 (256Bytes)


	// print EK public key!
	BYTE* pubkey = temp2->unique.rsa.buffer;
	int i,j;
	for(i=0; i<16; i++) {
		for(j=0; j<16; j++)
			Print(L"%2X ", pubkey[i*16+j]);
		Print(L"\r\n");
	}

	while(1);
	return 0;
}

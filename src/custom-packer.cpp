#include <windows.h>
#include <dbghelp.h>
#include <stdlib.h>
#include <iostream>
#include <sstream>
#include "aes.h"
#pragma comment(lib, "dbghelp.lib")

#define CBC 1

typedef unsigned __int64 QWORD;

typedef struct PE {
	PIMAGE_DOS_HEADER     DosHeader;
	PIMAGE_NT_HEADERS     NtHeader;
	PIMAGE_OPTIONAL_HEADER OptionalHeader;
	PIMAGE_FILE_HEADER     FileHeader;
	PIMAGE_SECTION_HEADER SectionHeader;
	QWORD                 ImageBase;
	QWORD                 oep;
} PE;

typedef struct SectionConfig {
	CHAR* name;
	QWORD vaddr;
	QWORD vsize;
	QWORD raddr;
	DWORD rsize;
	QWORD* characteristic;
} SectionConfig;


void Err(const char* msg) {
	MessageBox(NULL, TEXT(msg), TEXT("Error"), MB_OK | MB_ICONERROR);
}

void DbgPrint(const char* fmt, ...) {
	char buf[256];
	va_list v1;
	va_start(v1, fmt);
	vsnprintf(buf, sizeof(buf), fmt, v1);
	va_end(v1);
	OutputDebugString(buf);
}

void ParsePE(PE* pe, UCHAR* lpTargetBinBuffer) {
	pe->DosHeader      = (PIMAGE_DOS_HEADER)lpTargetBinBuffer;
	pe->NtHeader       = (PIMAGE_NT_HEADERS)((QWORD)lpTargetBinBuffer + pe->DosHeader->e_lfanew);
	pe->OptionalHeader = &pe->NtHeader->OptionalHeader;
	pe->FileHeader     = &pe->NtHeader->FileHeader;
	pe->ImageBase      = pe->OptionalHeader->ImageBase;
	pe->oep            = pe->ImageBase + pe->OptionalHeader->AddressOfEntryPoint;
	DbgPrint("ImageBase:0x%I64X, OEP:0x%I64X", pe->ImageBase, pe->oep + pe->ImageBase);
}

void FindSection(PE* pe, SectionConfig* target, SectionConfig* ext) {
	QWORD sectionLocation = (QWORD)IMAGE_FIRST_SECTION(pe->NtHeader);
	QWORD sectionSize = (QWORD)sizeof(IMAGE_SECTION_HEADER);

	for (int i = 0; i < pe->FileHeader->NumberOfSections; i++) {
		pe->SectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
		QWORD SectionTopAddr = pe->ImageBase + pe->SectionHeader->VirtualAddress;
		QWORD SectionEndAddr = pe->ImageBase + pe->SectionHeader->VirtualAddress + pe->SectionHeader->Misc.VirtualSize;

		// section that has oep
		if (SectionTopAddr <= pe->oep && pe->oep < SectionEndAddr) {
			target->name = (CHAR*)pe->SectionHeader->Name;
			target->vaddr = pe->ImageBase + pe->SectionHeader->VirtualAddress;
			target->vsize = pe->SectionHeader->Misc.VirtualSize;
			target->raddr = pe->SectionHeader->PointerToRawData;
			target->rsize = pe->SectionHeader->SizeOfRawData;
			target->characteristic = (QWORD*)&(pe->SectionHeader->Characteristics);
			DbgPrint("OEP is in %s section", target->name);
		}

		// section .ext
		if (!strcmp((CHAR*)pe->SectionHeader->Name, ".ext")) {
			ext->name = (CHAR*)pe->SectionHeader->Name;
			ext->vaddr = pe->ImageBase + pe->SectionHeader->VirtualAddress;
			ext->vsize = pe->SectionHeader->Misc.VirtualSize;
			ext->raddr = pe->SectionHeader->PointerToRawData;
			ext->rsize = pe->SectionHeader->SizeOfRawData;
		}
		sectionLocation += sectionSize;
	}
}

uint8_t aes128key[16] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

uint8_t iv[16] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

void aes_encrypt(UCHAR* start, DWORD size) {
	size_t keySize = sizeof(aes128key);
	if (keySize != 16)
		DbgPrint("WRONG KEY SIZE!!! %d", keySize);

	DbgPrint("original: %2X %2X %2X %2X %2X %2X %2X %2X", start[0], start[1], start[2], start[3], start[4], start[5], start[6], start[7]);
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, aes128key, iv);
	AES_CBC_encrypt_buffer(&ctx, start, size);
	return;
}

uint8_t encData[48] = {
	0xf6, 0x7c, 0xcd, 0x5e, 0x5a, 0x84, 0xaf, 0xc9, 0x2e, 0xd9, 0xe6, 0x35, 0xaf, 0xd0, 0xd1, 0x67,
	0x8f, 0xae, 0x07, 0x08, 0xf2, 0x1a, 0x51, 0xb2, 0x5a, 0xfe, 0xad, 0x86, 0x75, 0xe6, 0x37, 0x74
};

uint8_t correctData[48] = {
	0x89, 0xc8, 0x0f, 0xc8, 0xc3, 0x31, 0xc0, 0x48, 0x85, 0xc9, 0x74, 0x1a, 0x4c, 0x8d, 0x42, 0xff,
	0x48, 0x85, 0xd2, 0x74, 0x11, 0x80, 0x3c, 0x01, 0x00, 0x74, 0x0a, 0x49, 0x39, 0xc0, 0x76, 0x07
};

void aes_decrypt_test() {
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, aes128key, iv);
	AES_CBC_decrypt_buffer(&ctx, encData, 48);
	DbgPrint("decrypted: %2X %2X %2X %2X %2X %2X %2X %2X", encData[0], encData[1], encData[2], encData[3], encData[4], encData[5], encData[6], encData[7]);
	DbgPrint("should be: %2X %2X %2X %2X %2X %2X %2X %2X", correctData[0], correctData[1], correctData[2], correctData[3], correctData[4], correctData[5], correctData[6], correctData[7]);
}

UCHAR decodeStub[] = {
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,               // push registers
	0x48, 0xb8, 0x6c, 0x76, 0x7f, 0x60, 0x55, 0x74, 0xbe, 0x42, 0x41, 0x54, 0x55, 0x57, 0xbf, 0x42, 0x00, 0x00, 0x00, 0x56, 0x53, 0x48, 0x89, 0xd3, 0x48, 0x81, 0xec, 0x60, 0x02, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x5c, 0x48, 0x8d, 0x4c, 0x24, 0x5c, 0x4c, 0x8d, 0x44, 0x24, 0x40, 0x48, 0xb8, 0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f, 0x48, 0x89, 0x44, 0x24, 0x64, 0x48, 0x8b, 0x42, 0x60, 0x31, 0xd2, 0x4c, 0x8d, 0x64, 0x24, 0x38, 0xff, 0x90, 0x40, 0x01, 0x00, 0x00, 0x48, 0x8d, 0x54, 0x24, 0x6e, 0x48, 0xb8, 0x80, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x41, 0xb9, 0xf2, 0x01, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x4e, 0x48, 0x8b, 0x44, 0x24, 0x40, 0x4c, 0x8d, 0x44, 0x24, 0x4e, 0x48, 0x89, 0x54, 0x24, 0x20, 0xba, 0x0e, 0x00, 0x00, 0x00, 0x48, 0x89, 0xc1, 0xc7, 0x44, 0x24, 0x56, 0x01, 0x73, 0x81, 0x01, 0x66, 0xc7, 0x44, 0x24, 0x5a, 0x00, 0x01, 0xff, 0x50, 0x18, 0x66, 0x8b, 0x84, 0x24, 0x82, 0x00, 0x00, 0x00, 0x4c, 0x89, 0xe2, 0x86, 0xe0, 0x0f, 0xb7, 0xc0, 0x48, 0x8d, 0xb4, 0x04, 0x84, 0x00, 0x00, 0x00, 0x48, 0xb8, 0x41, 0x00, 0x0d, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x38, 0x48, 0x8b, 0x43, 0x40, 0x48, 0x89, 0xc1, 0xff, 0x50, 0x08, 0x8b, 0x54, 0x24, 0x38, 0x4c, 0x8d, 0x56, 0x10, 0x31, 0xc9, // 204
	0x53,                                                         // push rbx                <= save rbx
	0xE8, 0x00, 0x00, 0x00, 0x00,                                 // call $+5			    
	0x5b,                                                         // pop rbx                 <=  current instruction address will be set to rbx
	0x48, 0x81, 0xEB, 0xFF, 0xFF, 0xFF, 0xFF,                     // sub rbx, offset         <=  rbx will contain base address of this module  
	0x49, 0xb8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // mov r8, SystemVaddr   
	0x49, 0x01, 0xD8,                                             // add r8, rbx		    
	0x5b,                                                         // pop rbx                 <= restore rbx
	0x49, 0xb9, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // mov r9, SectionSize
	0x31, 0xc0, 0x41, 0xb3, 0x01, 0x0f, 0xb6, 0xe8, 0x41, 0x8a, 0x2c, 0x2a, 0x42, 0x30, 0x2c, 0x00, 0x48, 0x83, 0xf8, 0x01, 0x75, 0x0b, 0x80, 0x7e, 0x11, 0x26, 0x41, 0x0f, 0x44, 0xcb, 0x0f, 0x44, 0xd7, 0x48, 0xff, 0xc0, 0x4c, 0x39, 0xc8, 0x75, 0xdc, 0x84, 0xc9, 0x74, 0x05, 0x66, 0x89, 0x54, 0x24, 0x38, 0x48, 0x8b, 0x43, 0x40, 0x4c, 0x89, 0xe2, 0x48, 0x89, 0xc1, 0xff, 0x50, 0x08, // 63
	0x48, 0x81, 0xC4, 0x60, 0x02, 0x00, 0x00, 0x5B, 0x5E, 0x5F, 0x5D, 0x41, 0x5C,   // 13 add rsp,0x260; pop rbx; pop rsi, pop rdi, pop rbp, pop r12
	0x5F, 0x5E, 0x5D, 0x5C, 0x5B, 0x5A, 0x59, 0x58,               // pop registers
	0xE9, 0xFF, 0xFF, 0xFF, 0xFF                                  // jmp oep
};

void CreateDecodeStub(QWORD SectionVaddr, QWORD SectionVsize, QWORD oep, QWORD extRaddr, DWORD decodeStubOffset) {
	UINT offsetOffset = 8 + 204 + 1 + 5 + 1 + 4 - 1;
	UINT decodeStartOffset = offsetOffset + 6;
	UINT decodeSizeOffset = decodeStartOffset + 14;
	UINT jmpOepAddrOffset = decodeSizeOffset + 7 + 63 + 13 + 8 + 2;
	long oepOffset = oep - (extRaddr + jmpOepAddrOffset - 1) - 5;
	DWORD offset = decodeStubOffset + (8 + 204 + 1 + 5 + 1 - 1);

	memcpy(&decodeStub[offsetOffset], &offset, sizeof(DWORD));
	memcpy(&decodeStub[decodeStartOffset], &SectionVaddr, sizeof(QWORD));
	memcpy(&decodeStub[decodeSizeOffset], &SectionVsize, sizeof(QWORD));
	memcpy(&decodeStub[jmpOepAddrOffset], &oepOffset, sizeof(DWORD));
	return;
}

UCHAR* ReadTargetFile(WCHAR* lpTargetFilename, DWORD* dwTargetBinSize, UINT extSize) {
	HANDLE hTargetBin;
	DWORD dwReadSize;
	UCHAR* lpTargetBinBuffer;
	bool bRes;

	hTargetBin = CreateFileW(lpTargetFilename, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hTargetBin == INVALID_HANDLE_VALUE) {
		Err("No Such File");
		return 0;
	}

	*dwTargetBinSize = GetFileSize(hTargetBin, NULL);
	if (*dwTargetBinSize == -1) {
		Err("Failed to get file size");
		return 0;
	}

	DWORD newSize = *dwTargetBinSize + (DWORD)extSize;
	lpTargetBinBuffer = (UCHAR*)malloc(sizeof(DWORD) * newSize);
	if (lpTargetBinBuffer == NULL) {
		Err("Failed to allocate region to read file");
		return 0;
	}
	else memset(lpTargetBinBuffer, 0, sizeof(DWORD) * newSize);

	bRes = ReadFile(hTargetBin, lpTargetBinBuffer, *dwTargetBinSize, &dwReadSize, NULL);
	if (!bRes && *dwTargetBinSize != dwReadSize) {
		Err("Failed to read file");
		return 0;
	}

	CloseHandle(hTargetBin);

	return lpTargetBinBuffer;
}

BOOL WritePackedFile(WCHAR* lpPackedFilename, UCHAR* lpTargetBinBuffer, DWORD dwTargetBinSize, SectionConfig* target, UINT extSize) {
	bool bRes;

	*(target->characteristic) |= IMAGE_SCN_MEM_WRITE;

	HANDLE hPackedBin = CreateFileW(lpPackedFilename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPackedBin == INVALID_HANDLE_VALUE) {
		Err("No Such File");
		return FALSE;
	}

	DWORD dwWriteSize;
	bRes = WriteFile(hPackedBin, lpTargetBinBuffer, dwTargetBinSize + (DWORD)extSize, &dwWriteSize, NULL);
	if (!bRes && (dwTargetBinSize + (DWORD)extSize) != dwWriteSize) {
		Err("Write Failed");
		return FALSE;
	}

	CloseHandle(hPackedBin);

	return TRUE;
}

void AddExtSection(PE* pe, DWORD dwTargetBinSize, UINT extSize) {
	// appending additional data on EOF is done in ReadTargetFile

	// change size of image
	DWORD newSizeOfImage = 0;
	while (newSizeOfImage <= extSize)
		newSizeOfImage += pe->OptionalHeader->SectionAlignment;

	pe->OptionalHeader->SizeOfImage += newSizeOfImage;

	// determine ext location and section before ext
	QWORD extSecHeaderLocation = (QWORD)IMAGE_FIRST_SECTION(pe->NtHeader) + ((QWORD)sizeof(IMAGE_SECTION_HEADER) * pe->FileHeader->NumberOfSections);
	PIMAGE_SECTION_HEADER extSecHeader = (PIMAGE_SECTION_HEADER)(extSecHeaderLocation);
	QWORD beforeSecHeaderLocation = (QWORD)IMAGE_FIRST_SECTION(pe->NtHeader) + ((QWORD)sizeof(IMAGE_SECTION_HEADER) * (pe->FileHeader->NumberOfSections - 1));
	PIMAGE_SECTION_HEADER beforeSecHeader = (PIMAGE_SECTION_HEADER)beforeSecHeaderLocation;

	// change number of sectiosns
	pe->FileHeader->NumberOfSections += 1;
	DbgPrint("extSecHeaderLocation: 0x%I64X, NumberOfSections: %d", extSecHeaderLocation, pe->FileHeader->NumberOfSections);
	DbgPrint("beforeSecHeaderLocation: 0x%I64X, beforeSecHeader: %s", beforeSecHeaderLocation, beforeSecHeader->Name);


	// change ext section attributes
	DWORD vaddrOffset = 0;
	while (vaddrOffset < beforeSecHeader->Misc.VirtualSize)
		vaddrOffset += pe->OptionalHeader->SectionAlignment;

	char secname[5] = ".ext";
	strncpy_s((char*)extSecHeader->Name, 8, secname, 5);
	extSecHeader->Misc.VirtualSize = extSize;
	extSecHeader->VirtualAddress = beforeSecHeader->VirtualAddress + vaddrOffset;
	extSecHeader->SizeOfRawData = extSize;
	extSecHeader->PointerToRawData = dwTargetBinSize;
	extSecHeader->PointerToRelocations = 0;
	extSecHeader->PointerToLinenumbers = 0;
	extSecHeader->NumberOfRelocations = 0;
	extSecHeader->NumberOfLinenumbers = 0;
	extSecHeader->Characteristics = 0x60000020;

	DbgPrint("name: %s, ext vaddr: 0x%I64X, vsize: %I32X", extSecHeader->Name, extSecHeader->VirtualAddress, extSecHeader->Misc.VirtualSize);
	DbgPrint("sizeOfRawData:%I32X, PointerToRawData: 0x%I32X", extSecHeader->SizeOfRawData, extSecHeader->PointerToRawData);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	bool bRes;

	// handling args
	int nArgc = 0;
	WCHAR* lpCommandLine = GetCommandLineW();
	WCHAR** lppArgv = CommandLineToArgvW(lpCommandLine, &nArgc);
	WCHAR* lpTargetFilename = lppArgv[1];
	WCHAR* lpPackedFilename = lppArgv[2];

	// read target file to be packed
	// lpTargetBinBuffer : head address of target file located in memory
	DWORD dwTargetBinSize;
	UCHAR* lpTargetBinBuffer;
	UINT extSize = 2100;
	lpTargetBinBuffer = ReadTargetFile(lpTargetFilename, &dwTargetBinSize, extSize);
	DbgPrint("lpTargetBinBuffer: 0x%I64X", lpTargetBinBuffer);

	// locate address of headers
	PE* pe = (PE*)malloc(sizeof(PE));
	ParsePE(pe, lpTargetBinBuffer);


	// add ext section to put decode stub
	AddExtSection(pe, dwTargetBinSize, extSize);


	// find section to encrypt(target) and to put decodestub(ext)
	SectionConfig* target = (SectionConfig*)malloc(sizeof(SectionConfig));
	SectionConfig* ext = (SectionConfig*)malloc(sizeof(SectionConfig));
	FindSection(pe, target, ext);



	// new entrypoint
	QWORD newEP = ext->vaddr - pe->ImageBase;

	// エントリーポイントを含むセクションを暗号化
	aes_encrypt((UCHAR*)(target->raddr + lpTargetBinBuffer), target->vsize);

	// test decrypt
	aes_decrypt_test();

	// put decode stub to ext section
	CreateDecodeStub(target->vaddr, target->vsize, pe->oep, ext->raddr, (DWORD)newEP);
	memcpy((UCHAR*)(ext->raddr + lpTargetBinBuffer), decodeStub, sizeof(decodeStub));
	DbgPrint("DecodeStub located to 0x%I64X", (ext->raddr + lpTargetBinBuffer));

	// overwrite entrypoint
	pe->OptionalHeader->AddressOfEntryPoint = newEP;
	DbgPrint("Entry Point Modified to 0x%I64X", ext->vaddr);


	// write packed file
	if (WritePackedFile(lpPackedFilename, lpTargetBinBuffer, dwTargetBinSize, target, extSize) == FALSE) {
		Err("Writing packed file failed");
		return 1;
	}

	DbgPrint("Packing SUCCESS!!");

	// closing
	if (lpTargetBinBuffer) {
		free(lpTargetBinBuffer);
		lpTargetBinBuffer = NULL;
	}

	return 0;
}

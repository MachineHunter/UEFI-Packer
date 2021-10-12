#include <windows.h>
#include <dbghelp.h>
#include <stdlib.h>
#include <iostream>
#include <sstream>
#pragma comment(lib, "dbghelp.lib")

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

void XorEncode(UCHAR* start, DWORD size, BYTE encoder) {
	for (UINT i = 0; i < size; i++)
		start[i] ^= encoder;
	return;
}

UCHAR decodeStub[] = {
	0x90, 0x90,                                                   // 1 for 0xEB, 0xFE to break
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,               // 9 push registers
	0xE8, 0x00, 0x00, 0x00, 0x00,                                 // 14 call $+5 (next instruction)
	0x58,                                                         // 15 pop rax  <=  current instruction address will be set to rax
	0x48, 0x2D, 0xFF, 0xFF, 0xFF, 0xFF,                           // 21 sub rax, offset  <=  rax will contain base address of this module
	0x48, 0xBE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // 31 movabs rsi, SectionVaddr
	0x48, 0x01, 0xC6,                                             // 34 add rsi, rax
	0x48, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // 44 movabs rcx, SectionSize 
	0xB0, 0xFF,                                                   // 46 mov al, decoder
	0x30, 0x06,                                                   // 48 LOOP: xor byte ptr [rsi], al
	0x48, 0xFF, 0xC6,                                             // 51 inc rsi
	0x48, 0xFF, 0xC9,                                             // 54 dec rcx
	0x75, 0xF6,                                                   // 56 jne LOOP
	0x5F, 0x5E, 0x5D, 0x5C, 0x5B, 0x5A, 0x59, 0x58,               // 64 pop registers
	0xE9, 0xFF, 0xFF, 0xFF, 0xFF                                  // 69 jmp oep
};

void CreateDecodeStub(QWORD SectionVaddr, QWORD SectionVsize, BYTE decoder, QWORD oep, QWORD extRaddr, DWORD decodeStubOffset) {
	UINT offsetOffset = 18;
	UINT decodeStartOffset = 24;
	UINT decodeSizeOffset = 37;
	UINT decoderOffset = 46;
	UINT jmpOepAddrOffset = 66;

	long oepOffset = oep - (extRaddr + jmpOepAddrOffset - 1) - 5;
	DWORD offset = decodeStubOffset + 15;

	memcpy(&decodeStub[offsetOffset], &offset, sizeof(DWORD));
	memcpy(&decodeStub[decodeStartOffset], &SectionVaddr, sizeof(QWORD));
	memcpy(&decodeStub[decodeSizeOffset], &SectionVsize, sizeof(QWORD));
	memcpy(&decodeStub[decoderOffset], &decoder, sizeof(BYTE));
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
	bRes = WriteFile(hPackedBin, lpTargetBinBuffer, dwTargetBinSize+(DWORD)extSize, &dwWriteSize, NULL);
	if (!bRes && (dwTargetBinSize+(DWORD)extSize) != dwWriteSize) {
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

DWORD* CheckSecureBoot(PE* pe) {
	DWORD* certificateTable = (DWORD*)pe->OptionalHeader->DataDirectory[4].VirtualAddress;
	DbgPrint("Certificate is at offset: 0x%I32X", certificateTable);

	if (certificateTable == 0) {
		// checked by Hash (Secure Boot)
		DbgPrint("[!!] This file is not packable. Exiting...");
		exit(0);
	}
	
	// checked by certificate
	return certificateTable;
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
	UINT extSize = 400;
	lpTargetBinBuffer = ReadTargetFile(lpTargetFilename, &dwTargetBinSize, extSize);
	DbgPrint("lpTargetBinBuffer: 0x%I64X", lpTargetBinBuffer);

	// locate address of headers
	PE* pe = (PE*)malloc(sizeof(PE));
	ParsePE(pe, lpTargetBinBuffer);

	// check if this is packable when secure-boot is enabled
	// check by hash: exit
	// check by certificate: get the address of certificate list
	DWORD* certificateTable = CheckSecureBoot(pe);

	// add ext section to put decode stub
	AddExtSection(pe, dwTargetBinSize, extSize);


	// find section to encrypt(target) and to put decodestub(ext)
	SectionConfig* target = (SectionConfig*)malloc(sizeof(SectionConfig));
	SectionConfig* ext = (SectionConfig*)malloc(sizeof(SectionConfig));
	FindSection(pe, target, ext);



	// new entrypoint
	QWORD newEP = ext->vaddr - pe->ImageBase;

	// エントリーポイントを含むセクションを暗号化
	BYTE encoder = 0xff;
	XorEncode((UCHAR*)(target->raddr + lpTargetBinBuffer), target->vsize, encoder);

	// put decode stub to ext section
	CreateDecodeStub(target->vaddr, target->vsize, encoder, pe->oep, ext->raddr, (DWORD)newEP);
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
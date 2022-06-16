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

void ShiftAddrOfHeaders(PE* pe, UCHAR* lpTargetBinBuffer, UINT *sizeIncrease) {
	// shift optional header addresses
	pe->oep += *sizeIncrease;
	pe->OptionalHeader->BaseOfCode += *sizeIncrease;
	
	// shift each data directories' vaddr
	PIMAGE_DATA_DIRECTORY dataDirectory = (PIMAGE_DATA_DIRECTORY)(pe->NtHeader->OptionalHeader.DataDirectory);
	for (int i = 0; i < 16; i++) {
		if (dataDirectory[i].VirtualAddress != 0) {
			dataDirectory[i].VirtualAddress += *sizeIncrease;
			DbgPrint("%d dataDirectory present", i);
		}

		// if it is Relocation Directory
		if (i == 5) {
			QWORD relocDirAddr = (QWORD)lpTargetBinBuffer + (QWORD)dataDirectory[i].VirtualAddress;
			WORD* typeOffsetAddr = (WORD*)(relocDirAddr + sizeof(DWORD)*2);
			PIMAGE_BASE_RELOCATION relocDir = (PIMAGE_BASE_RELOCATION)relocDirAddr;
			DWORD relocSize = relocDir->SizeOfBlock - sizeof(DWORD)*2;
			DbgPrint("relocation table size (without vaddr and size field): 0x%X", relocSize);
			for (int j = 0; j < relocSize/sizeof(WORD); j++) {
				// first 4 bit is type and lower 12 bit is offset but doesn't this overflow and overwrite type?
				typeOffsetAddr[j] += *sizeIncrease;
			}
		}

		// if it is Debug Directory
		if (i == 6) {
			PIMAGE_DEBUG_DIRECTORY debugDir = (PIMAGE_DEBUG_DIRECTORY)(lpTargetBinBuffer + (QWORD)dataDirectory[i].VirtualAddress);
			debugDir->AddressOfRawData += *sizeIncrease;
			debugDir->PointerToRawData += *sizeIncrease;
		}
	}

	// shift each section header's vaddr
	QWORD sectionLocation = (QWORD)IMAGE_FIRST_SECTION(pe->NtHeader);
	QWORD sectionSize = (QWORD)sizeof(IMAGE_SECTION_HEADER);

	for (int i = 0; i < pe->FileHeader->NumberOfSections; i++) {
		pe->SectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
		// shifted all sections so shift header's vaddr and raddr too
		pe->SectionHeader->VirtualAddress += *sizeIncrease;
		pe->SectionHeader->PointerToRawData += *sizeIncrease;
		sectionLocation += sectionSize;
	}
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

UCHAR* ReadTargetFile(WCHAR* lpTargetFilename, DWORD* dwTargetBinSize, UINT extSize, UINT extHeaderSize) {
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

	DWORD newSize = *dwTargetBinSize + (DWORD)extSize + (DWORD)extHeaderSize + (DWORD)0x1000;
	// 0x1000 is a buffer since we extend more than extHeaderSize due to section alignment
	// if extHeaderSize=0x28 and section alignment is 0x20, additional 0x40 is required
	// 0x1000-0x40 will not be included in the output file since we're specifying only the required size when WriteFile
	// 0x1000 is not enough if section alignment is more than 0x1000, In that case, error will occur in AddExtSection.

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

BOOL WritePackedFile(WCHAR* lpPackedFilename, UCHAR* lpTargetBinBuffer, DWORD dwTargetBinSize, SectionConfig* target, UINT extSize, UINT *sizeIncreased) {
	bool bRes;

	*(target->characteristic) |= IMAGE_SCN_MEM_WRITE;

	HANDLE hPackedBin = CreateFileW(lpPackedFilename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPackedBin == INVALID_HANDLE_VALUE) {
		Err("No Such File");
		return FALSE;
	}

	DWORD dwWriteSize;
	bRes = WriteFile(hPackedBin, lpTargetBinBuffer, dwTargetBinSize + (DWORD)extSize + (DWORD)(*sizeIncreased), &dwWriteSize, NULL);
	if (!bRes && (dwTargetBinSize + (DWORD)extSize + (DWORD)(*sizeIncreased)) != dwWriteSize) {
		Err("Write Failed");
		return FALSE;
	}

	CloseHandle(hPackedBin);

	return TRUE;
}

void AddExtSection(PE* pe, UCHAR* lpTargetBinBuffer, DWORD dwTargetBinSize, UINT extSize, UINT extHeaderSize, UINT* sizeIncrease) {
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

	// change number of sections
	pe->FileHeader->NumberOfSections += 1;
	DbgPrint("extSecHeaderLocation: 0x%I64X, NumberOfSections: %d", extSecHeaderLocation, pe->FileHeader->NumberOfSections);
	DbgPrint("beforeSecHeaderLocation: 0x%I64X, beforeSecHeader: %s", beforeSecHeaderLocation, beforeSecHeader->Name);
	

	// shift all other sections (to allocate space for ext section header attributes entry)
	//  dwTargetBinSize(whole file size) = headerSize + sectionsSize
	if (pe->OptionalHeader->SectionAlignment > 0x1000)
		Err("increase buffer to more than 0x1000");

	*sizeIncrease = 0;
	while (*sizeIncrease <= extHeaderSize)
		*sizeIncrease += pe->OptionalHeader->SectionAlignment; // sections need to be aligned
	pe->OptionalHeader->SizeOfImage += *sizeIncrease;
	pe->OptionalHeader->SizeOfHeaders += extHeaderSize;
	QWORD headerSize = extSecHeaderLocation - (QWORD)lpTargetBinBuffer;
	DWORD sectionsSize = dwTargetBinSize - headerSize;
	memmove((UCHAR*)(extSecHeaderLocation + *sizeIncrease), (UCHAR*)extSecHeaderLocation, sectionsSize);


	// change ext section attributes
	DWORD vaddrOffset = 0;
	while (vaddrOffset < beforeSecHeader->Misc.VirtualSize)
		vaddrOffset += pe->OptionalHeader->SectionAlignment;

	char secname[5] = ".ext";
	memset((char*)extSecHeader->Name, 0, 8);
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
	UINT extSize = 400;
	UINT extHeaderSize = 0x28; // sizeof(IMAGE_SECTION_HEADER) と同じ
	UINT sizeIncrease = 0;
	lpTargetBinBuffer = ReadTargetFile(lpTargetFilename, &dwTargetBinSize, extSize, extHeaderSize);
	DbgPrint("lpTargetBinBuffer: 0x%I64X", lpTargetBinBuffer);

	// locate address of headers
	PE* pe = (PE*)malloc(sizeof(PE));
	ParsePE(pe, lpTargetBinBuffer);


	// add ext section to put decode stub
	// also, shift all sections to allocate space for ext section header entry
	AddExtSection(pe, lpTargetBinBuffer, dwTargetBinSize, extSize, extHeaderSize, &sizeIncrease);

	// shift address value of pe header
	ShiftAddrOfHeaders(pe, lpTargetBinBuffer, &sizeIncrease);

	// find section to encrypt(target) and to put decodestub(ext)
	SectionConfig* target = (SectionConfig*)malloc(sizeof(SectionConfig));
	SectionConfig* ext = (SectionConfig*)malloc(sizeof(SectionConfig));
	FindSection(pe, target, ext);



	// new entrypoint
	QWORD newEP = ext->vaddr - pe->ImageBase;

	// xor .text section with one byte 0xFF
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
	if (WritePackedFile(lpPackedFilename, lpTargetBinBuffer, dwTargetBinSize, target, extSize, &sizeIncrease) == FALSE) {
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
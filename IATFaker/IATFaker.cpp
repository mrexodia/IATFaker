#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <dbghelp.h>

int gtfo(const char* text = "")
{
    printf("gtfo! (%s)\n", text);
    return -1;
}

int main(int argc, char* argv[])
{
    //LEAKY AND UNSAFE!
    if (argc < 2)
        return gtfo("argc");

	bool fakeEverything = argc > 2;

    char sysdir[MAX_PATH];
    if (!GetSystemDirectoryA(sysdir, MAX_PATH))
        return gtfo("GetSystemDirectory");

	char exedir[MAX_PATH];
	GetModuleFileNameA(GetModuleHandle(0), exedir, MAX_PATH);
	*strrchr(exedir, '\\') = '\0';

    auto dllExists = [&sysdir](const char* name)
    {
        std::string file(sysdir);
        file += "\\";
        file += name;
        DWORD attrib = GetFileAttributesA(file.c_str());
        return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
    };

    //read the file
    auto hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return gtfo("CreateFile");

    //map the file
    auto hMappedFile = CreateFileMappingA(hFile, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr); //notice SEC_IMAGE
    if (!hMappedFile)
        return gtfo("CreateFileMappingA");

    //map the sections appropriately
    auto fileMap = MapViewOfFile(hMappedFile, FILE_MAP_READ, 0, 0, 0);
    if (!fileMap)
        return gtfo("MapViewOfFile");

    auto pidh = PIMAGE_DOS_HEADER(fileMap);
    if (pidh->e_magic != IMAGE_DOS_SIGNATURE)
        return gtfo("IMAGE_DOS_SIGNATURE");

    auto pnth = PIMAGE_NT_HEADERS(ULONG_PTR(fileMap) + pidh->e_lfanew);
    if (pnth->Signature != IMAGE_NT_SIGNATURE)
        return gtfo("IMAGE_NT_SIGNATURE");

#ifdef _WIN64
    if (pnth->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return gtfo("IMAGE_FILE_MACHINE_AMD64");
#else
    if (pnth->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
        return gtfo("IMAGE_FILE_MACHINE_I386");
#endif //_WIN64

    if (pnth->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
        return gtfo("IMAGE_NT_OPTIONAL_HDR_MAGIC");

    SIZE_T imageSize = pnth->OptionalHeader.SizeOfImage;
    auto readableRva = [fileMap, imageSize](ULONGLONG rva, SIZE_T size)
    {
        if (rva > imageSize || size > imageSize - (SIZE_T)rva)
            return false;
        if (!size)
            return true;

        auto current = (BYTE*)fileMap + (SIZE_T)rva;
        auto end = current + size;
        while (current < end)
        {
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQuery(current, &mbi, sizeof(mbi)))
                return false;
            if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
                return false;
            auto regionEnd = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
            if (regionEnd <= current)
                return false;
            current = regionEnd < end ? regionEnd : end;
        }
        return true;
    };

    auto ptrFromRva = [fileMap, readableRva](ULONGLONG rva, SIZE_T size) -> void*
    {
        if (!readableRva(rva, size))
            return nullptr;
        return (BYTE*)fileMap + (SIZE_T)rva;
    };

    auto cstrFromRva = [fileMap, imageSize](ULONGLONG rva) -> const char*
    {
        if (rva >= imageSize)
            return nullptr;

        auto start = (BYTE*)fileMap + (SIZE_T)rva;
        auto current = start;
        auto imageEnd = (BYTE*)fileMap + imageSize;
        while (current < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQuery(current, &mbi, sizeof(mbi)))
                return nullptr;
            if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
                return nullptr;
            auto regionEnd = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
            if (regionEnd <= current)
                return nullptr;
            if (regionEnd > imageEnd)
                regionEnd = imageEnd;
            for (; current < regionEnd; current++)
            {
                if (*current == '\0')
                    return (const char*)start;
            }
        }
        return nullptr;
    };

    auto importDir = pnth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    puts("Import Directory");
    printf(" RVA: %08X\n", importDir.VirtualAddress);
    printf("Size: %08X\n\n", importDir.Size);

    if (!importDir.VirtualAddress || !importDir.Size)
        return gtfo("No Import directory!");

    std::string compileBat("@echo off\n");

    auto importDescriptor = PIMAGE_IMPORT_DESCRIPTOR(ptrFromRva(importDir.VirtualAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR)));
    if (importDescriptor)
    {
        for (DWORD descriptorRva = importDir.VirtualAddress; ; descriptorRva += sizeof(IMAGE_IMPORT_DESCRIPTOR))
        {
            importDescriptor = PIMAGE_IMPORT_DESCRIPTOR(ptrFromRva(descriptorRva, sizeof(IMAGE_IMPORT_DESCRIPTOR)));
            if (!importDescriptor)
            {
                puts("INVALID IMPORT DESCRIPTOR");
                break;
            }
            if (!importDescriptor->OriginalFirstThunk && !importDescriptor->FirstThunk && !importDescriptor->Name)
                break;

            printf("OriginalFirstThunk: %08X\n", importDescriptor->OriginalFirstThunk);
            printf("     TimeDateStamp: %08X\n", importDescriptor->TimeDateStamp);
            printf("    ForwarderChain: %08X\n", importDescriptor->ForwarderChain);
            const char* modname = cstrFromRva(importDescriptor->Name);
            if(modname)
                printf("              Name: %08X \"%s\"\n", importDescriptor->Name, modname);
            else
                printf("              Name: %08X INVALID\n", importDescriptor->Name);
            printf("              Name: %08X\n", importDescriptor->Name);
            printf("        FirstThunk: %08X\n", importDescriptor->FirstThunk);

            std::string fakeDef;
			bool fakeThisShit = modname && (fakeEverything || (!dllExists(modname) && _strnicmp(modname, "api-ms-win-", 11) != 0));
            if (fakeThisShit)
            {
                printf("FAKE %s\n", modname);
                fakeDef += "LIBRARY ";
                fakeDef += modname;
                fakeDef += "\n";
                fakeDef += "EXPORTS";
                fakeDef += "\n";
            }

            DWORD thunkRva = importDescriptor->OriginalFirstThunk ? importDescriptor->OriginalFirstThunk : importDescriptor->FirstThunk;
            for (;; thunkRva += sizeof(IMAGE_THUNK_DATA))
            {
                auto thunkData = PIMAGE_THUNK_DATA(ptrFromRva(thunkRva, sizeof(IMAGE_THUNK_DATA)));
                if (!thunkData)
                {
                    printf("             Function: %08X INVALID THUNK\n", thunkRva);
                    break;
                }

                auto data = thunkData->u1.AddressOfData;
                if (!data)
                    break;

                if (IMAGE_SNAP_BY_ORDINAL(data))
                {
                    auto ordinal = IMAGE_ORDINAL(data);
                    printf("              Ordinal: %u\n", (unsigned)ordinal);
                    char ordname[256];
                    sprintf_s(ordname, "%u", (unsigned)ordinal);
                    auto fakename = std::string("__fake") + ordname;
                    fakeDef += fakename;
                    fakeDef += " @";
                    fakeDef += ordname;
                    fakeDef += " = kernel32.DebugBreak";
                    fakeDef += "\n";
                }
                else
                {
                    auto impname = cstrFromRva(data + FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name));
                    if (impname)
                    {
                        printf("             Function: %p \"%s\"\n", (void*)data, impname);
                        fakeDef += impname;
                        fakeDef += " = kernel32.DebugBreak";
                        fakeDef += "\n";
                    }
                    else
                        printf("             Function: %p INVALID\n", (void*)data);
                }
            }

            if (fakeThisShit)
            {
                std::string defName(modname);
                defName += ".def";
                //link /DEF:steam_api64.dll.def /DLL /OUT:steam_api64.dll /NODEFAULTLIB /NOENTRY
				compileBat += '\"';
				compileBat += exedir;
                compileBat += "\\link\\link.exe\" /DEF:";
                compileBat += defName;
                compileBat += " /DLL";
#ifdef _WIN64
                compileBat += " /MACHINE:X64";
#else
                compileBat += " /MACHINE:X86";
#endif
                compileBat += " /OUT:";
                compileBat += modname;
                compileBat += " /NODEFAULTLIB /NOENTRY\n";
                auto hDef = CreateFileA(defName.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                DWORD written = 0;
                WriteFile(hDef, fakeDef.c_str(), (DWORD)fakeDef.length(), &written, nullptr);
                CloseHandle(hDef);
            }

            puts("");
        }
    }
    else
        puts("INVALID IMPORT DESCRIPTOR");

    compileBat += "del *.exp *.lib *.def";
    auto hDef = CreateFileA("fake.bat", GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD written = 0;
    WriteFile(hDef, compileBat.c_str(), (DWORD)compileBat.length(), &written, nullptr);
    CloseHandle(hDef);

    system("fake");
	DeleteFileA("fake.bat");

    return 0;
}

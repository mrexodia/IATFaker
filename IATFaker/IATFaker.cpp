#include <windows.h>
#include <stdio.h>
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

    auto importDir = pnth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    puts("Import Directory");
    printf(" RVA: %08X\n", importDir.VirtualAddress);
    printf("Size: %08X\n\n", importDir.Size);

    if (!importDir.VirtualAddress || !importDir.Size)
        return gtfo("No Import directory!");

    std::string compileBat("@echo off\n");

    auto importDescriptor = PIMAGE_IMPORT_DESCRIPTOR(ULONG_PTR(fileMap) + importDir.VirtualAddress);
    if (!IsBadReadPtr((char*)fileMap + importDir.VirtualAddress, 0x1000))
    {
        for (; importDescriptor->FirstThunk; importDescriptor++)
        {
            printf("OriginalFirstThunk: %08X\n", importDescriptor->OriginalFirstThunk);
            printf("     TimeDateStamp: %08X\n", importDescriptor->TimeDateStamp);
            printf("    ForwarderChain: %08X\n", importDescriptor->ForwarderChain);
            const char* modname = nullptr;
            if (!IsBadReadPtr((char*)fileMap + importDescriptor->Name, 0x1000))
                modname = (char*)fileMap + importDescriptor->Name;
            if(modname)
                printf("              Name: %08X \"%s\"\n", importDescriptor->Name, modname);
            else
                printf("              Name: %08X INVALID\n", importDescriptor->Name);
            printf("              Name: %08X\n", importDescriptor->Name);
            printf("        FirstThunk: %08X\n", importDescriptor->FirstThunk);

            std::string fakeDef;
			bool fakeThisShit = fakeEverything || (modname && !dllExists(modname) && _strnicmp(modname, "api-ms-win-", 11) != 0);
            if (fakeThisShit)
            {
                printf("FAKE %s\n", modname);
                fakeDef += "LIBRARY ";
                fakeDef += modname;
                fakeDef += "\n";
                fakeDef += "EXPORTS";
                fakeDef += "\n";
            }

            auto thunkData = PIMAGE_THUNK_DATA(ULONG_PTR(fileMap) + importDescriptor->FirstThunk);
            for (; thunkData->u1.AddressOfData; thunkData++)
            {
                auto rva = ULONG_PTR(thunkData) - ULONG_PTR(fileMap);

                auto data = thunkData->u1.AddressOfData;
                if (data & IMAGE_ORDINAL_FLAG)
                {
                    auto ordinal = data & ~IMAGE_ORDINAL_FLAG;
                    printf("              Ordinal: %p\n", (void*)ordinal);
                    char ordname[256];
                    sprintf_s(ordname, "%zu", ordinal);
                    auto fakename = std::string("__fake") + ordname;
                    fakeDef += fakename;
                    fakeDef += " @";
                    fakeDef += ordname;
                    fakeDef += " = kernel32.DebugBreak";
                    fakeDef += "\n";
                }
                else
                {
                    auto importByName = PIMAGE_IMPORT_BY_NAME(ULONG_PTR(fileMap) + data);
                    if (!IsBadReadPtr(importByName, 0x1000))
                    {
                        auto impname = (char*)importByName->Name;
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
                compileBat += " /MACHINE:X86";
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

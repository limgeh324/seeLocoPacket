#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <nlohmann/json.hpp>

DWORD requestReturnAddress = 0x00000000;
BYTE jmpByteArray[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

DWORD hook(LPVOID lpFunction, DWORD returnAddress)
{
    DWORD dwAddr = returnAddress - 5;
    DWORD dwCalc = ((DWORD)lpFunction - dwAddr - 5);

    memcpy(&jmpByteArray[1], &dwCalc, 4);
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, jmpByteArray, sizeof(jmpByteArray), 0);
    return dwAddr;
}

void printRequestPacket(char* packet)
{
    uint32_t bodySize = *(uint32_t*)(packet + 18);

    std::cout << "[+] requestPacket!" << std::endl;

    if (0 >= bodySize) {
        std::cout << "[+] body -> none" << std::endl;
    }
    else
    {
        std::vector<uint8_t> bsonBody(packet + 22, packet + bodySize + 22);
        nlohmann::json body = nlohmann::json::from_bson(bsonBody);

        std::cout << "[+] body -> " << body.dump() << std::endl << std::endl;
    }
}

void __declspec(naked) requestHookASM()
{
    __asm
    {
        pushad

        mov ebx, [esi + 0x34]
        push ebx
        call printRequestPacket
        add esp, 4

        popad

        push ebp
        mov ebp, esp
        push -01

        jmp requestReturnAddress
    }
}

void seeLocoPacketMain()
{
    DWORD processAddress = (DWORD)GetModuleHandleA("KakaoTalk.exe");
    std::cout << "[+] processAddress -> 0x" << std::uppercase << std::hex << processAddress << std::endl;
    DWORD requestAddress = processAddress + 0x1079160; // first of 55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 51 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 8B F9 8B 4F 14 85 C9 0F 84 ?? ?? ?? ?? F6 87 9C 00 00 00 06 0F 85 ?? ?? ?? ?? 83 BF 94 00 00 00 00 0F 85 ?? ?? ?? ?? 8B 01 8B 40 5C FF D0 84 C0 0F 85
    std::cout << "[+] requestAddress -> 0x" << std::uppercase << std::hex << requestAddress << std::endl << std::endl;
    requestReturnAddress = requestAddress + 5;

    hook(requestHookASM, requestReturnAddress);
    std::cout << "[+] hooked request!" << std::endl << std::endl;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        AllocConsole();
        freopen("CON", "w", stdout);
        CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)seeLocoPacketMain, NULL, NULL, NULL);

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


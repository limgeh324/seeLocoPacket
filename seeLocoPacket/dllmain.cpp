#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <nlohmann/json.hpp>

DWORD requestReturnAddress = 0x10762BD; // first of 84 C0 0F 84 ?? ?? ?? ?? 8B 46 38 3B F8 77 3D 01 7E 3C 2B
DWORD requestCallAddress = 0x1079160; // Address called from the previous of requestReturnAddress
BYTE jmpByteArray[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

DWORD hook(LPVOID lpFunction, DWORD returnAddress)
{
    DWORD dwAddr = returnAddress - 5;
    DWORD dwCalc = ((DWORD)lpFunction - dwAddr - 5);

    memcpy(&jmpByteArray[1], &dwCalc, 4);
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, jmpByteArray, sizeof(jmpByteArray), 0);
    return dwAddr;
}

struct LocoPacketHeader {
    uint32_t packetID;
    std::string methodName;
    uint32_t bodySize;
};

LocoPacketHeader getLocoPacketHeader(char* packetHeader) {
    uint32_t packetID = *(uint32_t*)packetHeader;
    char* methodNameChar = new char[11];
    memcpy(methodNameChar, packetHeader + 6, 11);
    std::string methodName(methodNameChar);
    uint32_t bodySize = *(uint32_t*)(packetHeader + 18);

    LocoPacketHeader locoPacketHeader;
    locoPacketHeader.packetID = packetID;
    locoPacketHeader.methodName = methodName;
    locoPacketHeader.bodySize = bodySize;

    return locoPacketHeader;
}

void printRequestPacket(char* packet)
{
    LocoPacketHeader packetHeader = getLocoPacketHeader(packet);

    std::cout << "[+] requestPacket!" << std::endl;
    std::cout << "[-] packetID -> " << packetHeader.packetID << std::endl;
    std::cout << "[-] methodName -> " << packetHeader.methodName << std::endl;
    std::cout << "[-] bodySize -> " << packetHeader.bodySize << std::endl;

    if (0 >= packetHeader.bodySize) {
        std::cout << "[-] body -> none" << std::endl << std::endl;
    }
    else
    {
        std::vector<uint8_t> bsonBody(packet + 22, packet + packetHeader.bodySize + 22);
        nlohmann::json body = nlohmann::json::from_bson(bsonBody);

        std::cout << "[-] body -> " << body.dump() << std::endl << std::endl;
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

        call requestCallAddress
        jmp requestReturnAddress
    }
}

void seeLocoPacketMain()
{
    DWORD processAddress = (DWORD)GetModuleHandleA("KakaoTalk.exe");
    requestReturnAddress += processAddress;
    requestCallAddress += processAddress;
    std::cout << "[+] processAddress -> 0x" << std::uppercase << std::hex << processAddress << std::endl;
    std::cout << "[+] requestReturnAddress -> 0x" << std::uppercase << std::hex << requestReturnAddress << std::endl;
    std::cout << "[+] requestCallAddress -> 0x" << std::uppercase << std::hex << requestCallAddress << std::endl << std::endl;

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


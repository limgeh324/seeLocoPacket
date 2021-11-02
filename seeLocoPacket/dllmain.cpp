#include "pch.h"
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using std::vector;
using std::cout;
using std::endl;

DWORD requestReturnAddress = 0x10762B4;
DWORD responseReturnAddress = 0x10793E4;

BYTE jmpByteArray[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

std::vector<std::uint8_t> packetBuffer;
uint32_t packetSize = -1;

struct LocoPacketHeader
{
    uint32_t packetID;
    std::string methodName;
    uint32_t bodySize;
};

LocoPacketHeader getLocoPacketHeader(char* packetHeader)
{
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

void printPacket(char* packet)
{
    LocoPacketHeader packetHeader = getLocoPacketHeader(packet);

    std::cout << "[-] packetID -> " << std::dec << packetHeader.packetID << std::endl;
    std::cout << "[-] methodName -> " << std::dec << packetHeader.methodName << std::endl;
    std::cout << "[-] bodySize -> " << std::dec << packetHeader.bodySize << std::endl;

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

void printRequest(char* packet)
{
    std::cout << "[+] request!" << std::endl;
    printPacket(packet);
}

void printResponse(char* packet, uint32_t size)
{
    try {
        std::vector<std::uint8_t> buffer(packet, packet + size);

        packetBuffer.insert(packetBuffer.end(), buffer.begin(), buffer.end());

        if (packetSize == -1 && packetBuffer.size() >= 22) {
            LocoPacketHeader packetHeader = getLocoPacketHeader((char*)packetBuffer.data());
            packetSize = packetHeader.bodySize + 22;
        }

        if (packetSize != -1 && packetBuffer.size() >= packetSize) {
            std::cout << "[+] response!" << std::endl;
            printPacket((char*)packetBuffer.data());

            std::vector<std::uint8_t> newBuffer = std::vector<std::uint8_t>(packetBuffer.begin() + packetSize, packetBuffer.end());
            int newSize = newBuffer.size();

            packetBuffer.clear();
            packetSize = -1;

            printResponse((char*)(newBuffer.data()), newSize);
        }
    }
    catch (std::exception& e) {
        std::cout << "[!] Exception ->" << e.what() << std::endl << std::endl;
    }
}

DWORD hook(LPVOID lpFunction, DWORD returnAddress)
{
    DWORD dwAddr = returnAddress - 5;
    DWORD dwCalc = ((DWORD)lpFunction - dwAddr - 5);

    memcpy(&jmpByteArray[1], &dwCalc, 4);
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, jmpByteArray, sizeof(jmpByteArray), 0);
    return dwAddr;
}

void __declspec(naked) requestHookASM() {
    __asm {
        pushad

        mov ebx, [esi + 0x34]

        push ebx
        call printRequest
        add esp, 0x04

        popad

        cmp eax, edi
        cmovb edi, eax

        jmp requestReturnAddress
    }
}

void __declspec(naked) responseHookASM() {
    __asm {
        pushad

        mov ebx, [ebp + 0x10]
        add ebx, 0x14

        push edi
        push ebx
        call printResponse
        add esp, 0x8

        popad

        mov eax, [ebp + 0x10]
        test eax, eax

        jmp responseReturnAddress
    }
}

void Start()
{
    DWORD baseAddress = (DWORD)GetModuleHandleA("KakaoTalk.exe");
    requestReturnAddress += baseAddress;
    responseReturnAddress += baseAddress;
    std::cout << "[+] requestReturnAddress -> 0x" << std::nouppercase << std::hex << requestReturnAddress << std::endl;
    std::cout << "[+] responseReturnAddress -> 0x" << std::nouppercase << std::hex << responseReturnAddress << std::endl;
    hook(requestHookASM, requestReturnAddress);
    std::cout << "[+] hooked request!" << std::endl;
    hook(responseHookASM, responseReturnAddress);
    std::cout << "[+] hooked response!" << std::endl << std::endl;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        AllocConsole();
        freopen("CON", "w", stdout);
        CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Start, NULL, NULL, NULL);

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

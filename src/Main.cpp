#include <direct.h>
#include <xbyak/xbyak.h>

using namespace RE;
using namespace RE::BSScript;
using namespace SKSE;
using namespace SKSE::log;
using namespace SKSE::stl;

namespace Mus {
    static RE::VMHandle ReferenceHandle = 0;
    static RE::FormID ReferenceFormID = 0;

    static std::vector<RE::VMHandle> NodeTransformKeys_ErrorHandles;
    static std::vector<RE::FormID> BodyMorphData_morphName_ErrorFormIDs;
    static std::vector<RE::FormID> BodyMorphData_keyName_ErrorFormIDs;

    static void __stdcall NodeTransformKeys_Error()
    {
        NodeTransformKeys_ErrorHandles.push_back(ReferenceHandle);
        ReferenceHandle = 0;
    }

    static void __stdcall BodyMorphData_morphName_Error()
    {
        BodyMorphData_morphName_ErrorFormIDs.push_back(ReferenceFormID);
        ReferenceFormID = 0;
    }

    static void __stdcall BodyMorphData_keyName_Error()
    {
        BodyMorphData_keyName_ErrorFormIDs.push_back(ReferenceFormID);
        ReferenceFormID = 0;
    }

    static void InitError()
    {
        NodeTransformKeys_ErrorHandles.clear();
        BodyMorphData_morphName_ErrorFormIDs.clear();
        BodyMorphData_keyName_ErrorFormIDs.clear();
    }

    static void __stdcall GetHandle(std::uint64_t handle)
    {
        ReferenceHandle = handle;
    }

    static void __stdcall GetFormID(RE::FormID formID)
    {
        ReferenceFormID = formID;
    }

    static void ErrorNotification()
    {
        if (NodeTransformKeys_ErrorHandles.size() > 0)
        {
            const std::string msg1 = "Invalid NodeTransformKeys : " + std::to_string(NodeTransformKeys_ErrorHandles.size());
            const std::string msg2 = "So skip it instead of crash";
            log::error("{}", msg1);
            log::error("{}", msg2);
            RE::DebugMessageBox((msg1 + "\n" + msg2).c_str());

            const auto vm = RE::BSScript::Internal::VirtualMachine::GetSingleton();
            const auto policy = vm ? vm->GetObjectHandlePolicy() : nullptr;
            if (policy)
            {
                for (const auto& handle : NodeTransformKeys_ErrorHandles)
                {
                    if (handle != 0)
                    {
                        const auto form = policy->GetObjectForHandle(RE::FormType::Reference, handle);
                        const auto ref = form ? form->As<RE::TESObjectREFR>() : nullptr;
                        if (ref)
                            log::error("Invalid NodeTransformKeys : {:x} {}", ref->formID, ref->GetName());
                        else
                            log::error("Invalid NodeTransformKeys : invalid reference");
                    }
                    else
                        log::error("Invalid NodeTransformKeys : invalid reference");
                }
            }
            else
                log::error("Unable to get IObjectHandlePolicy");
        }
        if (BodyMorphData_morphName_ErrorFormIDs.size() > 0)
        {
            const std::string msg1 = "Invalid BodyMorphData morphName : " + std::to_string(BodyMorphData_morphName_ErrorFormIDs.size());
            const std::string msg2 = "So skip it instead of crash";
            log::error("{}", msg1);
            log::error("{}", msg2);
            RE::DebugMessageBox((msg1 + "\n" + msg2).c_str());

            for (const auto& formID : BodyMorphData_morphName_ErrorFormIDs)
            {
                if (formID != 0)
                {
                    const auto ref = RE::TESForm::LookupByID<RE::TESObjectREFR>(formID);
                    if (ref)
                        log::error("Invalid BodyMorphData morphName : {:x} {}", ref->formID, ref->GetName());
                    else
                        log::error("Invalid BodyMorphData morphName : invalid reference");
                }
                else
                    log::error("Invalid NodeTransformKeys : invalid reference");
            }
        }
        if (BodyMorphData_keyName_ErrorFormIDs.size() > 0)
        {
            const std::string msg1 = "Invalid BodyMorphData keyName : " + std::to_string(BodyMorphData_keyName_ErrorFormIDs.size());
            const std::string msg2 = "So skip it instead of crash";
            log::error("{}", msg1);
            log::error("{}", msg2);
            RE::DebugMessageBox((msg1 + "\n" + msg2).c_str());

            for (const auto& formID : BodyMorphData_keyName_ErrorFormIDs)
            {
                if (formID != 0)
                {
                    const auto ref = RE::TESForm::LookupByID<RE::TESObjectREFR>(formID);
                    if (ref)
                        log::error("Invalid BodyMorphData keyName : {:x} {}", ref->formID, ref->GetName());
                    else
                        log::error("Invalid BodyMorphData keyName : invalid reference");
                }
                else
                    log::error("Invalid NodeTransformKeys : invalid reference");
            }
        }
    }

    inline std::wstring GetSKEEDLLName() {
        return REL::Module::IsVR() ? L"skeevr.dll" : L"skee64.dll";
    }

    inline std::uintptr_t FindAddressByPattern(HMODULE a_module, const char* pattern)
    {
        if (!a_module)
            return 0;

        const auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(a_module);
        const auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(a_module) + dosHeader->e_lfanew);

        const auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
        const auto* scanBytes = reinterpret_cast<std::uint8_t*>(a_module);

        std::vector<int> patternBytes;
        const char* start = pattern;
        const char* end = pattern + strlen(pattern);

        for (const char* current = start; current < end; ++current)
        {
            if (*current == '?')
            {
                patternBytes.push_back(-1);
                if (*(current + 1) == '?')
                    current++;
            }
            else if (isxdigit(*current))
            {
                patternBytes.push_back(strtol(current, nullptr, 16));
                while (isxdigit(*current))
                    current++;
            }
        }

        const auto patternSize = patternBytes.size();
        for (std::size_t i = 0; i < sizeOfImage - patternSize; ++i)
        {
            bool found = true;
            for (std::size_t j = 0; j < patternSize; ++j)
            {
                if (scanBytes[i + j] != patternBytes[j] && patternBytes[j] != -1)
                {
                    found = false;
                    break;
                }
            }
            if (found)
            {
                return reinterpret_cast<std::uintptr_t>(&scanBytes[i]);
            }
        }
        return 0;
    }

    void SEVR_RefInfo(HMODULE a_skee)
    {
        // sub_1800754A0 / NodeTransformRegistrationMapHolder::Load
        {
            bool isSuccess = false;

            //const std::uintptr_t hookAddr = baseAddr + 0x75506;
            //const std::uintptr_t returnAddr = baseAddr + 0x75519;
            //const std::uintptr_t target1Addr = baseAddr + 0x56690;
            //const std::uintptr_t target2Addr = baseAddr + 0x75750;

            const char* pattern = "4C 8D 3D ? ? ? ? 4C 89 7C 24 20 4C 8D 0D ? ? ? ? BA 80 00 00 00 44 8D 42 82";
            const std::uintptr_t hookAddr = FindAddressByPattern(a_skee, pattern);
            if (hookAddr)
            {
                log::info("Found NodeTransformRegistrationMapHolder::Load::morphName Hook Address {:x}", hookAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                const std::uintptr_t returnAddr = hookAddr + 0x13;
                log::info("Found NodeTransformRegistrationMapHolder::Load::morphName Return Address {:x}", returnAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                const std::int32_t offset1 = *reinterpret_cast<std::int32_t*>(hookAddr + 0x3);
                const std::uintptr_t target1Addr = (hookAddr + 0x7) + offset1;
                log::info("Found NodeTransformRegistrationMapHolder::Load::morphName Target1 Address {:x}", target1Addr - reinterpret_cast<std::uintptr_t>(a_skee));

                const std::uintptr_t lea2Addr = hookAddr + 0xC;
                const std::int32_t offset2 = *reinterpret_cast<int32_t*>(lea2Addr + 0x3);
                const std::uintptr_t target2Addr = (lea2Addr + 0x7) + offset2;
                log::info("Found NodeTransformRegistrationMapHolder::Load::morphName Target2 Address {:x}", target2Addr - reinterpret_cast<std::uintptr_t>(a_skee));

                struct Patch : Xbyak::CodeGenerator
                {
                    Patch(std::uintptr_t retAddr, std::uintptr_t funcAddr, std::uintptr_t tar1Addr, std::uintptr_t tar2Addr)
                    {
                        // backup
                        pushfq();
                        push(rax);
                        push(rcx);
                        push(rdx);
                        push(r8);
                        push(r9);
                        push(r10);
                        push(r11);

                        mov(rcx, qword[rsp + 0x78]);

                        push(rbp);
                        mov(rbp, rsp);
                        and_(rsp, -16);
                        sub(rsp, 0x20);

                        // get ref handle
                        mov(rax, funcAddr);
                        call(rax);

                        mov(rsp, rbp);
                        pop(rbp);

                        // revert
                        pop(r11);
                        pop(r10);
                        pop(r9);
                        pop(r8);
                        pop(rdx);
                        pop(rcx);
                        pop(rax);
                        popfq();

                        mov(r15, tar1Addr);
                        mov(qword[rsp + 0x20], r15);
                        mov(r9, tar2Addr);

                        push(rax);
                        mov(rax, retAddr);
                        xchg(qword[rsp], rax);
                        ret();
                    }
                };

                static Patch patch(returnAddr, reinterpret_cast<std::uintptr_t>(GetHandle), target1Addr, target2Addr);
                patch.ready();
                std::uint8_t jumpPayload[19] = {
                    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x90, 0x90, 0x90, 0x90, 0x90};
                *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
                DWORD oldProtect;
                if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 19, PAGE_EXECUTE_READWRITE, &oldProtect))
                {
                    memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 19);
                    VirtualProtect(reinterpret_cast<void*>(hookAddr), 19, oldProtect, &oldProtect);
                    isSuccess = true;
                }
            }

            if (isSuccess)
                log::info("NodeTransformRegistrationMapHolder::Load hook handle done");
            else
                log::error("Failed to NodeTransformRegistrationMapHolder::Load hook handle");
        }

        // sub_180010590 / ActorMorphs::Load
        {
            bool isSuccess = false;

            //const std::uintptr_t hookAddr = baseAddr + 0x10604;
            //const std::uintptr_t returnAddr = baseAddr + 0x10613;

            const char* pattern = "33 F6 48 89 74 24 ? 48 89 74 24 ? 8D 4E 38 E8 ? ? ? ? 48 89 00 48 89 40 08 48 89 40 10 66 C7 40 18 01 01";
            const std::uintptr_t hookAddr = FindAddressByPattern(a_skee, pattern);
            if (hookAddr)
            {
                log::info("Found ActorMorphs::Load Hook Address {:x}", hookAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                const std::uintptr_t returnAddr = hookAddr + 0xF;
                log::info("Found ActorMorphs::Load Return Address {:x}", returnAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                struct Patch : Xbyak::CodeGenerator
                {
                    Patch(std::uintptr_t retAddr, std::uintptr_t funcAddr)
                    {
                        // backup
                        pushfq();
                        push(rax);
                        push(rcx);
                        push(rdx);
                        push(r8);
                        push(r9);
                        push(r10);
                        push(r11);

                        cmp(r12d, 3);
                        jb("IsHandle");

                        mov(ecx, dword[rsp + 0x88]);
                        jmp("GetFormID");

                        L("IsHandle");
                        // use low 32bit
                        mov(rcx, qword[rsp + 0x98]);

                        L("GetFormID");
                        // get formID
                        push(rbp);
                        mov(rbp, rsp);
                        and_(rsp, -16);
                        sub(rsp, 0x20);

                        mov(rax, funcAddr);
                        call(rax);

                        mov(rsp, rbp);
                        pop(rbp);

                        // revert
                        pop(r11);
                        pop(r10);
                        pop(r9);
                        pop(r8);
                        pop(rdx);
                        pop(rcx);
                        pop(rax);
                        popfq();

                        xor_(esi, esi);
                        mov(qword[rsp + 0x38], rsi);
                        mov(qword[rsp + 0x40], rsi);
                        lea(ecx, ptr[rsi + 0x38]);

                        push(rax);
                        mov(rax, retAddr);
                        xchg(qword[rsp], rax);
                        ret();
                    }
                };

                static Patch patch(returnAddr, reinterpret_cast<std::uintptr_t>(GetFormID));
                patch.ready();
                std::uint8_t jumpPayload[15] = {
                    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x90};
                *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
                DWORD oldProtect;
                if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 15, PAGE_EXECUTE_READWRITE, &oldProtect))
                {
                    memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 15);
                    VirtualProtect(reinterpret_cast<void*>(hookAddr), 15, oldProtect, &oldProtect);
                    isSuccess = true;
                }
            }

            if (isSuccess)
                log::info("ActorMorphs::Load hook formID done");
            else
                log::error("Failed to ActorMorphs::Load hook formID");
        }
    }

    void SEVR_Patch(HMODULE a_skee)
    {
        // sub_180075190 / NodeTransformKeys::Load
        {
            bool isSuccess = false;

            //const std::uintptr_t hookAddr = baseAddr + 0x75240;
            //const std::uintptr_t returnAddr = baseAddr + 0x7524E;
            //const std::uintptr_t escapeAddr = baseAddr + 0x753D0;

            const char* pattern = "48 8B 38 48 8B 48 08 4C 89 28 4C 89 68 08 48 89 7D ? 48 89 4D ? 48 8B 5D ? 48 85 DB";
            const std::uintptr_t hookAddr = FindAddressByPattern(a_skee, pattern);
            if (hookAddr)
            {
                log::info("Found NodeTransformKeys::Load Hook Address {:x}", hookAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                const std::uintptr_t returnAddr = hookAddr + 0xE;
                log::info("Found NodeTransformKeys::Load Return Address {:x}", returnAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                const char* escapePattern = "FF C6 3B 75 ? 0F 82 ? ? ? ? 40 0F B6 C7 48 8B 9C 24 ? ? ? ? 48 81 C4 C0 00 00 00 41 5F 41 5E 41 5D 41 5C 5F 5E 5D C3";
                const std::uintptr_t preEscapeAddr = FindAddressByPattern(a_skee, escapePattern);
                if (preEscapeAddr)
                {
                    const std::uintptr_t escapeAddr = preEscapeAddr + 0xF;
                    log::info("Found NodeTransformKeys::Load Escape Address {:x}", escapeAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                    struct Patch : Xbyak::CodeGenerator
                    {
                        Patch(std::uintptr_t retAddr, std::uintptr_t escAddr, std::uintptr_t funcAddr)
                        {
                            mov(rdi, ptr[rax]);
                            mov(rcx, ptr[rax + 8]);
                            mov(ptr[rax], r13);
                            mov(ptr[rax + 8], r13);

                            // check nullptr
                            test(rdi, rdi);
                            jz("IsNull");

                            push(rax);
                            mov(rax, retAddr);
                            xchg(qword[rsp], rax);
                            ret();

                            L("IsNull");

                            // backup
                            pushfq();
                            push(rax);
                            push(rcx);
                            push(rdx);
                            push(r8);
                            push(r9);
                            push(r10);
                            push(r11);

                            // call func
                            push(rbp);
                            mov(rbp, rsp);
                            and_(rsp, -16);
                            sub(rsp, 0x20);

                            mov(rax, funcAddr);
                            call(rax);

                            mov(rsp, rbp);
                            pop(rbp);

                            // revert
                            pop(r11);
                            pop(r10);
                            pop(r9);
                            pop(r8);
                            pop(rdx);
                            pop(rcx);
                            pop(rax);
                            popfq();

                            mov(al, 1);
                            push(r11);
                            mov(r11, escAddr);
                            xchg(qword[rsp], r11);
                            ret();
                        }
                    };

                    static Patch patch(returnAddr, escapeAddr, reinterpret_cast<std::uintptr_t>(NodeTransformKeys_Error));
                    patch.ready();
                    std::uint8_t jumpPayload[14] = {
                        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                    *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
                    DWORD oldProtect;
                    if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, PAGE_EXECUTE_READWRITE, &oldProtect))
                    {
                        memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 14);
                        VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, oldProtect, &oldProtect);
                        isSuccess = true;
                    }
                }
            }

            if (isSuccess)
                log::info("NodeTransformKeys::Load patch done");
            else
                log::error("Failed to NodeTransformKeys::Load patch");
        }

        // sub_18000FE90 / BodyMorphData::Load / morphName
        {
            bool isSuccess = false;

            //const std::uintptr_t hookAddr = baseAddr + 0xFF80;
            //const std::uintptr_t returnAddr = baseAddr + 0xFF90;
            //const std::uintptr_t escapeAddr = baseAddr + 0x104CB;

            const char* pattern = "90 44 89 64 24 ? BA 04 00 00 00 48 8D 4C 24 ? FF 53 50 85 C0 0F 84 ? ? ? ? C7 45 ? 00 00 00 00";
            const std::uintptr_t hookAddr = FindAddressByPattern(a_skee, pattern);
            if (hookAddr)
            {
                log::info("Found BodyMorphData::Load::morphName Hook Address {:x}", hookAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                const std::uintptr_t returnAddr = hookAddr + 0x10;
                log::info("Found BodyMorphData::Load::morphName Return Address {:x}", returnAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                const char* escapePattern = "B0 01 EB 02 32 C0 48 8B 8D ? ? ? ? 48 33 CC E8 ? ? ? ? 48 8B 9C 24 ? ? ? ? 48 81 C4 B0 02 00 00";
                const std::uintptr_t escapeAddr = FindAddressByPattern(a_skee, escapePattern);
                if (escapeAddr)
                {
                    log::info("Found BodyMorphData::Load::morphName Escape Address {:x}", escapeAddr - reinterpret_cast<std::uintptr_t>(a_skee));
                    struct Patch : Xbyak::CodeGenerator
                    {
                        Patch(std::uintptr_t retAddr, std::uintptr_t escAddr, std::uintptr_t funcAddr)
                        {
                            mov(dword[rsp + 0x24], r12d);
                            mov(edx, 4);
                            lea(rcx, ptr[rsp + 0x24]);
                            mov(rax, qword[rsp + 0x50]);

                            // check nullptr
                            test(rax, rax);
                            jz("IsNull");

                            push(r11);
                            mov(r11, retAddr);
                            xchg(qword[rsp], r11);
                            ret();

                            L("IsNull");

                            // backup
                            pushfq();
                            push(rax);
                            push(rcx);
                            push(rdx);
                            push(r8);
                            push(r9);
                            push(r10);
                            push(r11);

                            // call func
                            push(rbp);
                            mov(rbp, rsp);
                            and_(rsp, -16);
                            sub(rsp, 0x20);

                            mov(rax, funcAddr);
                            call(rax);

                            mov(rsp, rbp);
                            pop(rbp);

                            // revert
                            pop(r11);
                            pop(r10);
                            pop(r9);
                            pop(r8);
                            pop(rdx);
                            pop(rcx);
                            pop(rax);
                            popfq();

                            mov(al, 1);
                            push(r11);
                            mov(r11, escAddr);
                            xchg(qword[rsp], r11);
                            ret();
                        }
                    };

                    static Patch patch(returnAddr, escapeAddr, reinterpret_cast<std::uintptr_t>(BodyMorphData_morphName_Error));
                    patch.ready();
                    std::uint8_t jumpPayload[16] = {
                        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x90, 0x90};
                    *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
                    DWORD oldProtect;
                    if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 16, PAGE_EXECUTE_READWRITE, &oldProtect))
                    {
                        memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 16);
                        VirtualProtect(reinterpret_cast<void*>(hookAddr), 16, oldProtect, &oldProtect);
                        isSuccess = true;
                    }
                }
            }

            if (isSuccess)
                log::info("BodyMorphData::Load::morphName patch done");
            else
                log::error("Failed to BodyMorphData::Load::morphName patch");
        }

        // sub_18000FE90 / BodyMorphData::Load / keyName
        {
            bool isSuccess = false;

            //const std::uintptr_t hookAddr = baseAddr + 0x10020;
            //const std::uintptr_t returnAddr = baseAddr + 0x1002E;
            //const std::uintptr_t escapeAddr = baseAddr + 0x104CB;

            const char* pattern = "90 C7 44 24 ? 00 00 00 00 BA 04 00 00 00 48 8D 4C 24 ? FF 53 50 85 C0 0F 84 ? ? ? ? 48 8B 74 24 ? 48 8B D6 48 83 7E 18 10";
            const std::uintptr_t hookAddr = FindAddressByPattern(a_skee, pattern);
            if (hookAddr)
            {
                log::info("Found BodyMorphData::Load::keyName Hook Address {:x}", hookAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                const std::uintptr_t returnAddr = hookAddr + 0xE;
                log::info("Found BodyMorphData::Load::keyName Return Address {:x}", returnAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                const char* escapePattern = "B0 01 EB 02 32 C0 48 8B 8D ? ? ? ? 48 33 CC E8 ? ? ? ? 48 8B 9C 24 ? ? ? ? 48 81 C4 B0 02 00 00";
                const std::uintptr_t escapeAddr = FindAddressByPattern(a_skee, escapePattern);
                if (escapeAddr)
                {
                    log::info("Found BodyMorphData::Load::keyName Escape Address {:x}", escapeAddr - reinterpret_cast<std::uintptr_t>(a_skee));
                    struct Patch : Xbyak::CodeGenerator
                    {
                        Patch(std::uintptr_t retAddr, std::uintptr_t escAddr, std::uintptr_t funcAddr)
                        {
                            mov(dword[rsp + 0x30], 0);
                            mov(edx, 4);
                            mov(rax, qword[rsp + 0x40]);

                            // check nullptr
                            test(rax, rax);
                            jz("IsNull");

                            push(r11);
                            mov(r11, retAddr);
                            xchg(qword[rsp], r11);
                            ret();

                            L("IsNull");

                            // backup
                            pushfq();
                            push(rax);
                            push(rcx);
                            push(rdx);
                            push(r8);
                            push(r9);
                            push(r10);
                            push(r11);

                            // call func
                            push(rbp);
                            mov(rbp, rsp);
                            and_(rsp, -16);
                            sub(rsp, 0x20);

                            mov(rax, funcAddr);
                            call(rax);

                            mov(rsp, rbp);
                            pop(rbp);

                            // revert
                            pop(r11);
                            pop(r10);
                            pop(r9);
                            pop(r8);
                            pop(rdx);
                            pop(rcx);
                            pop(rax);
                            popfq();

                            mov(al, 1);
                            push(r11);
                            mov(r11, escAddr);
                            xchg(qword[rsp], r11);
                            ret();
                        }
                    };

                    static Patch patch(returnAddr, escapeAddr, reinterpret_cast<std::uintptr_t>(BodyMorphData_keyName_Error));
                    patch.ready();
                    std::uint8_t jumpPayload[14] = {
                        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                    *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
                    DWORD oldProtect;
                    if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, PAGE_EXECUTE_READWRITE, &oldProtect))
                    {
                        memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 14);
                        VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, oldProtect, &oldProtect);
                        isSuccess = true;
                    }
                }
            }

            if (isSuccess)
                log::info("BodyMorphData::Load::keyName patch done");
            else
                log::error("Failed to BodyMorphData::Load::keyName patch");
        }
    }

    void AE_RefInfo(HMODULE a_skee)
    {
        // sub_1800C4100 / NodeTransformRegistrationMapHolder::Load::Internal
        {
            bool isSuccess = false;

            //const std::uintptr_t hookAddr = baseAddr + 0xC4168;
            //const std::uintptr_t returnAddr = baseAddr + 0xC417B;

            //const std::uintptr_t target1Addr = baseAddr + 0xB0AD0;
            //const std::uintptr_t target2Addr = baseAddr + 0xC4500;

            const char* pattern = "48 8D 05 ? ? ? ? 48 89 44 24 ? 4C 8D 0D ? ? ? ? BA 80 00 00 00 44 8D 42 82 48 8D 4C 24 ? E8 ? ? ? ? 90 4C 8B CB";
            const std::uintptr_t hookAddr = FindAddressByPattern(a_skee, pattern);
            if (hookAddr)
            {
                log::info("Found NodeTransformRegistrationMapHolder::Load::morphName Hook Address {:x}", hookAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                const std::uintptr_t returnAddr = hookAddr + 0x13;
                log::info("Found NodeTransformRegistrationMapHolder::Load Return Address {:x}", returnAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                const std::int32_t offset1 = *reinterpret_cast<std::int32_t*>(hookAddr + 0x3);
                const std::uintptr_t target1Addr = (hookAddr + 0x7) + offset1;
                log::info("Found NodeTransformRegistrationMapHolder::Load::morphName Target1 Address {:x}", target1Addr - reinterpret_cast<std::uintptr_t>(a_skee));

                const std::uintptr_t lea2Addr = hookAddr + 0xC;
                const std::int32_t offset2 = *reinterpret_cast<int32_t*>(lea2Addr + 0x3);
                const std::uintptr_t target2Addr = (lea2Addr + 0x7) + offset2;
                log::info("Found NodeTransformRegistrationMapHolder::Load::morphName Target2 Address {:x}", target2Addr - reinterpret_cast<std::uintptr_t>(a_skee));

                struct Patch : Xbyak::CodeGenerator
                {
                    Patch(std::uintptr_t retAddr, std::uintptr_t funcAddr, std::uintptr_t tar1Addr, std::uintptr_t tar2Addr)
                    {
                        // backup
                        pushfq();
                        push(rax);
                        push(rcx);
                        push(rdx);
                        push(r8);
                        push(r9);
                        push(r10);
                        push(r11);

                        mov(rcx, qword[rsp + 0x80]);

                        push(rbp);
                        mov(rbp, rsp);
                        and_(rsp, -16);
                        sub(rsp, 0x20);

                        // get ref handle
                        mov(rax, funcAddr);
                        call(rax);

                        mov(rsp, rbp);
                        pop(rbp);

                        // revert
                        pop(r11);
                        pop(r10);
                        pop(r9);
                        pop(r8);
                        pop(rdx);
                        pop(rcx);
                        pop(rax);
                        popfq();

                        mov(rax, tar1Addr);
                        mov(qword[rsp + 0x20], rax);
                        mov(r9, tar2Addr);

                        push(r11);
                        mov(r11, retAddr);
                        xchg(qword[rsp], r11);
                        ret();
                    }
                };

                static Patch patch(returnAddr, reinterpret_cast<std::uintptr_t>(GetHandle), target1Addr, target2Addr);
                patch.ready();
                std::uint8_t jumpPayload[19] = {
                    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x90, 0x90, 0x90, 0x90, 0x90};
                *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
                DWORD oldProtect;
                if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 19, PAGE_EXECUTE_READWRITE, &oldProtect))
                {
                    memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 19);
                    VirtualProtect(reinterpret_cast<void*>(hookAddr), 19, oldProtect, &oldProtect);
                    isSuccess = true;
                }
            }

            if (isSuccess)
                log::info("NodeTransformRegistrationMapHolder::Load hook handle done");
            else
                log::error("Failed to NodeTransformRegistrationMapHolder::Load hook handle");
        }

        // sub_1800266E0 / ActorMorphs::Load
        {
            bool isSuccess = false;

            //const std::uintptr_t hookAddr = baseAddr + 0x26769;
            //const std::uintptr_t returnAddr = baseAddr + 0x26778;

            const char* pattern = "4C 89 6C 24 ? 4C 89 6C 24 ? B9 38 00 00 00 E8 ? ? ? ? 48 89 00 48 89 40 08 48 89 40 10 66 C7 40 18 01 01 48 89 44 24 ?";
            const std::uintptr_t hookAddr = FindAddressByPattern(a_skee, pattern);
            if (hookAddr)
            {
                log::info("Found ActorMorphs::Load::morphName Hook Address {:x}", hookAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                const std::uintptr_t returnAddr = hookAddr + 0xF;
                log::info("Found ActorMorphs::Load Return Address {:x}", returnAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                struct Patch : Xbyak::CodeGenerator
                {
                    Patch(std::uintptr_t retAddr, std::uintptr_t funcAddr)
                    {
                        // backup
                        pushfq();
                        push(rax);
                        push(rcx);
                        push(rdx);
                        push(r8);
                        push(r9);
                        push(r10);
                        push(r11);

                        cmp(r12d, 3);
                        jb("IsHandle");

                        mov(ecx, dword[rsp + 0x80]);
                        jmp("GetFormID");

                        L("IsHandle");
                        // use low 32bit
                        mov(ecx, dword[rsp + 0xB8]);

                        L("GetFormID");
                        // get formID
                        push(rbp);
                        mov(rbp, rsp);
                        and_(rsp, -16);
                        sub(rsp, 0x20);

                        mov(rax, funcAddr);
                        call(rax);

                        mov(rsp, rbp);
                        pop(rbp);

                        // revert
                        pop(r11);
                        pop(r10);
                        pop(r9);
                        pop(r8);
                        pop(rdx);
                        pop(rcx);
                        pop(rax);
                        popfq();

                        mov(qword[rsp + 0x48], r13);
                        mov(qword[rsp + 0x50], r13);
                        mov(ecx, 0x38);

                        push(rax);
                        mov(rax, retAddr);
                        xchg(qword[rsp], rax);
                        ret();
                    }
                };

                static Patch patch(returnAddr, reinterpret_cast<std::uintptr_t>(GetFormID));
                patch.ready();
                std::uint8_t jumpPayload[15] = {
                    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x90};
                *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
                DWORD oldProtect;
                if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 15, PAGE_EXECUTE_READWRITE, &oldProtect))
                {
                    memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 15);
                    VirtualProtect(reinterpret_cast<void*>(hookAddr), 15, oldProtect, &oldProtect);
                    isSuccess = true;
                }
            }

            if (isSuccess)
                log::info("ActorMorphs::Load hook formID done");
            else
                log::error("Failed to ActorMorphs::Load hook formID");
        }
    }

    void AE_Patch(HMODULE a_skee)
    {
        // sub_1800C3DD0 / NodeTransformKeys::Load
        {
            bool isSuccess = false;

            //const std::uintptr_t hookAddr = baseAddr + 0xC3E7E;
            //const std::uintptr_t returnAddr = baseAddr + 0xC3E8C;
            //const std::uintptr_t escapeAddr = baseAddr + 0xC401C;

            const char* pattern = "48 8B 38 48 8B 48 08 4C 89 28 4C 89 68 08 48 89 7D ? 48 89 4D ? 48 8B 5D ? 48 85 DB 74 ? B8 FF FF FF FF";
            const std::uintptr_t hookAddr = FindAddressByPattern(a_skee, pattern);
            if (hookAddr)
            {
                log::info("Found NodeTransformKeys::Load Hook Address {:x}", hookAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                const std::uintptr_t returnAddr = hookAddr + 0xE;
                log::info("Found NodeTransformKeys::Load Return Address {:x}", returnAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                const char* escapePattern = "FF C6 3B 75 ? 0F 82 ? ? ? ? 40 0F B6 C7 48 8B 9C 24 ? ? ? ? 48 81 C4 D0 00 00 00 41 5F 41 5E 41 5D 41 5C 5F 5E 5D C3";
                const std::uintptr_t preEscapeAddr = FindAddressByPattern(a_skee, escapePattern);
                if (preEscapeAddr)
                {
                    const std::uintptr_t escapeAddr = preEscapeAddr + 0xF;
                    log::info("Found NodeTransformKeys::Load Escape Address {:x}", escapeAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                    struct Patch : Xbyak::CodeGenerator
                    {
                        Patch(std::uintptr_t retAddr, std::uintptr_t escAddr, std::uintptr_t funcAddr)
                        {
                            mov(rdi, ptr[rax]);
                            mov(rcx, ptr[rax + 8]);
                            mov(ptr[rax], r13);
                            mov(ptr[rax + 8], r13);

                            // check nullptr
                            test(rdi, rdi);
                            jz("IsNull");

                            push(r11);
                            mov(r11, retAddr);
                            xchg(qword[rsp], r11);
                            ret();

                            L("IsNull");

                            // backup
                            pushfq();
                            push(rax);
                            push(rcx);
                            push(rdx);
                            push(r8);
                            push(r9);
                            push(r10);
                            push(r11);

                            // call func
                            push(rbp);
                            mov(rbp, rsp);
                            and_(rsp, -16);
                            sub(rsp, 0x20);

                            mov(rax, funcAddr);
                            call(rax);

                            mov(rsp, rbp);
                            pop(rbp);

                            // revert
                            pop(r11);
                            pop(r10);
                            pop(r9);
                            pop(r8);
                            pop(rdx);
                            pop(rcx);
                            pop(rax);
                            popfq();

                            mov(al, 1);
                            push(r11);
                            mov(r11, escAddr);
                            xchg(qword[rsp], r11);
                            ret();
                        }
                    };

                    static Patch patch(returnAddr, escapeAddr, reinterpret_cast<std::uintptr_t>(NodeTransformKeys_Error));
                    patch.ready();
                    std::uint8_t jumpPayload[14] = {
                        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                    *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
                    DWORD oldProtect;
                    if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, PAGE_EXECUTE_READWRITE, &oldProtect))
                    {
                        memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 14);
                        VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, oldProtect, &oldProtect);
                        isSuccess = true;
                    }
                }
            }

            if (isSuccess)
                log::info("NodeTransformKeys::Load patch done");
            else
                log::error("Failed to NodeTransformKeys::Load patch");
        }

        // sub_180025D20 / BodyMorphData::Load morphName
        {
            bool isSuccess = false;

            //const std::uintptr_t hookAddr = baseAddr + 0x25F81;
            //const std::uintptr_t returnAddr = baseAddr + 0x25F8F;
            //const std::uintptr_t escapeAddr = baseAddr + 0x2666C;

            const char* pattern = "44 89 7C 24 ? 48 8B 43 50 BA 04 00 00 00 48 8D 4C 24 ? FF D0 85 C0 0F 84 ? ? ? ? C7 45 ? 00 00 00 00 4C 89 7D ? 4C 89 7D ? B9 28 00 00 00 E8 ? ? ? ?";
            const std::uintptr_t hookAddr = FindAddressByPattern(a_skee, pattern);
            if (hookAddr)
            {
                log::info("Found BodyMorphData::Load::morphName Hook Address {:x}", hookAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                const std::uintptr_t returnAddr = hookAddr + 0xE;
                log::info("Found BodyMorphData::Load::morphName Return Address {:x}", returnAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                const char* escapePattern = "B0 01 EB 02 32 C0 48 8B 8D ? ? ? ? 48 33 CC E8 ? ? ? ? 48 8B 9C 24 ? ? ? ? 48 81 C4 70 03 00 00 41 5F 41 5E 41 5D 41 5C 5F 5E 5D C3";
                const std::uintptr_t escapeAddr = FindAddressByPattern(a_skee, escapePattern);
                if (escapeAddr)
                {
                    log::info("Found BodyMorphData::Load::morphName Escape Address {:x}", escapeAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                    struct Patch : Xbyak::CodeGenerator
                    {
                        Patch(std::uintptr_t retAddr, std::uintptr_t escAddr, std::uintptr_t funcAddr)
                        {
                            mov(dword[rsp + 0x28], r15d);
                            mov(rax, qword[rbx + 0x50]);
                            mov(edx, 4);
                            mov(rcx, qword[rsp + 0x78]);

                            // check nullptr
                            test(rcx, rcx);
                            jz("IsNull");

                            push(r11);
                            mov(r11, retAddr);
                            xchg(qword[rsp], r11);
                            ret();

                            L("IsNull");

                            // backup
                            pushfq();
                            push(rax);
                            push(rcx);
                            push(rdx);
                            push(r8);
                            push(r9);
                            push(r10);
                            push(r11);

                            // call func
                            push(rbp);
                            mov(rbp, rsp);
                            and_(rsp, -16);
                            sub(rsp, 0x20);

                            mov(rax, funcAddr);
                            call(rax);

                            mov(rsp, rbp);
                            pop(rbp);

                            // revert
                            pop(r11);
                            pop(r10);
                            pop(r9);
                            pop(r8);
                            pop(rdx);
                            pop(rcx);
                            pop(rax);
                            popfq();

                            mov(al, 1);
                            push(r11);
                            mov(r11, escAddr);
                            xchg(qword[rsp], r11);
                            ret();
                        }
                    };

                    static Patch patch(returnAddr, escapeAddr, reinterpret_cast<std::uintptr_t>(BodyMorphData_morphName_Error));
                    patch.ready();
                    std::uint8_t jumpPayload[14] = {
                        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                    *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
                    DWORD oldProtect;
                    if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, PAGE_EXECUTE_READWRITE, &oldProtect))
                    {
                        memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 14);
                        VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, oldProtect, &oldProtect);
                        isSuccess = true;
                    }
                }
            }

            if (isSuccess)
                log::info("BodyMorphData::Load::morphName patch done");
            else
                log::error("Failed to BodyMorphData::Load::morphName patch");
        }

        // sub_180025D20 / BodyMorphData::Load / keyName
        {
            bool isSuccess = false;

            //const std::uintptr_t hookAddr = baseAddr + 0x26021;
            //const std::uintptr_t returnAddr = baseAddr + 0x26032;
            //const std::uintptr_t escapeAddr = baseAddr + 0x2666C;

            const char* pattern = "C7 44 24 ? 00 00 00 00 48 8B 43 50 BA 04 00 00 00 48 8D 4C 24 ? FF D0 85 C0 0F 84 ? ? ? ? 4C 8B 74 24 ? 49 8B D6 49 8D 46 18 48 89 45 ?";
            const std::uintptr_t hookAddr = FindAddressByPattern(a_skee, pattern);
            if (hookAddr)
            {
                log::info("Found BodyMorphData::Load::keyName Hook Address {:x}", hookAddr - reinterpret_cast<std::uintptr_t>(a_skee));
                const std::uintptr_t returnAddr = hookAddr + 0x11;
                log::info("Found BodyMorphData::Load::keyName Return Address {:x}", returnAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                const char* escapePattern = "B0 01 EB 02 32 C0 48 8B 8D ? ? ? ? 48 33 CC E8 ? ? ? ? 48 8B 9C 24 ? ? ? ? 48 81 C4 70 03 00 00 41 5F 41 5E 41 5D 41 5C 5F 5E 5D C3";
                const std::uintptr_t escapeAddr = FindAddressByPattern(a_skee, escapePattern);
                if (escapeAddr)
                {
                    log::info("Found BodyMorphData::Load::keyName Escape Address {:x}", escapeAddr - reinterpret_cast<std::uintptr_t>(a_skee));

                    struct Patch : Xbyak::CodeGenerator
                    {
                        Patch(std::uintptr_t retAddr, std::uintptr_t escAddr, std::uintptr_t funcAddr)
                        {
                            mov(dword[rsp + 0x40], 0);
                            mov(rax, qword[rbx + 0x50]);
                            mov(edx, 4);
                            mov(rcx, qword[rsp + 0x50]);

                            // check nullptr
                            test(rcx, rcx);
                            jz("IsNull");

                            push(r11);
                            mov(r11, retAddr);
                            xchg(qword[rsp], r11);
                            ret();

                            L("IsNull");

                            // backup
                            pushfq();
                            push(rax);
                            push(rcx);
                            push(rdx);
                            push(r8);
                            push(r9);
                            push(r10);
                            push(r11);

                            // call func
                            push(rbp);
                            mov(rbp, rsp);
                            and_(rsp, -16);
                            sub(rsp, 0x20);

                            mov(rax, funcAddr);
                            call(rax);

                            mov(rsp, rbp);
                            pop(rbp);

                            // revert
                            pop(r11);
                            pop(r10);
                            pop(r9);
                            pop(r8);
                            pop(rdx);
                            pop(rcx);
                            pop(rax);
                            popfq();

                            mov(al, 1);
                            push(r11);
                            mov(r11, escAddr);
                            xchg(qword[rsp], r11);
                            ret();
                        }
                    };

                    static Patch patch(returnAddr, escapeAddr, reinterpret_cast<std::uintptr_t>(BodyMorphData_keyName_Error));
                    patch.ready();
                    std::uint8_t jumpPayload[17] = {
                        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x90, 0x90, 0x90};
                    *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
                    DWORD oldProtect;
                    if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 17, PAGE_EXECUTE_READWRITE, &oldProtect))
                    {
                        memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 17);
                        VirtualProtect(reinterpret_cast<void*>(hookAddr), 17, oldProtect, &oldProtect);
                        isSuccess = true;
                    }
                }
            }

            if (isSuccess)
                log::info("BodyMorphData::Load::keyName patch done");
            else
                log::error("Failed to BodyMorphData::Load::keyName patch");
        }
    }

    struct DLLVersion
    {
        std::uint32_t v0, v1, v2, v3;
        bool operator==(const DLLVersion& other) const
        {
            return v0 == other.v0 && v1 == other.v1 && v2 == other.v2 && v3 == other.v3;
        }
    };

    enum Version : std::uint8_t {
        noSupport,
        se1597_3_4_5_0,
        vr1415_3_4_5_0,
        ae161170_0_4_19_16
    };
    Version GetVersion()
    {
        LPDWORD handle = 0;
        DWORD datalen = GetFileVersionInfoSize(GetSKEEDLLName().c_str(), handle);
        if (datalen == 0)
            return Version::noSupport;
        std::vector<BYTE> data(datalen);
        DWORD handleinfo = 0;
        if (!GetFileVersionInfoW(GetSKEEDLLName().c_str(), handleinfo, datalen, data.data()))
            return Version::noSupport;
        std::uint32_t verlen = 0;
        VS_FIXEDFILEINFO* verinfo = nullptr;
        if (!VerQueryValue(data.data(), L"\\", (void**)&verinfo, &verlen))
            return Version::noSupport;
        std::uint32_t version0 = HIWORD(verinfo->dwFileVersionMS);
        std::uint32_t version1 = LOWORD(verinfo->dwFileVersionMS);
        std::uint32_t version2 = HIWORD(verinfo->dwFileVersionLS);
        std::uint32_t version3 = LOWORD(verinfo->dwFileVersionLS);
        DLLVersion dllVersion(version0, version1, version2, version3);
        if (REL::Module::IsVR())
        {
            if (dllVersion == DLLVersion(3, 4, 5, 0))
                return Version::vr1415_3_4_5_0;
        }
        else
        {
            if (REL::Module::IsSE())
            {
                if (dllVersion == DLLVersion(3, 4, 5, 0))
                    return Version::se1597_3_4_5_0;
            }
            else
            {
                if (dllVersion == DLLVersion(0, 4, 19, 16))
                    return Version::ae161170_0_4_19_16;
            }
        }
        return Version::noSupport;
    };

    void SKEEPatch() 
    {
        const auto skee = GetModuleHandle(GetSKEEDLLName().c_str());
        if (!skee)
        {
            log::info("SKEE does not loaded");
            return;
        }

        switch (GetVersion())
        {
        case Version::se1597_3_4_5_0: {
            SEVR_RefInfo(skee);
            SEVR_Patch(skee);
        }
        break;
        case Version::vr1415_3_4_5_0: {
            SEVR_RefInfo(skee);
            SEVR_Patch(skee);
        }
        break;
        case Version::ae161170_0_4_19_16: {
            AE_RefInfo(skee);
            AE_Patch(skee);
        }
        break;
        default: {
            log::error("No support version");
            return;
        }
        break;
        }
    }
}

SKSEPluginLoad(const LoadInterface* skse) 
{
    auto* plugin = PluginDeclaration::GetSingleton();
    Init(skse, true);
    const auto version = plugin->GetVersion();
    const auto runtime = REL::Module::get().version();
    log::info("{} {} is loading...", plugin->GetName(), version);
    log::info("Working on skyrim version : {}.{}.{}.{}", runtime.major(), runtime.minor(), runtime.patch(), runtime.build());

    if (!SKSE::GetMessagingInterface()->RegisterListener([](SKSE::MessagingInterface::Message* message) {
            switch (message->type)
            {
            case SKSE::MessagingInterface::kPostLoad:
                Mus::SKEEPatch();
                break;
            case SKSE::MessagingInterface::kPreLoadGame:
                Mus::InitError();
                break;
            case SKSE::MessagingInterface::kPostLoadGame:
                Mus::ErrorNotification();
                break;
            default:
                break;
            }
        }))
    {
        log::error("Unable to patch");
    }

    log::info("{} has finished loading.", plugin->GetName());
    return true;
}

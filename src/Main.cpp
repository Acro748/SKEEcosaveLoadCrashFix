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

    void SE1597_3_4_5_0_RefInfo(const std::uintptr_t baseAddr)
    {
        // sub_1800754A0 / NodeTransformRegistrationMapHolder::Load
        {
            const std::uintptr_t hookAddr = baseAddr + 0x75506;
            const std::uintptr_t returnAddr = baseAddr + 0x75519;

            const std::uintptr_t target1Addr = baseAddr + 0x56690;
            const std::uintptr_t target2Addr = baseAddr + 0x75750;

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
                0x90, 0x90, 0x90, 0x90, 0x90
            };
            *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
            DWORD oldProtect;
            if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 19, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 19);
                VirtualProtect(reinterpret_cast<void*>(hookAddr), 19, oldProtect, &oldProtect);
                log::info("NodeTransformRegistrationMapHolder::Load hook handle done");
            }
            else
                log::error("Failed to NodeTransformRegistrationMapHolder::Load hook handle");
        }

        // sub_180010590 / ActorMorphs::Load
        {
            const std::uintptr_t hookAddr = baseAddr + 0x10604;
            const std::uintptr_t returnAddr = baseAddr + 0x10613;

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
                0x90
            };
            *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
            DWORD oldProtect;
            if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 15, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 15);
                VirtualProtect(reinterpret_cast<void*>(hookAddr), 15, oldProtect, &oldProtect);
                log::info("ActorMorphs::Load hook formID done");
            }
            else
                log::error("Failed to ActorMorphs::Load hook formID");
        }
    }

    void SE1597_3_4_5_0_Patch(const std::uintptr_t baseAddr)
    {
        // sub_180075190 / NodeTransformKeys::Load
        {
            const std::uintptr_t hookAddr = baseAddr + 0x75240;
            const std::uintptr_t returnAddr = baseAddr + 0x7524E;
            const std::uintptr_t escapeAddr = baseAddr + 0x753D0;
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
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
            };
            *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
            DWORD oldProtect;
            if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 14);
                VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, oldProtect, &oldProtect);
                log::info("NodeTransformKeys::Load patch done");
            }
            else
                log::error("Failed to NodeTransformKeys::Load patch");
        }

        // sub_18000FE90 / BodyMorphData::Load / morphName
        {
            const std::uintptr_t hookAddr = baseAddr + 0xFF80;
            const std::uintptr_t returnAddr = baseAddr + 0xFF90;
            const std::uintptr_t escapeAddr = baseAddr + 0x104CB;
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
                0x90, 0x90
            };
            *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
            DWORD oldProtect;
            if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 16, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 16);
                VirtualProtect(reinterpret_cast<void*>(hookAddr), 16, oldProtect, &oldProtect);
                log::info("BodyMorphData::Load morphName patch done");
            }
            else
                log::error("Failed to BodyMorphData::Load morphName patch");
        }

        // sub_18000FE90 / BodyMorphData::Load / keyName
        {
            const std::uintptr_t hookAddr = baseAddr + 0x10020;
            const std::uintptr_t returnAddr = baseAddr + 0x1002E;
            const std::uintptr_t escapeAddr = baseAddr + 0x104CB;
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
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
            DWORD oldProtect;
            if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 14);
                VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, oldProtect, &oldProtect);
                log::info("BodyMorphData::Load keyName patch done");
            }
            else
                log::error("Failed to BodyMorphData::Load keyName patch");
        }
    }

    void VR1415_3_4_5_0_RefInfo(const std::uintptr_t baseAddr)
    {
        // sub_180072690 / NodeTransformRegistrationMapHolder::Load
        {
            const std::uintptr_t hookAddr = baseAddr + 0x726F6;
            const std::uintptr_t returnAddr = baseAddr + 0x72709;

            const std::uintptr_t target1Addr = baseAddr + 0x538E0;
            const std::uintptr_t target2Addr = baseAddr + 0x72940;

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
                log::info("NodeTransformRegistrationMapHolder::Load hook handle done");
            }
            else
                log::error("Failed to NodeTransformRegistrationMapHolder::Load hook handle");
        }

        // sub_18000F290 / ActorMorphs::Load
        {
            const std::uintptr_t hookAddr = baseAddr + 0xF304;
            const std::uintptr_t returnAddr = baseAddr + 0xF313;

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
                log::info("ActorMorphs::Load hook formID done");
            }
            else
                log::error("Failed to ActorMorphs::Load hook formID");
        }
    }

    void VR1415_3_4_5_0_Patch(const std::uintptr_t baseAddr)
    {
        // sub_180072380 / NodeTransformKeys::Load
        {
            const std::uintptr_t hookAddr = baseAddr + 0x72430;
            const std::uintptr_t returnAddr = baseAddr + 0x7243E;
            const std::uintptr_t escapeAddr = baseAddr + 0x725C5;
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
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
            };
            *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
            DWORD oldProtect;
            if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 14);
                VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, oldProtect, &oldProtect);
                log::info("NodeTransformKeys::Load patch done");
            }
            else
                log::error("Failed to NodeTransformKeys::Load patch");
        }

        // sub_18000EB90 / BodyMorphData::Load / morphName
        {
            const std::uintptr_t hookAddr = baseAddr + 0xEC80;
            const std::uintptr_t returnAddr = baseAddr + 0xEC90;
            const std::uintptr_t escapeAddr = baseAddr + 0xF1D0;
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
                0x90, 0x90
            };
            *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
            DWORD oldProtect;
            if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 16, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 16);
                VirtualProtect(reinterpret_cast<void*>(hookAddr), 16, oldProtect, &oldProtect);
                log::info("BodyMorphData::Load morphName patch done");
            }
            else
                log::error("Failed to BodyMorphData::Load morphName patch");
        }

        // sub_18000EB90 / BodyMorphData::Load / keyName
        {
            const std::uintptr_t hookAddr = baseAddr + 0xED20;
            const std::uintptr_t returnAddr = baseAddr + 0xED2E;
            const std::uintptr_t escapeAddr = baseAddr + 0xF1D0;
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
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
            DWORD oldProtect;
            if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 14);
                VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, oldProtect, &oldProtect);
                log::info("BodyMorphData::Load keyName patch done");
            }
            else
                log::error("Failed to BodyMorphData::Load keyName patch");
        }
    }

    void AE161170_0_4_19_16_RefInfo(const std::uintptr_t baseAddr)
    {
        // sub_1800C4100 / NodeTransformRegistrationMapHolder::Load::Internal
        {
            const std::uintptr_t hookAddr = baseAddr + 0xC4168;
            const std::uintptr_t returnAddr = baseAddr + 0xC417B;

            const std::uintptr_t target1Addr = baseAddr + 0xB0AD0;
            const std::uintptr_t target2Addr = baseAddr + 0xC4500;

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
                0x90, 0x90, 0x90, 0x90, 0x90
            };
            *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
            DWORD oldProtect;
            if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 19, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 19);
                VirtualProtect(reinterpret_cast<void*>(hookAddr), 19, oldProtect, &oldProtect);
                log::info("NodeTransformRegistrationMapHolder::Load hook handle done");
            }
            else
                log::error("Failed to NodeTransformRegistrationMapHolder::Load hook handle");
        }

        // sub_1800266E0 / ActorMorphs::Load
        {
            const std::uintptr_t hookAddr = baseAddr + 0x26769;
            const std::uintptr_t returnAddr = baseAddr + 0x26778;

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
                0x90
            };
            *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
            DWORD oldProtect;
            if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 15, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 15);
                VirtualProtect(reinterpret_cast<void*>(hookAddr), 15, oldProtect, &oldProtect);
                log::info("ActorMorphs::Load hook formID done");
            }
            else
                log::error("Failed to ActorMorphs::Load hook formID");
        }
    }

    void AE161170_0_4_19_16_Patch(const std::uintptr_t baseAddr)
    {
        // sub_1800C3DD0 / NodeTransformKeys::Load
        {
            const std::uintptr_t hookAddr = baseAddr + 0xC3E7E;
            const std::uintptr_t returnAddr = baseAddr + 0xC3E8C;
            const std::uintptr_t escapeAddr = baseAddr + 0xC401C;
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
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
            };
            *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
            DWORD oldProtect;
            if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 14);
                VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, oldProtect, &oldProtect);
                log::info("NodeTransformKeys::Load patch done");
            }
            else
                log::error("Failed to NodeTransformKeys::Load patch");
        }

        // sub_180025D20 / BodyMorphData::Load morphName
        {
            const std::uintptr_t hookAddr = baseAddr + 0x25F81;
            const std::uintptr_t returnAddr = baseAddr + 0x25F8F;
            const std::uintptr_t escapeAddr = baseAddr + 0x2666C;
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
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
            DWORD oldProtect;
            if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 14);
                VirtualProtect(reinterpret_cast<void*>(hookAddr), 14, oldProtect, &oldProtect);
                log::info("BodyMorphData::Load morphName patch done");
            }
            else
                log::error("Failed to BodyMorphData::Load morphName patch");
        }

        // sub_180025D20 / BodyMorphData::Load / keyName
        {
            const std::uintptr_t hookAddr = baseAddr + 0x26021;
            const std::uintptr_t returnAddr = baseAddr + 0x26032;
            const std::uintptr_t escapeAddr = baseAddr + 0x2666C;
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
                0x90, 0x90, 0x90
            };
            *reinterpret_cast<std::uintptr_t*>(&jumpPayload[6]) = reinterpret_cast<std::uintptr_t>(patch.getCode());
            DWORD oldProtect;
            if (VirtualProtect(reinterpret_cast<void*>(hookAddr), 17, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                memcpy(reinterpret_cast<void*>(hookAddr), jumpPayload, 17);
                VirtualProtect(reinterpret_cast<void*>(hookAddr), 17, oldProtect, &oldProtect);
                log::info("BodyMorphData::Load keyName patch done");
            }
            else
                log::error("Failed to BodyMorphData::Load keyName patch");
        }
    }

    struct DLLVersion
    {
        std::uint32_t v0, v1, v2, v3;
        bool operator==(const DLLVersion& other) const {
            return v0 == other.v0 && v1 == other.v1 && v2 == other.v2 && v3 == other.v3;
        }
    };

    enum Version : std::uint8_t {
        noSupport,
        se1597_3_4_5_0,
        vr1415_3_4_5_0,
        ae161170_0_4_19_16
    };
    Version GetVersion() {
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
        const auto version = GetVersion();
        const auto skee = GetModuleHandle(GetSKEEDLLName().c_str());
        if (!skee)
        {
            log::info("SKEE does not loaded");
            return;
        }
        const auto baseAddr = reinterpret_cast<std::uintptr_t>(skee);
        switch (version)
        {
        case Version::se1597_3_4_5_0: {
            SE1597_3_4_5_0_RefInfo(baseAddr);
            SE1597_3_4_5_0_Patch(baseAddr);
        } break;
        case Version::vr1415_3_4_5_0: {
            VR1415_3_4_5_0_RefInfo(baseAddr);
            VR1415_3_4_5_0_Patch(baseAddr);
        } break;
        case Version::ae161170_0_4_19_16: {
            AE161170_0_4_19_16_RefInfo(baseAddr);
            AE161170_0_4_19_16_Patch(baseAddr);
        } break;
        default: {
            log::error("No support version");
            return;
        } break;
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

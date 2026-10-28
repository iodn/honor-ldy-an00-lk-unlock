// Inactive-B activation client for android.hardware.boot.IBootControl/default.
//
// Modes:
//   read                          - getters only.
//   activate                      - precondition reads; prints DRY_RUN_OK and
//                                   does NOT call setActiveBootSlot.
//   activate --execute --confirm-inactive-b
//                                 - calls setActiveBootSlot(1). This mutates
//                                   misc+0x800 and the UFS boot-LUN. Do not run
//                                   without a reviewed executor and explicit
//                                   authorization.
//
// The client must run in the shell/UID 2000 domain: the su broker's kernel
// domain cannot see this service through servicemanager.

#include <android/binder_auto_utils.h>
#include <android/binder_ibinder.h>
#include <aidl/android/hardware/boot/IBootControl.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <string>
#include <unistd.h>

namespace boot = aidl::android::hardware::boot;

namespace {

constexpr const char* kService = "android.hardware.boot.IBootControl/default";
constexpr int32_t kExpectedVersion = 1;
constexpr const char* kExpectedHash =
    "2400346954240a5de495a1debc81429dd012d7b7";
constexpr const char* kMarkerPath = "/data/local/tmp/.iboot_setter_done";

using GetServiceFn = AIBinder* (*)(const char*);

bool check(const char* what, const ndk::ScopedAStatus& st, bool& ok) {
    if (!st.isOk()) {
        ok = false;
        std::printf("%s: FAIL status=%d message=%s\n", what,
                    static_cast<int>(st.getStatus()), st.getMessage());
        return false;
    }
    return true;
}

bool write_setter_marker(const std::string& nonce, const char* outcome,
                         int status, int exception, int service_error) {
    FILE* file = std::fopen(kMarkerPath, "w");
    if (file == nullptr) {
        return false;
    }
    std::fprintf(file,
                 "nonce=%s\noutcome=%s\nstatus=%d\nexception=%d\n"
                 "service_error=%d\n",
                 nonce.c_str(), outcome, status, exception, service_error);
    std::fflush(file);
    ::fsync(fileno(file));
    std::fclose(file);
    return true;
}

struct State {
    int32_t active = -1;
    int32_t current = -1;
    int32_t slots = -1;
    boot::MergeStatus merge = boot::MergeStatus::NONE;
    std::string suffixA;
    std::string suffixB;
    bool bootableA = false;
    bool successfulA = false;
    bool bootableB = false;
    bool successfulB = false;
    bool ok = true;
};

bool read_state(const std::shared_ptr<boot::IBootControl>& service, State* s) {
    s->ok = true;
    check("getActiveBootSlot", service->getActiveBootSlot(&s->active), s->ok);
    check("getCurrentSlot", service->getCurrentSlot(&s->current), s->ok);
    check("getNumberSlots", service->getNumberSlots(&s->slots), s->ok);
    check("getSnapshotMergeStatus", service->getSnapshotMergeStatus(&s->merge), s->ok);
    check("getSuffix(0)", service->getSuffix(0, &s->suffixA), s->ok);
    check("getSuffix(1)", service->getSuffix(1, &s->suffixB), s->ok);
    check("isSlotBootable(0)", service->isSlotBootable(0, &s->bootableA), s->ok);
    check("isSlotMarkedSuccessful(0)",
          service->isSlotMarkedSuccessful(0, &s->successfulA), s->ok);
    check("isSlotBootable(1)", service->isSlotBootable(1, &s->bootableB), s->ok);
    check("isSlotMarkedSuccessful(1)",
          service->isSlotMarkedSuccessful(1, &s->successfulB), s->ok);
    return s->ok;
}

void print_state(const State& s) {
    std::printf("active=%d current=%d slots=%d merge=%d\n", s.active, s.current,
                s.slots, static_cast<int>(s.merge));
    std::printf("A suffix=%s bootable=%d successful=%d\n", s.suffixA.c_str(),
                s.bootableA ? 1 : 0, s.successfulA ? 1 : 0);
    std::printf("B suffix=%s bootable=%d successful=%d\n", s.suffixB.c_str(),
                s.bootableB ? 1 : 0, s.successfulB ? 1 : 0);
}

bool preconditions(const State& s, int target) {
    bool ok = true;
    if (!s.ok) {
        std::printf("precondition: read_state failed\n");
        ok = false;
    }
    if (s.slots != 2) {
        std::printf("precondition: expected 2 slots, got %d\n", s.slots);
        ok = false;
    }
    if (target == 1) {
        if (s.current != 0 || s.active != 0) {
            std::printf("precondition: forward activation expects current=0 active=0, "
                        "got current=%d active=%d\n", s.current, s.active);
            ok = false;
        }
        if (s.successfulB) {
            std::printf("precondition: B is already marked successful; "
                        "setActive alone would not arm the retry mechanism\n");
            ok = false;
        }
        if (!s.bootableB) {
            std::printf("precondition: B must be bootable\n");
            ok = false;
        }
    } else if (target == 0) {
        if (s.current != 0) {
            std::printf("precondition: rollback expects current=0 (A running), "
                        "got current=%d\n", s.current);
            ok = false;
        }
        if (s.active != 0 && s.active != 1) {
            std::printf("precondition: rollback expects active 0 or 1, got %d\n",
                        s.active);
            ok = false;
        }
    } else {
        std::printf("precondition: invalid target %d\n", target);
        ok = false;
    }
    if (!s.bootableA || !s.successfulA) {
        std::printf("precondition: A must be bootable and marked successful\n");
        ok = false;
    }
    if (s.suffixA != "_a" || s.suffixB != "_b") {
        std::printf("precondition: unexpected suffixes A=%s B=%s\n",
                    s.suffixA.c_str(), s.suffixB.c_str());
        ok = false;
    }
    return ok;
}

}  // namespace

int main(int argc, char** argv) {
    bool activate = false;
    bool execute = false;
    bool confirm_inactive_b = false;
    bool confirm_rollback = false;
    int target = 1;
    std::string nonce;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "read") == 0) {
            activate = false;
        } else if (std::strcmp(argv[i], "activate") == 0) {
            activate = true;
        } else if (std::strcmp(argv[i], "--execute") == 0) {
            execute = true;
        } else if (std::strcmp(argv[i], "--confirm-inactive-b") == 0) {
            confirm_inactive_b = true;
        } else if (std::strcmp(argv[i], "--confirm-rollback") == 0) {
            confirm_rollback = true;
        } else if (std::strcmp(argv[i], "--slot") == 0) {
            if (i + 1 >= argc) {
                std::printf("usage: %s [read | activate [--slot 0|1] "
                            "[--nonce HEX] [--execute "
                            "--confirm-inactive-b|--confirm-rollback]]\n",
                            argv[0]);
                return 2;
            }
            target = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--nonce") == 0) {
            if (i + 1 >= argc) {
                std::printf("usage: %s [read | activate [--slot 0|1] "
                            "[--nonce HEX] [--execute "
                            "--confirm-inactive-b|--confirm-rollback]]\n",
                            argv[0]);
                return 2;
            }
            nonce = argv[++i];
        } else {
            std::printf("usage: %s [read | activate [--slot 0|1] "
                        "[--nonce HEX] [--execute "
                        "--confirm-inactive-b|--confirm-rollback]]\n",
                        argv[0]);
            return 2;
        }
    }
    if (target != 0 && target != 1) {
        std::printf("invalid --slot %d (expected 0 or 1)\n", target);
        return 2;
    }
    if (execute && nonce.empty()) {
        std::printf("REFUSED: --execute requires --nonce\n");
        return 3;
    }

    void* lib = dlopen("libbinder_ndk.so", RTLD_NOW);
    if (lib == nullptr) {
        std::printf("FAIL dlopen libbinder_ndk.so: %s\n", dlerror());
        return 1;
    }
    auto get_service =
        reinterpret_cast<GetServiceFn>(dlsym(lib, "AServiceManager_getService"));
    if (get_service == nullptr) {
        std::printf("FAIL dlsym AServiceManager_getService\n");
        return 1;
    }

    AIBinder* raw = get_service(kService);
    if (raw == nullptr) {
        std::printf("FAIL service not found: %s (run as shell, not via su broker)\n",
                    kService);
        return 1;
    }
    auto service = boot::IBootControl::fromBinder(ndk::SpAIBinder(raw));
    if (!service) {
        std::printf("FAIL fromBinder returned null\n");
        return 1;
    }

    int32_t version = -1;
    std::string iface_hash;
    auto vst = service->getInterfaceVersion(&version);
    auto hst = service->getInterfaceHash(&iface_hash);
    bool iface_ok = vst.isOk() && hst.isOk() && version == kExpectedVersion &&
                    iface_hash == kExpectedHash;
    if (vst.isOk()) {
        std::printf("interface_version=%d\n", version);
    } else {
        std::printf("getInterfaceVersion: FAIL status=%d message=%s\n",
                    static_cast<int>(vst.getStatus()), vst.getMessage());
    }
    if (hst.isOk()) {
        std::printf("interface_hash=%s\n", iface_hash.c_str());
    } else {
        std::printf("getInterfaceHash: FAIL status=%d message=%s\n",
                    static_cast<int>(hst.getStatus()), hst.getMessage());
    }
    if (!iface_ok) {
        std::printf("interface version/hash mismatch: expected version=%d hash=%s\n",
                    kExpectedVersion, kExpectedHash);
    }

    State state;
    if (!read_state(service, &state)) {
        print_state(state);
        std::printf("READ_FAIL\n");
        return 1;
    }
    print_state(state);

    if (!activate) {
        std::printf("%s\n", state.ok ? "READ_ONLY_OK" : "READ_ONLY_FAIL");
        return state.ok ? 0 : 1;
    }

    if (!iface_ok) {
        std::printf("DRY_RUN_REFUSED interface version/hash mismatch\n");
        return 3;
    }

    if (!preconditions(state, target)) {
        std::printf("DRY_RUN_REFUSED\n");
        return 3;
    }

    if (!execute) {
        std::printf("DRY_RUN_OK would_call=setActiveBootSlot(%d) "
                    "(no mutation performed)\n", target);
        return 0;
    }

    bool confirmed = (target == 1) ? confirm_inactive_b : confirm_rollback;
    if (!confirmed) {
        std::printf("REFUSED: target %d requires %s\n", target,
                    target == 1 ? "--confirm-inactive-b" : "--confirm-rollback");
        return 3;
    }

    auto st = service->setActiveBootSlot(target);
    const bool setter_ok = st.isOk();
    const int setter_status = static_cast<int>(st.getStatus());
    const int setter_exception = static_cast<int>(st.getExceptionCode());
    const int service_error = st.getServiceSpecificError();
    const char* outcome = setter_ok ? "OK"
        : (st.getExceptionCode() == EX_SERVICE_SPECIFIC ? "SERVICE_ERROR"
                                                        : "UNKNOWN");
    if (!write_setter_marker(nonce, outcome, setter_status, setter_exception,
                             service_error)) {
        std::printf("WARN setter marker write failed\n");
    }
    if (!setter_ok) {
        std::printf("ACTIVATE_FAIL target=%d status=%d exception=%d "
                    "service_error=%d outcome=%s message=%s\n",
                    target, setter_status, setter_exception, service_error,
                    outcome, st.getMessage());
        return 1;
    }
    std::printf("ACTIVATE_OK target=%d\n", target);

    State after;
    if (!read_state(service, &after)) {
        print_state(after);
        std::printf("POST_READ_FAIL\n");
        return 1;
    }
    print_state(after);
    return 0;
}

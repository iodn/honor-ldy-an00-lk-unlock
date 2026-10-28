// Read-only client for android.hardware.boot.IBootControl/default.
//
// Calls getters only. It does NOT call setActiveBootSlot, setSlotAsUnbootable,
// markBootSuccessful, or setSnapshotMergeStatus. No partition is written.
//
// Built with the NDK against the AIDL-generated IBootControl interface.

#include <android/binder_auto_utils.h>
#include <android/binder_ibinder.h>
#include <aidl/android/hardware/boot/IBootControl.h>

#include <cstdint>
#include <cstdio>
#include <dlfcn.h>
#include <string>

namespace boot = aidl::android::hardware::boot;

namespace {

constexpr const char* kService = "android.hardware.boot.IBootControl/default";

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

}  // namespace

int main() {
    void* lib = dlopen("libbinder_ndk.so", RTLD_NOW);
    if (lib == nullptr) {
        std::printf("READONLY_FAIL dlopen libbinder_ndk.so: %s\n", dlerror());
        return 1;
    }
    auto get_service =
        reinterpret_cast<GetServiceFn>(dlsym(lib, "AServiceManager_getService"));
    if (get_service == nullptr) {
        std::printf("READONLY_FAIL dlsym AServiceManager_getService\n");
        return 1;
    }

    AIBinder* raw = get_service(kService);
    if (raw == nullptr) {
        std::printf("READONLY_FAIL service not found: %s\n", kService);
        return 1;
    }
    ndk::SpAIBinder binder(raw);
    auto service = boot::IBootControl::fromBinder(binder);
    if (!service) {
        std::printf("READONLY_FAIL fromBinder returned null\n");
        return 1;
    }

    bool ok = true;
    int32_t version = -1;
    std::string iface_hash;
    if (check("getInterfaceVersion", service->getInterfaceVersion(&version), ok)) {
        std::printf("interface_version=%d\n", version);
    }
    if (check("getInterfaceHash", service->getInterfaceHash(&iface_hash), ok)) {
        std::printf("interface_hash=%s\n", iface_hash.c_str());
    }
    int32_t active = -1;
    int32_t current = -1;
    int32_t slots = -1;
    boot::MergeStatus merge = boot::MergeStatus::NONE;

    if (check("getActiveBootSlot", service->getActiveBootSlot(&active), ok)) {
        std::printf("getActiveBootSlot=%d\n", active);
    }
    if (check("getCurrentSlot", service->getCurrentSlot(&current), ok)) {
        std::printf("getCurrentSlot=%d\n", current);
    }
    if (check("getNumberSlots", service->getNumberSlots(&slots), ok)) {
        std::printf("getNumberSlots=%d\n", slots);
    }
    if (check("getSnapshotMergeStatus", service->getSnapshotMergeStatus(&merge), ok)) {
        std::printf("getSnapshotMergeStatus=%d\n", static_cast<int>(merge));
    }

    if (slots >= 0 && slots <= 8) {
        for (int32_t slot = 0; slot < slots; ++slot) {
            std::string suffix;
            bool bootable = false;
            bool successful = false;
            if (check("getSuffix", service->getSuffix(slot, &suffix), ok)) {
                std::printf("getSuffix(%d)=%s\n", slot, suffix.c_str());
            }
            if (check("isSlotBootable", service->isSlotBootable(slot, &bootable), ok)) {
                std::printf("isSlotBootable(%d)=%d\n", slot, bootable ? 1 : 0);
            }
            if (check("isSlotMarkedSuccessful",
                      service->isSlotMarkedSuccessful(slot, &successful), ok)) {
                std::printf("isSlotMarkedSuccessful(%d)=%d\n", slot,
                            successful ? 1 : 0);
            }
        }
    } else {
        std::printf("slot count out of range; skipping per-slot reads\n");
        ok = false;
    }

    std::printf("%s\n", ok ? "READONLY_OK" : "READONLY_FAIL");
    return ok ? 0 : 1;
}

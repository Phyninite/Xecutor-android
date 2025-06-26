#include "roblox.hpp"
#include "../hook/hook.hpp"
#include "../memory/memory.hpp"
#include <android/log.h>

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "", __VA_ARGS__)
#define DEF_ADDR(name, offset) const uint64_t name = memory::getAbsoluteAddress("libroblox.so", offset)

namespace {
    const uint64_t script_start = 0x2AA1E8C;
    void* original_script_start = nullptr;
    void* original_wsj_step = nullptr;
    uint64_t script_start_address = 0;
    uint64_t wsj_step_address = 0;
    uint64_t current_script_context = 0;
    bool game_changed = false;
}

void hooked_script_start(uint64_t a1) {
    if (current_script_context == 0) {
        current_script_context = a1;
        LOGD("Initial script context: 0x%lx", current_script_context);
    } else if (current_script_context != a1) {
        current_script_context = a1;
        game_changed = true;
        LOGD("Game changed - new script context: 0x%lx", current_script_context);
    }
    
    auto original = reinterpret_cast<void(*)(uint64_t)>(original_script_start);
    if (original) {
        original(a1);
    }
}

void hooked_wsj_step() {
    LOGD("WSJ Step hooked - starting roblox hooks");
    setup_roblox_hooks();
    
    auto original = reinterpret_cast<void(*)()>(original_wsj_step);
    if (original) {
        original();
    }
}

void setup_roblox_hooks() {
    script_start_address = memory::getAbsoluteAddress("libroblox.so", script_start);
    
    if (script_start_address == 0) {
        LOGD("Failed to find script start address");
        return;
    }
    
    LOGD("Found script start at: 0x%lx", script_start_address);
    
    if (HOOK_MGR.hook(script_start_address, "virtual", reinterpret_cast<void*>(hooked_script_start), 0, 10)) {
        original_script_start = HOOK_MGR.get_original(script_start_address, 0);
        LOGD("Successfully hooked script start");
    } else {
        LOGD("Failed to hook script start");
    }
}

void roblox_mgr::start(uint64_t wsj_step_offset) {
    DEF_ADDR(wsj_step, wsj_step_offset);
    wsj_step_address = wsj_step;
    
    if (wsj_step_address == 0) {
        LOGD("Failed to find wsj_step address");
        return;
    }
    
    LOGD("Found wsj_step at: 0x%lx", wsj_step_address);
    
    if (HOOK_MGR.hook(wsj_step_address, "virtual", reinterpret_cast<void*>(hooked_wsj_step), 0, 10)) {
        original_wsj_step = HOOK_MGR.get_original(wsj_step_address, 0);
        LOGD("Successfully hooked wsj_step");
    } else {
        LOGD("Failed to hook wsj_step");
    }
}

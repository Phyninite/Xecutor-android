#include "hook.hpp"
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <algorithm>

bool hook_mgr::hook(uint64_t address, const std::string& type, void* replacement, 
                    uint64_t index, uint64_t vtable_size) {
    if (!replacement || !is_valid_ptr(reinterpret_cast<void*>(address))) {
        return false;
    }

    std::lock_guard<std::mutex> lock(hook_mutex);
    
    auto key = generate_key(address, index);
    if (active_hooks.find(key) != active_hooks.end()) {
        return false;
    }

    hook_info info = {};
    info.target_address = address;
    info.replacement_function = replacement;
    info.index = index;
    info.vtable_size = vtable_size;

    if (type == "vtable") {
        info.type = hook_type::vtable;
        if (!hook_vtable_internal(address, replacement, index, &info.original_function)) {
            return false;
        }
    } else if (type == "virtual") {
        info.type = hook_type::virtual_function;
        if (!hook_virtual_function_internal(address, replacement, index, vtable_size, &info.original_function)) {
            return false;
        }
    } else {
        return false;
    }

    active_hooks[key] = info;
    return true;
}

bool hook_mgr::unhook(uint64_t address, uint64_t index) {
    std::lock_guard<std::mutex> lock(hook_mutex);
    
    auto key = generate_key(address, index);
    auto it = active_hooks.find(key);
    if (it == active_hooks.end()) {
        return false;
    }

    const auto& info = it->second;
    
    if (info.type == hook_type::vtable) {
        auto vtable_ptr = reinterpret_cast<void***>(address);
        auto vtable = *vtable_ptr;
        
        if (!is_valid_ptr(vtable)) {
            return false;
        }

        auto patch_address = reinterpret_cast<uint64_t>(&vtable[index]);
        if (make_writable(patch_address)) {
            vtable[index] = info.original_function;
            restore_protection(patch_address);
        }
    }

    active_hooks.erase(it);
    return true;
}

void* hook_mgr::get_original(uint64_t address, uint64_t index) {
    std::lock_guard<std::mutex> lock(hook_mutex);
    
    auto key = generate_key(address, index);
    auto it = active_hooks.find(key);
    return (it != active_hooks.end()) ? it->second.original_function : nullptr;
}

void hook_mgr::cleanup_all() {
    std::lock_guard<std::mutex> lock(hook_mutex);
    
    for (auto* vtable : allocated_vtables) {
        free(vtable);
    }
    allocated_vtables.clear();
    active_hooks.clear();
}

bool hook_mgr::hook_vtable_internal(uint64_t address, void* replacement, uint64_t index, void** original) {
    auto vtable_ptr = reinterpret_cast<void***>(address);
    auto vtable = *vtable_ptr;
    
    if (!is_valid_ptr(vtable)) {
        return false;
    }

    *original = vtable[index];
    auto patch_address = reinterpret_cast<uint64_t>(&vtable[index]);

    if (!make_writable(patch_address)) {
        return false;
    }

    vtable[index] = replacement;
    return restore_protection(patch_address);
}

bool hook_mgr::hook_virtual_function_internal(uint64_t address, void* replacement, 
                                            uint64_t index, uint64_t vtable_size, void** original) {
    auto current_vtable = *reinterpret_cast<void***>(address);
    if (!is_valid_ptr(current_vtable) || index >= vtable_size) {
        return false;
    }

    auto new_vtable = static_cast<void**>(aligned_alloc(sizeof(void*), vtable_size * sizeof(void*)));
    if (!new_vtable) {
        return false;
    }

    std::memcpy(new_vtable, current_vtable, vtable_size * sizeof(void*));
    allocated_vtables.push_back(new_vtable);

    *original = new_vtable[index];
    new_vtable[index] = replacement;

    if (!make_writable(address)) {
        return false;
    }

    *reinterpret_cast<void***>(address) = new_vtable;
    restore_protection(address);
    return true;
}

bool hook_mgr::make_writable(uint64_t address) {
    const auto page_size = sysconf(_SC_PAGESIZE);
    const auto page_mask = ~(page_size - 1);
    const auto page_start = address & page_mask;
    
    return mprotect(reinterpret_cast<void*>(page_start), page_size, 
                   PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

bool hook_mgr::restore_protection(uint64_t address) {
    const auto page_size = sysconf(_SC_PAGESIZE);
    const auto page_mask = ~(page_size - 1);
    const auto page_start = address & page_mask;
    
    return mprotect(reinterpret_cast<void*>(page_start), page_size, 
                   PROT_READ | PROT_EXEC) == 0;
}

bool hook_mgr::is_valid_ptr(void* ptr) {
    return ptr != nullptr && reinterpret_cast<uintptr_t>(ptr) > 0x1000;
}

uint64_t hook_mgr::generate_key(uint64_t address, uint64_t index) {
    return address ^ (index << 32);
}

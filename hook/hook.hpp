#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <mutex>
#include <unordered_map>

enum class hook_type {
    vtable,
    virtual_function
};

struct hook_info {
    uint64_t target_address;
    void* original_function;
    void* replacement_function;
    hook_type type;
    uint64_t index;
    uint64_t vtable_size;
};

class hook_mgr {
public:
    static auto& instance() {
        static hook_mgr mgr;
        return mgr;
    }

    bool hook(uint64_t address, const std::string& type, void* replacement, 
              uint64_t index = 0, uint64_t vtable_size = 0);
    
    bool unhook(uint64_t address, uint64_t index = 0);
    
    void* get_original(uint64_t address, uint64_t index = 0);
    
    void cleanup_all();

private:
    hook_mgr() = default;
    ~hook_mgr() { cleanup_all(); }
    
    hook_mgr(const hook_mgr&) = delete;
    hook_mgr& operator=(const hook_mgr&) = delete;
    
    std::vector<void**> allocated_vtables;
    std::unordered_map<uint64_t, hook_info> active_hooks;
    std::mutex hook_mutex;
    
    bool hook_vtable_internal(uint64_t address, void* replacement, uint64_t index, void** original);
    bool hook_virtual_function_internal(uint64_t address, void* replacement, 
                                      uint64_t index, uint64_t vtable_size, void** original);
    bool make_writable(uint64_t address);
    bool restore_protection(uint64_t address);
    bool is_valid_ptr(void* ptr);
    uint64_t generate_key(uint64_t address, uint64_t index);
};

#define HOOK_MGR hook_mgr::instance()

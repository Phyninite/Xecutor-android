#include "hook.hpp"

__attribute__((constructor))
void lib_constructor() {
    
}

__attribute__((destructor)) 
void lib_destructor() {
    HOOK_MGR.cleanup_all();
}

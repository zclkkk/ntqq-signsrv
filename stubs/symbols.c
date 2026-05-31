// wrapper.node requires this symbol from the QQ main executable.
// We provide an empty stub so dlopen succeeds. The sign function
// at the extracted offset does not call this symbol.
void qq_magic_napi_register() {}

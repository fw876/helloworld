__attribute__((weak)) void __dummy(void *x) { }
void f(void *x) { __dummy(x); }
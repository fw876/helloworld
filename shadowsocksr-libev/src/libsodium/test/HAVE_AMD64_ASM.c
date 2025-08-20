#if defined(__amd64) || defined(__amd64__) || defined(__x86_64__)
# if defined(__CYGWIN__) || defined(__MINGW32__) || defined(__MINGW64__) || defined(_WIN32) || defined(_WIN64)
# error Windows x86_64 calling conventions are not supported yet
# endif
/* neat */
#else
# error !x86_64
#endif
void main() {
	__asm__("pxor %xmm12,%xmm6");
}
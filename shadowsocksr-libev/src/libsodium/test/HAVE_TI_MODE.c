#ifndef __GNUC__
# error mode(TI) is a gcc extension
#endif
#if defined(__clang__) && !defined(__x86_64__)
# error clang doesn't properly compile smult_curve25519_donna_c64.c
#endif
#ifndef NATIVE_LITTLE_ENDIAN
# error donna_c64 currently requires a little endian CPU
#endif
#ifdef EMSCRIPTEN
# error emscripten currently supports only shift operations on integers \
# larger than 64 bits
#endif
#include <stdint.h>
typedef unsigned uint128_t __attribute__((mode(TI)));
void fcontract(uint128_t *t) {
	*t += 0x8000000000000 - 1;
}

void main(){
	(void) fcontract;
}
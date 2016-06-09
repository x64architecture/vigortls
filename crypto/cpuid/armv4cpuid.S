#include "arm_arch.h"

.text
.code	32

.align	5
#if __ARM_ARCH__ >= 7
.global	_armv7_neon_probe
.type	_armv7_neon_probe,%function
_armv7_neon_probe:
	.word	0xf26ee1fe	@ vorr	q15,q15,q15
	.word	0xe12fff1e	@ bx	lr
.size	_armv7_neon_probe,.-_armv7_neon_probe

.global	_armv7_tick
.type	_armv7_tick,%function
_armv7_tick:
	mrc	p15,0,r0,c9,c13,0
	.word	0xe12fff1e	@ bx	lr
.size	_armv7_tick,.-_armv7_tick
#endif

#if __ARM_ARCH__ >= 8
.global	_armv8_aes_probe
.type	_armv8_aes_probe,%function
_armv8_aes_probe:
	.word	0xf3b00300	@ aese.8	q0,q0
	.word	0xe12fff1e	@ bx	lr
.size	_armv8_aes_probe,.-_armv8_aes_probe

.global	_armv8_sha1_probe
.type	_armv8_sha1_probe,%function
_armv8_sha1_probe:
	.word	0xf2000c40	@ sha1c.32	q0,q0,q0
	.word	0xe12fff1e	@ bx	lr
.size	_armv8_sha1_probe,.-_armv8_sha1_probe

.global	_armv8_sha256_probe
.type	_armv8_sha256_probe,%function
_armv8_sha256_probe:
	.word	0xf3000c40	@ sha256h.32	q0,q0,q0
	.word	0xe12fff1e	@ bx	lr
.size	_armv8_sha256_probe,.-_armv8_sha256_probe
.global	_armv8_pmull_probe
.type	_armv8_pmull_probe,%function
_armv8_pmull_probe:
	.word	0xf2a00e00	@ vmull.p64	q0,d0,d0
	.word	0xe12fff1e	@ bx	lr
.size	_armv8_pmull_probe,.-_armv8_pmull_probe
#endif
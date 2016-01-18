#include "arm_arch.h"

.text
.code	32

.align	5
#if __ARM_ARCH__>=7
.global	_armv7_neon_probe
.type	_armv7_neon_probe,%function
_armv7_neon_probe:
	.word	0xf26ee1fe	@ vorr	q15,q15,q15
	.word	0xe12fff1e	@ bx	lr
.size	_armv7_neon_probe,.-_armv7_neon_probe
#endif

/*
 * Copyright 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

.macro adr_l, reg:req, sym:req
	adrp \reg, \sym
	add \reg, \reg, :lo12:\sym
.endm

/**
 * This is a generic entry point for an image. It carries out the operations
 * required to prepare the loaded image to be run. Specifically, it zeroes the
 * bss section using registers x25 and above, prepares the stack, enables
 * floating point, and sets up the exception vector.
 */
.section .init.entry, "ax"
.global entry
entry:
	/* Disable trapping floating point access in EL1. */
	mrs x30, cpacr_el1
	orr x30, x30, #(0x3 << 20)
	msr cpacr_el1, x30
	isb

	/* Zero out the bss section. */
	adr_l x29, bss_begin
	adr_l x30, bss_end
0:	cmp x29, x30
	b.hs 1f
	stp xzr, xzr, [x29], #16
	b 0b

1:	/* Prepare the stack. */
	adr x30, boot_stack_end
	mov sp, x30

	/* Call into Rust code. */
	bl main

	/* Loop forever waiting for interrupts. */
2:	wfi
	b 2b

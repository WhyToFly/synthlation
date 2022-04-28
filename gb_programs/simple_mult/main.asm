;--------------------------------------------------------
; File Created by SDCC : free open source ANSI-C Compiler
; Version 4.1.6 #12539 (Mac OS X x86_64)
;--------------------------------------------------------
	.module main
	.optsdcc -mgbz80
	
;--------------------------------------------------------
; Public variables in this module
;--------------------------------------------------------
	.globl _main
	.globl _waitpadup
	.globl _waitpad
	.globl _simple_mult_fun
;--------------------------------------------------------
; special function registers
;--------------------------------------------------------
;--------------------------------------------------------
; ram data
;--------------------------------------------------------
	.area _DATA
;--------------------------------------------------------
; ram data
;--------------------------------------------------------
	.area _INITIALIZED
;--------------------------------------------------------
; absolute external ram data
;--------------------------------------------------------
	.area _DABS (ABS)
;--------------------------------------------------------
; global & static initialisations
;--------------------------------------------------------
	.area _HOME
	.area _GSINIT
	.area _GSFINAL
	.area _GSINIT
;--------------------------------------------------------
; Home
;--------------------------------------------------------
	.area _HOME
	.area _HOME
;--------------------------------------------------------
; code
;--------------------------------------------------------
	.area _CODE
;main.c:7: void main(void)
;	---------------------------------
; Function main
; ---------------------------------
_main::
;main.c:57: __endasm;
;	this seems to always be at address 0200?
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
;	load example values; remove
	ld	a, #0x05
	ld	b, #0x00
;	put a into lower part of hl (first argument)
	ld	l, a
;	put b into upper part of hl (second argument)
	ld	h, b
;	pass arguments to function by pushing to the stack
	push	hl
;	call function
	call	_simple_mult_fun
;	get result in hl register
	pop	hl
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
;	call printf with result number
	ld	d, #0x00
	push	de
	ld	de, #___str_0
	push	de
	call	_printf
	add	sp, #4
	        ___str_0:
	.ascii	"%u"
	.db	0x00
;main.c:63: waitpad(0xFF);
	ld	a, #0xff
	push	af
	inc	sp
	call	_waitpad
	inc	sp
;main.c:64: waitpadup();
;main.c:65: }
	jp	_waitpadup
;main.c:68: uint8_t simple_mult_fun(uint8_t a){
;	---------------------------------
; Function simple_mult_fun
; ---------------------------------
_simple_mult_fun::
;main.c:69: return a * 4;
	ldhl	sp,	#2
	ld	a, (hl)
	add	a, a
	add	a, a
	ld	e, a
;main.c:70: }
	ret
	.area _CODE
	.area _INITIALIZER
	.area _CABS (ABS)

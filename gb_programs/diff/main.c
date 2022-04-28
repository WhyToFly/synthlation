#include <gb/gb.h>
#include <stdint.h>
#include <stdio.h>

uint8_t diff_fun(uint8_t a, uint8_t b);

void main(void)
{
    __asm
        ; this seems to always be at address 0200?
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop

        ; load example values; remove
        ld a, #0x05
        ld b, #0x07

        ; put a into lower part of hl (first argument)
        ld l, a
        ; put b into upper part of hl (second argument)
        ld h, b
        ; pass arguments to function by pushing to the stack
        push hl

        ; call function
        call _diff_fun

        ; get result in hl register
        pop hl

        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop

        ; call printf with result number
    	ld	d, #0x00
    	push	de
    	ld	de, #___str_0
    	push	de
    	call	_printf
    	add	sp, #4

        ___str_0:
        	.ascii "%u"
        	.db 0x00
    __endasm;

    //res = xor_fun(5,7);

    //printf("%u", res);

    waitpad(0xFF);
    waitpadup();
}

// looks like by having the function down here the start of main will always be at the same address? (0200)
uint8_t diff_fun(uint8_t a, uint8_t b){
    if (a > b){
        return a - b;
    }
    return b - a;
}

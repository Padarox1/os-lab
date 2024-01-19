.extern start_kernel
.extern task_init
.extern mm_init
.extern clock_set_next_event

#include "defs.h"


    .section .text.init
    .globl _start
_start:

    la sp, boot_stack_top
    li t0, PA2VA_OFFSET
    sub sp, sp, t0

    call setup_vm
    call relocate

    call mm_init

    call setup_vm_final

    call task_init

    # ------------------

        # set stvec = _traps

    la t0, trapvec
    csrw stvec, t0

    ; li t0, 0x00000001
    ; csrs stvec, t0

    # ------------------

        # set sie[STIE] = 1

    li t0, 0x00000020
    csrs sie, t0

    # ------------------

        # set first time interrupt

    call clock_set_next_event

    # ------------------

        # set sstatus[SIE] = 1

    ; li t0, 0x00000002
    ; csrs sstatus, t0

    # ------------------


    call start_kernel

relocate:
    # set ra = ra + PA2VA_OFFSET
    # set sp = sp + PA2VA_OFFSET (If you have set the sp before)
   
    li t0, PA2VA_OFFSET
    add ra, ra, t0

    li t0, PA2VA_OFFSET
    add sp, sp, t0

    # set satp with early_pgtbl
    
    la t0, early_pgtbl
    li t1, PA2VA_OFFSET
    sub t0, t0, t1
    srli t0, t0, 12
    li t1, 0x8000000000000000
    or t0, t0, t1
    csrw satp, t0
    
    # flush tlb
    sfence.vma zero, zero
		
    # flush icache
    fence.i

    ret

    .section .bss.stack
    .globl boot_stack
boot_stack:
    .space 0x1000 # <-- change to your stack size

    .globl boot_stack_top
boot_stack_top:
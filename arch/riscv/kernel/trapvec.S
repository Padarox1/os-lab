    .section .text.trapvec
    .align 2
    .globl trapvec

trapvec:
    j _traps # 5
    .space 4
    .space 4
    .space 4
    .space 4
    j _traps # 5
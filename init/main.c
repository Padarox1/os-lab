#include "printk.h"
#include "sbi.h"

extern void test();

int start_kernel() {
    printk("2022");
    printk(" Hello RISC-V\n");
    // sbi_ecall(0x1, 0x0, 0x30, 0, 0, 0, 0, 0);

    // schedule();
    
    test(); // DO NOT DELETE !!!

	return 0;
}

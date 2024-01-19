// clock.c
#include "printk.h"
// QEMU中时钟的频率是10MHz, 也就是1秒钟相当于10000000个时钟周期。
unsigned long TIMECLOCK = 1000000;
extern void do_timer();
extern void sbi_ecall(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
unsigned long get_cycles() {
    // 编写内联汇编，使用 rdtime 获取 time 寄存器中 (也就是mtime 寄存器 )的值并返回
    // YOUR CODE HERE
    unsigned long cycles;
    asm volatile ("rdtime %0" : "=r" (cycles));
    return cycles;
}

int finish = 0;
void clock_set_next_event() {
    // 下一次 时钟中断 的时间点

    

    unsigned long now = get_cycles();

    // printk("now @ %d\n", now);

    unsigned long next = get_cycles() + TIMECLOCK;

    // 使用 sbi_ecall 来完成对下一次时钟中断的设置
    // YOUR CODE HERE

    // printk("next clock interrupt @ %d\n", next);
    sbi_ecall(0, 0, next, 0, 0, 0, 0, 0);
} 
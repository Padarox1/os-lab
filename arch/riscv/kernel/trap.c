#include "printk.h"
#include "types.h"
#include "syscall.h"
#include "defs.h"
#include "proc.h"

extern void clock_set_next_event();
extern void do_timer();

extern struct task_struct *current; // 当前运行线程

void do_page_fault(struct pt_regs *regs)
{
    /*
        1. 通过 stval 获得访问出错的虚拟内存地址（Bad Address）
        2. 通过 find_vma() 查找 Bad Address 是否在某个 vma 中
        3. 分配一个页，将这个页映射到对应的用户地址空间
        4. 通过 (vma->vm_flags & VM_ANONYM) 获得当前的 VMA 是否是匿名空间
        5. 根据 VMA 匿名与否决定将新的页清零或是拷贝 uapp 中的内容
    */
    uint64_t bad_addr = regs->stval;

    uint64_t bad_page_start = bad_addr >> 12 << 12;
    uint64_t bad_page_end = (bad_addr >> 12 << 12) + PGSIZE;
    struct vm_area_struct *vma = find_vma(current, bad_addr);
    if (vma == NULL)
    {
        printk("bad addr: %lx\n", bad_addr);
        printk("find vma failed!\n");
        return;
    }
    uint64_t page = (uint64_t)alloc_page();
    if (page == 0)
    {
        printk("alloc page failed!\n");
        return;
    }
    // printk("vm_flags: %lx\n", vma->vm_flags);
    uint64_t perm = PTE_V | PTE_U;
    if (vma->vm_flags & VM_R_MASK)
    {
        perm |= PTE_R;
    }
    if (vma->vm_flags & VM_W_MASK)
    {
        perm |= PTE_W;
    }
    if (vma->vm_flags & VM_X_MASK)
    {
        perm |= PTE_X;
    }
    create_mapping_one(current->pgd, bad_addr, page - PA2VA_OFFSET, perm);
    if (vma->vm_flags & VM_ANONYM)
    {
        memset((void *)bad_page_start, 0, PGSIZE);
    }
    else
    {
        *(char *)bad_addr = 0;
        uint64_t file_bad_addr = bad_addr - vma->vm_start + vma->vm_content_offset_in_file;
        uint64_t file_bad_page_start = file_bad_addr >> 12 << 12;
        uint64_t file_bad_page_end = (file_bad_addr >> 12 << 12) + PGSIZE;
        if (file_bad_page_start < vma->vm_content_offset_in_file)
        {
            file_bad_page_start = vma->vm_content_offset_in_file;
        }
        if (file_bad_page_end > vma->vm_content_offset_in_file + vma->vm_content_size_in_file)
        {
            file_bad_page_end = vma->vm_content_offset_in_file + vma->vm_content_size_in_file;
        }
        if (file_bad_page_start >= file_bad_page_end)
        {
            // printk("file_bad_page_start >= file_bad_page_end!\n");
            return;
        }
        bad_page_start = file_bad_page_start + vma->vm_start - vma->vm_content_offset_in_file;
        bad_page_end = file_bad_page_end + vma->vm_start - vma->vm_content_offset_in_file;
        memcpy((void *)bad_page_start, (void *)file_bad_page_start, file_bad_page_end - file_bad_page_start);
    }
}

void trap_handler(uint64_t scause, uint64_t sepc, struct pt_regs *regs)
{
    // 通过 `scause` 判断trap类型
    // 如果是interrupt 判断是否是timer interrupt
    // 如果是timer interrupt 则打印输出相关信息, 并通过 `clock_set_next_event()` 设置下一次时钟中断
    // `clock_set_next_event()` 见 4.3.4 节
    // 其他interrupt / exception 可以直接忽略

    // YOUR CODE HERE

    // printk("scause: %lx\n", scause);

    // register unsigned long t0 asm("t0") = 0;
    // asm volatile("csrr t0, sscratch" : "=r"(t0));
    // printk("sscratch: %lx\n", t0);
    if (scause == 0x8000000000000005)
    {
        // printk("timer interrupt!\n");
        clock_set_next_event();
        do_timer();
    }
    else if (scause == 0x8)
    {
        if (regs->x[17] == SYS_WRITE)
        {
            regs->x[10] = sys_write(regs->x[10], (void *)regs->x[11], regs->x[12]);
        }
        else if (regs->x[17] == SYS_GETPID)
        {
            regs->x[10] = sys_getpid();
        }
        else if (regs->x[17] == SYS_CLONE)
        {
            regs->x[10] = sys_clone(regs);
        }
        else if (regs->x[17] == SYS_READ)
        {
            regs->x[10] = sys_read(regs->x[10], (void *)regs->x[11], regs->x[12]);
        }
        else if(regs->x[17] == SYS_OPENAT)
        {
            regs->x[10] = sys_openat(regs->x[10], (void *)regs->x[11], regs->x[12]);
        }
        else if(regs->x[17] == SYS_CLOSE)
        {
            regs->x[10] = sys_close(regs->x[10]);
            // printk("sys_close not implemented!\n");
        }
        else if(regs->x[17] == SYS_LSEEK)
        {
            regs->x[10] = sys_lseek(regs->x[10], regs->x[11], regs->x[12]);
        }
        else
        {
            printk("Unhandled Syscall: %d\n", regs->x[17]);
            while (1);
        }
        // for (unsigned int i = 0; i < 0x4FFFFFFF; i++)
        //     ;
        regs->sepc += 4;
    }
    else if (scause == 12 || scause == 13 || scause == 15)
    {
        // printk("page fault!\n");
        // printk("stval: %lx\n", regs->stval);
        // printk("sepc: %lx\n", regs->sepc);
        // printk("scause: %lx\n", regs->scause);
        do_page_fault(regs);
    }
    else
    {
        // printk("other interrupt!\n");
    }
}
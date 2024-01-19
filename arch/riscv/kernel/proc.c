// arch/riscv/kernel/proc.c
#include "proc.h"
#include "mm.h"
#include "defs.h"
#include "rand.h"
#include "printk.h"
#include "test.h"
#include "elf.h"
#include "virtio.h"
#include "mbr.h"
// arch/riscv/kernel/proc.c

struct task_struct *idle;           // idle process
struct task_struct *current;        // 指向当前运行线程的 `task_struct`
struct task_struct *task[NR_TASKS]; // 线程数组, 所有的线程都保存在此

/**
 * new content for unit test of 2023 OS lab2
 */

// char task_test_char[NR_TASKS];       // TEST_SCHEDULE 测试中，各个 TASK 输出的字符
// uint64 task_test_priority[NR_TASKS]; // TEST_SCHEDULE 测试中，各个 TASK 的 priority 已经被事先定好
// uint64 task_test_counter[NR_TASKS];  // TEST_SCHEDULE 测试中，各个 TASK 的 counter 已经被事先定好
// uint64 task_test_index = 0;          // TEST_SCHEDULE 测试中，输出到 task_test_output 中的字符数量
// char task_test_output[NR_TASKS + 1]; // TEST_SCHEDULE 测试中，各个 TASK 输出字符的全局 buffer

extern uint64 task_test_priority[]; // test_init 后，用于初始化 task[i].priority 的数组
extern uint64 task_test_counter[];  // test_init 后，用于初始化 task[i].counter  的数组

extern unsigned long swapper_pg_dir[]; // swapper_pg_dir 在 setup_vm_final 中初始化
extern void create_mapping(uint64 *pgtbl, uint64 va, uint64 pa, uint64 sz, uint64 perm);

extern char _sramdisk[], _eramdisk[];
extern char __dummy[];
extern char __ret_from_fork[];

void do_mmap(struct task_struct *task, uint64_t addr, uint64_t length, uint64_t flags,
             uint64_t vm_content_offset_in_file, uint64_t vm_content_size_in_file)
{
    (task->vma_cnt)++;
    struct vm_area_struct *vma = task->vmas + task->vma_cnt - 1;
    vma->vm_start = addr;
    vma->vm_end = addr + length;
    vma->vm_flags = flags;
    vma->vm_content_offset_in_file = vm_content_offset_in_file;
    vma->vm_content_size_in_file = vm_content_size_in_file;
}

struct vm_area_struct *find_vma(struct task_struct *task, uint64_t addr)
{
    for (int i = 0; i < task->vma_cnt; i++)
    {
        if (task->vmas[i].vm_start <= addr && task->vmas[i].vm_end > addr)
        {
            return task->vmas + i;
        }
    }
    return 0;
}

static uint64_t load_program_vma(struct task_struct *task)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)_sramdisk;

    uint64_t phdr_start = (uint64_t)ehdr + ehdr->e_phoff;
    int phdr_cnt = ehdr->e_phnum;

    int64_t magic_num = 0x00010102464c457f;
    if (*(int64_t *)(ehdr->e_ident) != magic_num)
    {
        printk("not a valid elf file\n");
        return -1;
    }
    if (*(int64_t *)(&ehdr->e_ident[8]) != 0)
    {
        printk("not a valid elf file\n");
        return -1;
    }

    Elf64_Phdr *phdr;
    int load_phdr_cnt = 0;
    for (int i = 0; i < phdr_cnt; i++)
    {
        phdr = (Elf64_Phdr *)(phdr_start + sizeof(Elf64_Phdr) * i);
        if (phdr->p_type == PT_LOAD)
        {
            // alloc space and copy content
            // do mapping
            uint64_t va = phdr->p_vaddr;
            uint64_t sz = phdr->p_memsz;
            uint64_t va_end = va + sz;
            uint64_t begin_page = va >> 12;
            uint64_t end_page = (va_end - 1) >> 12;
            uint64_t page_num = end_page - begin_page + 1;
            uint64_t page_offset = va & 0xfff;
            // uint64_t pa = (uint64_t)alloc_page(page_num);
            uint64_t perm = PTE_U | PTE_V;
            if (phdr->p_flags & PF_X)
                perm |= PTE_X;
            if (phdr->p_flags & PF_W)
                perm |= PTE_W;
            if (phdr->p_flags & PF_R)
                perm |= PTE_R;
            uint64_t vma_perm = 0;
            if (phdr->p_flags & PF_X)
                vma_perm |= VM_X_MASK;
            if (phdr->p_flags & PF_W)
                vma_perm |= VM_W_MASK;
            if (phdr->p_flags & PF_R)
                vma_perm |= VM_R_MASK;

            printk("page_offset: %ld\n", page_offset);
            printk("page_num: %ld\n", page_num);

            // memset((void *)pa, 0, page_num * PGSIZE);
            // memcpy((void *)(pa + page_offset), (void *)((uint64_t)ehdr + phdr->p_offset), phdr->p_filesz);

            // create_mapping(task->pgd, va, pa - PA2VA_OFFSET, sz, perm);
            do_mmap(task, va, sz, vma_perm, (void *)((uint64_t)ehdr + phdr->p_offset), phdr->p_filesz);

            load_phdr_cnt++;
        }
    }

    // allocate user stack and do mapping
    // create_mapping(task->pgd, USER_END - PGSIZE, (uint64_t)alloc_page() - PA2VA_OFFSET, PGSIZE, PTE_R | PTE_W | PTE_X | PTE_V | PTE_U);
    do_mmap(task, USER_END - PGSIZE, PGSIZE, VM_R_MASK | VM_W_MASK | VM_ANONYM, 0, 0);

    // following code has been written for you
    // set user stack pointer

    // pc for the user program
    task->thread.sepc = ehdr->e_entry;
    // sstatus bits set
    task->thread.sstatus = SPIE | SUM;
    // user stack for user program
    task->thread.sscratch = USER_END;
}

uint64 task_clone(struct pt_regs *regs)
{
    /*
     1. 参考 task_init 创建一个新的 task，将的 parent task 的整个页复制到新创建的
        task_struct 页上(这一步复制了哪些东西?）。将 thread.ra 设置为
        __ret_from_fork，并正确设置 thread.sp
        (仔细想想，这个应该设置成什么值?可以根据 child task 的返回路径来倒推)

     2. 利用参数 regs 来计算出 child task 的对应的 pt_regs 的地址，
        并将其中的 a0, sp, sepc 设置成正确的值(为什么还要设置 sp?)

     3. 为 child task 申请 user stack，并将 parent task 的 user stack
        数据复制到其中。 (既然 user stack 也在 vma 中，这一步也可以直接在 5 中做，无需特殊处理)

     3.1. 同时将子 task 的 user stack 的地址保存在 thread_info->
        user_sp 中，如果你已经去掉了 thread_info，那么无需执行这一步

     4. 为 child task 分配一个根页表，并仿照 setup_vm_final 来创建内核空间的映射

     5. 根据 parent task 的页表和 vma 来分配并拷贝 child task 在用户态会用到的内存

     6. 返回子 task 的 pid
    */
    int new_pid = -1;
    for (int i = 1; i < NR_TASKS; i++)
    {
        if (task[i] == NULL)
        {
            new_pid = i;
            break;
        }
    }
    if (new_pid == -1)
    {
        printk("task array is full!\n");
        return -1;
    }
    task[new_pid] = (struct task_struct *)kalloc();
    memcpy(task[new_pid], current, PGSIZE);
    task[new_pid]->pid = new_pid;
    struct pt_regs *child_regs = (struct pt_regs *)((uint64)task[new_pid] + (uint64)regs - (uint64)current);
    child_regs->x[REG_a0] = 0;
    child_regs->x[REG_sp] = child_regs->x[REG_sp] - (uint64)current + (uint64)task[new_pid];
    child_regs->sepc += 4;
    // printk("child_regs->x[REG_sp]: %lx\n", child_regs->x[REG_sp]);
    task[new_pid]->thread.ra = (uint64)__ret_from_fork;
    task[new_pid]->thread.sp = child_regs->x[REG_sp];
    task[new_pid]->thread.sepc = child_regs->sepc;
    task[new_pid]->thread.sstatus = child_regs->sstatus;
    task[new_pid]->thread.sscratch = child_regs->sscratch;
    task[new_pid]->pgd = (uint64)alloc_page();
    memset(task[new_pid]->pgd, 0, PGSIZE);
    memcpy(task[new_pid]->pgd, swapper_pg_dir, PGSIZE);
    task[new_pid]->satp = (uint64)task[new_pid]->pgd - PA2VA_OFFSET;
    task[new_pid]->satp = (uint64)task[new_pid]->satp >> 12;
    task[new_pid]->satp = (pagetable_t)((uint64)task[new_pid]->satp | 0x8000000000000000);
    for (int i = 0; i < current->vma_cnt; i++)
    {
        struct vm_area_struct *vma = task[new_pid]->vmas + i;
        uint64_t va_start = vma->vm_start;
        uint64_t va_end = vma->vm_end;
        uint64_t va_start_page = va_start >> 12;
        uint64_t va_end_page = (va_end - 1) >> 12;
        uint64_t PTE_perm = PTE_V | PTE_U;
        if (vma->vm_flags & VM_R_MASK)
        {
            PTE_perm |= PTE_R;
        }
        if (vma->vm_flags & VM_W_MASK)
        {
            PTE_perm |= PTE_W;
        }
        if (vma->vm_flags & VM_X_MASK)
        {
            PTE_perm |= PTE_X;
        }
        if (va_start_page == va_end_page)
        {
            uint64_t va_offset = va_start & 0xfff;
            uint64_t va_size = va_end - va_start;
            if (is_mapped(current->pgd, va_start))
            {
                uint64_t pa = (uint64_t)alloc_page();
                memcpy((void *)pa, (void *)va_start, va_size);
                create_mapping_one(task[new_pid]->pgd, va_start, pa - PA2VA_OFFSET, PTE_perm);
            }
        }
        else
        {
            uint64_t va_offset = va_start & 0xfff;
            uint64_t va_size = va_end - va_start;
            uint64_t pa;
            if (is_mapped(current->pgd, va_start))
            {
                pa = (uint64_t)alloc_page();
                memcpy((void *)pa + va_offset, (void *)va_start, PGSIZE - va_offset);
                create_mapping_one(task[new_pid]->pgd, va_start, pa - PA2VA_OFFSET, PTE_perm);
            }
            for (int j = va_start_page + 1; j < va_end_page; j++)
            {
                if(is_mapped(current->pgd, j << 12))
                {
                    pa = (uint64_t)alloc_page();
                    memcpy((void *)pa, (void *)(j << 12), PGSIZE);
                    create_mapping_one(task[new_pid]->pgd, j << 12, pa - PA2VA_OFFSET, PTE_perm);
                }
            }
            if(is_mapped(current->pgd, va_end_page << 12))
            {
                pa = (uint64_t)alloc_page();
                memcpy((void *)pa, (void *)(va_end_page << 12), va_end & 0xfff);
                create_mapping_one(task[new_pid]->pgd, va_end_page << 12, pa - PA2VA_OFFSET, PTE_perm);
            }
        }
    }
    return new_pid;
}
void task_init()
{

    test_init(NR_TASKS);
    // 1. 调用 kalloc() 为 idle 分配一个物理页

    idle = (struct task_struct *)kalloc();

    // 2. 设置 state 为 TASK_RUNNING;

    idle->state = TASK_RUNNING;

    // 3. 由于 idle 不参与调度 可以将其 counter / priority 设置为 0

    idle->counter = 0;
    idle->priority = 0;

    // 4. 设置 idle 的 pid 为 0
    idle->pid = 0;
    // 5. 将 current 和 task[0] 指向 idle
    current = idle;
    task[0] = idle;

    /* YOUR CODE HERE */

    // 1. 参考 idle 的设置, 为 task[1] ~ task[NR_TASKS - 1] 进行初始化

    // 2. 其中每个线程的 state 为 TASK_RUNNING, counter 为 0, priority 使用 rand() 来设置, pid 为该线程在线程数组中的下标。
    //      但如果 TEST_SCHEDULE 宏已经被 define，那么为了单元测试的需要，进行如下赋值：
    //      task[i].counter  = task_test_counter[i];
    //      task[i].priority = task_test_priority[i];

    // 3. 为 task[1] ~ task[NR_TASKS - 1] 设置 `thread_struct` 中的 `ra` 和 `sp`,

    // 4. 其中 `ra` 设置为 __dummy （见 4.3.2）的地址,  `sp` 设置为 该线程申请的物理页的高地址

    uint64 page_num = ((uint64)_eramdisk - (uint64)_sramdisk) / PGSIZE + 1;

    for (int i = 1; i < 2; i++)
    {
        task[i] = (struct task_struct *)kalloc();
        task[i]->state = TASK_RUNNING;
        task[i]->counter = task_test_counter[i];
        task[i]->priority = task_test_priority[i];
        task[i]->pid = i;

        task[i]->thread.ra = (uint64)__dummy;
        task[i]->thread.sp = (uint64)task[i] + PGSIZE;

        task[i]->pgd = (uint64)alloc_page();
        memset(task[i]->pgd, 0, PGSIZE);
        memcpy(task[i]->pgd, swapper_pg_dir, PGSIZE);

        load_program_vma(task[i]);

        task[i]->satp = (uint64)task[i]->pgd - PA2VA_OFFSET;
        task[i]->satp = (uint64)task[i]->satp >> 12;
        task[i]->satp = (pagetable_t)((uint64)task[i]->satp | 0x8000000000000000);

        task[i]->files = file_init();
    }

    /* YOUR CODE HERE */

    printk("...proc_init done!\n");

    virtio_dev_init();
    printk("virtio_dev_init done!\n");
    mbr_init();

}

extern void schedule_test();
void dummy()
{

    schedule_test();
    uint64 MOD = 1000000007;
    uint64 auto_inc_local_var = 0;
    int last_counter = -1;
    printk("dummy: current->counter = %d, current->pid = %d\n", current->counter, current->pid);
    while (1)
    {
        if ((last_counter == -1 || current->counter != last_counter) && current->counter > 0)
        {
            if (current->counter == 1)
            {
                --(current->counter); // forced the counter to be zero if this thread is going to be scheduled
            }                         // in case that the new counter is also 1，leading the information not printed.
            last_counter = current->counter;
            auto_inc_local_var = (auto_inc_local_var + 1) % MOD;
            printk("[PID = %d] is running. auto_inc_local_var = %d. thread space begin at %llx\n", current->pid, auto_inc_local_var, current);
        }
    }
}

extern void __switch_to(struct task_struct *prev, struct task_struct *next);

void switch_to(struct task_struct *next)
{
    /* YOUR CODE HERE */

    if (current == next)
    {
        return;
    }

    struct task_struct *prev = current;
    current = next;
    __switch_to(prev, next);
}

void do_timer(void)
{
    // 1. 如果当前线程是 idle 线程 直接进行调度
    // 2. 如果当前线程不是 idle 对当前线程的运行剩余时间减1 若剩余时间仍然大于0 则直接返回 否则进行调度

    /* YOUR CODE HERE */

    if (current == idle)
    {
        schedule();
        return;
    }

    if (current->counter == 0)
    {
        schedule();
        return;
    }
    current->counter--;
    if (current->counter == 0)
    {
        schedule();
    }
}

void schedule(void)
{
    /* YOUR CODE HERE */
#ifdef SJF
    struct task_struct *next = idle;
    uint64 min_left_time = 0x7fffffffffffffff;
    int flag = 0;
    // printk("schedule\n");
    for (int i = 1; i < NR_TASKS; i++)
    {
        if (task[i]->state == TASK_RUNNING)
        {
            if (task[i]->counter)
                flag = 1;
            if (task[i]->counter < min_left_time && task[i]->counter > 0)
            {
                min_left_time = task[i]->counter;
                next = task[i];
            }
        }
    }

    if (!flag)
    {
        for (int i = 1; i < NR_TASKS; i++)
        {
            if (task[i]->state == TASK_RUNNING)
            {
                task[i]->counter = rand();
            }
        }
        schedule();
        return;
    }

    switch_to(next);
#endif

#ifdef PRIORITY
    struct task_struct *next = idle;
    uint64 max_counter = 0;
    int flag = 0;
    // printk("schedule\n");
    for (int i = 1; i < NR_TASKS; i++)
    {
        if (task[i] == NULL)
            continue;
        if (task[i]->state == TASK_RUNNING)
        {
            if (task[i]->counter)
                flag = 1;
            if (task[i]->counter >= max_counter)
            {
                max_counter = task[i]->counter;
                next = task[i];
            }
        }
    }

    if (max_counter == 0)
    {
        for (int i = 1; i < NR_TASKS; i++)
        {
            if (task[i] == NULL)
                continue;
            if (task[i]->state == TASK_RUNNING)
            {
                task[i]->counter = task[i]->priority;
            }
        }
        schedule();
        return;
    }

    switch_to(next);
#endif
}

#include "defs.h"
#include "printk.h"
#include "virtio.h"
// arch/riscv/kernel/vm.c

/* early_pgtbl: 用于 setup_vm 进行 1GB 的 映射。 */
unsigned long  early_pgtbl[512] __attribute__((__aligned__(0x1000)));

void setup_vm(void) {
    /* 
    将 0x80000000 开始的 1GB 区域进行两次映射，其中一次是等值映射 ( PA == VA ) ，另一次是将其映射到 direct mapping area ( 使得 PA + PV2VA_OFFSET == VA )。
    1. 由于是进行 1GB 的映射 这里不需要使用多级页表 
    2. 将 va 的 64bit 作为如下划分： | high bit | 9 bit | 30 bit |
        high bit 可以忽略
        中间9 bit 作为 early_pgtbl 的 index
        低 30 bit 作为 页内偏移 这里注意到 30 = 9 + 9 + 12， 即我们只使用根页表， 根页表的每个 entry 都对应 1GB 的区域。 
    3. Page Table Entry 的权限 V | R | W | X 位设置为 1
    */

    unsigned long *p = early_pgtbl;
    unsigned long va = 0x80000000;
    unsigned long pa = 0x80000000;
    unsigned long mid_bits = 0x1ffll << 30;
    unsigned long low_bits = 0x3fffffff;

    p[(va&mid_bits)>>30] = pa >> 12 << 10 | 0xf;

    va += PA2VA_OFFSET;

    p[(va&mid_bits)>>30] = pa >> 12 << 10 | 0xf;


}

/* swapper_pg_dir: kernel pagetable 根目录， 在 setup_vm_final 进行映射。 */
unsigned long  swapper_pg_dir[512] __attribute__((__aligned__(0x1000)));
extern char _stext[], _etext[];
extern char _srodata[], _erodata[];
extern char _sdata[], _edata[];
extern char _sbss[], _ebss[];
extern char _sramdisk[], _eramdisk[];
void setup_vm_final(void) {
    memset(swapper_pg_dir, 0x0, PGSIZE);

    // No OpenSBI mapping required

    // mapping kernel text X|-|R|V
    // create_mapping(...);
    create_mapping(swapper_pg_dir, _stext, _stext - PA2VA_OFFSET, _etext - _stext, PTE_X | PTE_R | PTE_V);

    // mapping kernel rodata -|-|R|V
    // create_mapping(...);
    create_mapping(swapper_pg_dir, _srodata, _srodata - PA2VA_OFFSET,  _erodata - _srodata, PTE_R | PTE_V);
    
    // mapping other memory -|W|R|V
    // create_mapping(...);
    // create_mapping(swapper_pg_dir, _sdata, _sdata - PA2VA_OFFSET, _edata - _sdata, 0x7);
    // create_mapping(swapper_pg_dir, _sbss, _sbss - PA2VA_OFFSET, _ebss - _sbss, 0x7);
    create_mapping(swapper_pg_dir, _sdata, _sdata - PA2VA_OFFSET, PHY_END + PA2VA_OFFSET - (uint64)_sdata, PTE_W | PTE_R | PTE_V);

    create_mapping(swapper_pg_dir, _sramdisk, _sramdisk - PA2VA_OFFSET, _eramdisk - _sramdisk, PTE_X | PTE_W | PTE_R | PTE_V);

    create_mapping(swapper_pg_dir, io_to_virt(VIRTIO_START), VIRTIO_START, VIRTIO_SIZE * VIRTIO_COUNT, PTE_W | PTE_R | PTE_V);

    // set satp with swapper_pg_dir
    register unsigned long t0 asm("t0") = (unsigned long)swapper_pg_dir - PA2VA_OFFSET;
    t0 = t0 >> 12;
    t0 |= 0x8000000000000000;

    printk("satp: %lx\n", t0);

    asm volatile("csrw satp, %0" : : "r"(t0));

    // YOUR CODE HERE

    // flush TLB
    asm volatile("sfence.vma zero, zero");
  
    // flush icache
    asm volatile("fence.i");
    return;
}




void create_mapping_one(uint64 *pgtbl, uint64 va, uint64 pa, uint64 perm) {

    unsigned long vpn[3];
    unsigned long *p = pgtbl;
    unsigned long va_tmp = va;
    vpn[2] = (va_tmp >> 30) & 0x1ff;
    vpn[1] = (va_tmp >> 21) & 0x1ff;
    vpn[0] = (va_tmp >> 12) & 0x1ff;

    unsigned long pte = p[vpn[2]];
    if ((pte & PTE_V) == 0) {
        unsigned long pgtbl_1 = (unsigned long)kalloc() - PA2VA_OFFSET;
        pgtbl_1 = pgtbl_1 >> 12 << 10;
        p[vpn[2]] = (unsigned long)pgtbl_1 | PTE_V;
    }

    p = (unsigned long *)((p[vpn[2]] >> 10 << 12) + PA2VA_OFFSET);

    pte = p[vpn[1]];
    if ((pte & PTE_V) == 0) {
        unsigned long pgtbl_2 = (unsigned long)kalloc() - PA2VA_OFFSET;
        pgtbl_2 = pgtbl_2 >> 12 << 10;
        p[vpn[1]] = (unsigned long)pgtbl_2 | PTE_V;
    }

    p = (unsigned long *)((p[vpn[1]] >> 10 << 12) + PA2VA_OFFSET);

    pte = pa >> 12 << 10 | perm;
    p[vpn[0]] = pte;

}

/**** 创建多级页表映射关系 *****/
/* 不要修改该接口的参数和返回值 */
void create_mapping(uint64 *pgtbl, uint64 va, uint64 pa, uint64 sz, uint64 perm) {
    /*
    pgtbl 为根页表的基地址
    va, pa 为需要映射的虚拟地址、物理地址
    sz 为映射的大小，单位为字节
    perm 为映射的权限 (即页表项的低 8 位)

    创建多级页表的时候可以使用 kalloc() 来获取一页作为页表目录
    可以使用 V bit 来判断页表项是否存在
    */

    for(int i = 0; i < sz; i += PGSIZE) {
        create_mapping_one(pgtbl, va + i, pa + i, perm);
    }
    


}

int is_mapped(uint64 *pgtbl, uint64 va) {
    unsigned long vpn[3];
    unsigned long *p = pgtbl;
    unsigned long va_tmp = va;
    vpn[2] = (va_tmp >> 30) & 0x1ff;
    vpn[1] = (va_tmp >> 21) & 0x1ff;
    vpn[0] = (va_tmp >> 12) & 0x1ff;

    unsigned long pte = p[vpn[2]];
    if ((pte & PTE_V) == 0) {
        return 0;
    }

    p = (unsigned long *)((p[vpn[2]] >> 10 << 12) + PA2VA_OFFSET);

    pte = p[vpn[1]];
    if ((pte & PTE_V) == 0) {
        return 0;
    }

    p = (unsigned long *)((p[vpn[1]] >> 10 << 12) + PA2VA_OFFSET);

    pte = p[vpn[0]];
    if ((pte & PTE_V) == 0) {
        return 0;
    }

    return 1;
}
#include "syscall.h"
#include "fs.h"
#include "proc.h"
#include "types.h"
#include <fat32.h>

extern uint64 printk(const char *fmt, ...);
extern struct task_struct *current;

uint64 sys_write(unsigned int fd, const char *buf, uint64 len)
{
    int64_t ret = 0;
    struct file *file = &(current->files[fd]);
    if (file->opened)
    {
        if (file->perms & FILE_WRITABLE)
        {
            ret = file->write(file, buf, len);
        }
        else
        {
            printk("sys_write: fd = %d, file not writable\n", fd);
            ret = ERROR_FILE_NOT_OPEN;
        }
    }
    else
    {
        printk("sys_write: fd = %d, file not opened\n", fd);
        ret = ERROR_FILE_NOT_OPEN;
    }
    return ret;

    // printk("sys_write: fd = %d, buf = %s, len = %d\n", fd, buf, len);
    // char *cbuf = (char *)buf;
    // uint64 res = printk("%s", cbuf);
    // return res;
}

int64_t sys_read(unsigned int fd, char *buf, uint64_t count)
{
    int64_t ret;
    struct file *target_file = &(current->files[fd]);
    if (target_file->opened)
    {
        if (target_file->perms & FILE_READABLE)
        {
            ret = target_file->read(target_file, buf, count);
        }
        else
        {
            printk("sys_read: fd = %d, file not readable\n", fd);
            ret = ERROR_FILE_NOT_OPEN;
        }
    }
    else
    {
        printk("sys_read: fd = %d, file not opened\n", fd);
        ret = ERROR_FILE_NOT_OPEN;
    }
    return ret;
}

int64_t sys_lseek(int fd, int64_t offset, int whence)
{
    int64_t ret;
    struct file *target_file = &(current->files[fd]);
    if (target_file->opened)
    {
        if (target_file->perms & FILE_READABLE)
        {
            ret = target_file->lseek(target_file, offset, whence);
        }
        else if (target_file->perms & FILE_WRITABLE)
        {
            ret = target_file->lseek(target_file, offset, whence);
        }
        else
        {
            printk("sys_lseek: fd = %d, file not readable\n", fd);
            ret = ERROR_FILE_NOT_OPEN;
        }
    }
    else
    {
        printk("sys_lseek: fd = %d, file not opened\n", fd);
        ret = ERROR_FILE_NOT_OPEN;
    }
    return ret;
}

int64_t sys_openat(int dfd, const char *filename, int flags)
{
    int fd = -1;

    // Find an available file descriptor first
    for (int i = 0; i < PGSIZE / sizeof(struct file); i++)
    {
        if (!current->files[i].opened)
        {
            fd = i;
            break;
        }
    }

    // Do actual open
    file_open(&(current->files[fd]), filename, flags);

    // printk("sys_openat: dfd = %d, filename = %s, flags = %d, fd = %d\n", dfd, filename, flags, fd);

    return fd;
}

int64_t sys_close(int fd)
{
    int64_t ret;
    struct file *target_file = &(current->files[fd]);
    if (target_file->opened)
    {
        target_file->opened = 0;
    }
    else
    {
        printk("sys_close: fd = %d, file not opened\n", fd);
        ret = ERROR_FILE_NOT_OPEN;
    }
    return ret;

}

uint64 sys_getpid()
{
    // printk("sys_getpid: pid = %d\n", current->pid);
    return current->pid;
}

extern struct pt_regs;
uint64 sys_clone(struct pt_regs *regs)
{
    return task_clone(regs);
}
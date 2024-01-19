#include <defs.h>
#include <fat32.h>
#include <mbr.h>
#include <mm.h>
#include <printk.h>
#include <string.h>
#include <virtio.h>

struct fat32_bpb fat32_header;

struct fat32_volume fat32_volume;

uint8_t fat32_buf[VIRTIO_BLK_SECTOR_SIZE];
uint8_t fat32_table_buf[VIRTIO_BLK_SECTOR_SIZE];

uint64_t cluster_to_sector(uint64_t cluster) // cluster的第一个sector
{
    return (cluster - 2) * fat32_volume.sec_per_cluster + fat32_volume.first_data_sec;
}

uint32_t next_cluster(uint64_t cluster) // 下一个cluster的编号
{
    uint64_t fat_offset = cluster * 4;
    uint64_t fat_sector = fat32_volume.first_fat_sec + fat_offset / VIRTIO_BLK_SECTOR_SIZE;
    virtio_blk_read_sector(fat_sector, fat32_table_buf);
    int index_in_sector = fat_offset % (VIRTIO_BLK_SECTOR_SIZE / sizeof(uint32_t));
    return *(uint32_t *)(fat32_table_buf + index_in_sector);
}

void fat32_init(uint64_t lba, uint64_t size)
{
    virtio_blk_read_sector(lba, (void *)&fat32_header);
    assert(lba == fat32_header.hidd_sec);
    fat32_volume.first_fat_sec = lba + fat32_header.rsvd_sec_cnt;
    fat32_volume.sec_per_cluster = fat32_header.sec_per_clus;
    fat32_volume.first_data_sec = fat32_volume.first_fat_sec + fat32_header.fat_sz32 * fat32_header.num_fats;
    fat32_volume.fat_sz = fat32_header.fat_sz32;

    virtio_blk_read_sector(fat32_volume.first_data_sec, fat32_buf); // Get the root directory
    struct fat32_dir_entry *dir_entry = (struct fat32_dir_entry *)fat32_buf;
}

int is_fat32(uint64_t lba)
{
    virtio_blk_read_sector(lba, (void *)&fat32_header);
    if (fat32_header.boot_sector_signature != 0xaa55)
    {
        return 0;
    }
    return 1;
}

int next_slash(const char *path)
{
    int i = 0;
    while (path[i] != '\0' && path[i] != '/')
    {
        i++;
    }
    if (path[i] == '\0')
    {
        return -1;
    }
    return i;
}

void to_upper_case(char *str)
{
    for (int i = 0; str[i] != '\0'; i++)
    {
        if (str[i] >= 'a' && str[i] <= 'z')
        {
            str[i] -= 32;
        }
    }
}

struct fat32_file fat32_open_file(const char *path)
{
    struct fat32_file file;
    /* todo: open the file according to path */
    // find the filename
    int slash_pos = next_slash(path + 1);
    int len = strlen(path);
    char filename[13];
    memcpy(filename, path + 1 + slash_pos + 1, len - slash_pos - 1);
    // to uppercase
    to_upper_case(filename);
    // printk("fat32_open_file: filename = %s\n", filename);
    for (int i = 0; i < fat32_volume.sec_per_cluster; ++i)
    {
        virtio_blk_read_sector(fat32_volume.first_data_sec + i, fat32_buf);
        struct fat32_dir_entry *dir_entry = (struct fat32_dir_entry *)fat32_buf;
        for (int j = 0; j < fat32_volume.sec_per_cluster * VIRTIO_BLK_SECTOR_SIZE / sizeof(struct fat32_dir_entry); j++)
        {
            if (dir_entry[j].name[0] == 0)
            {
                break;
            }
            // printk("fat32_open_file: dir_entry[%d].name = %s\n", j, dir_entry[j].name);
            if (memcmp(dir_entry[j].name, filename, strlen(filename)) == 0)
            {
                // printk("fat32_open_file: find file %s\n", filename);
                file.cluster = dir_entry[j].startlow | (dir_entry[j].starthi << 16);
                file.dir.cluster = 2;
                file.dir.index = i * FAT32_ENTRY_PER_SECTOR + j;
            }
        }
    }

    return file;
}

uint32_t get_file_len(struct file *file)
{
    uint32_t sectorId = file->fat32_file.dir.index / FAT32_ENTRY_PER_SECTOR;
    virtio_blk_read_sector(cluster_to_sector(file->fat32_file.dir.cluster) + sectorId, fat32_table_buf);
    uint32_t index = file->fat32_file.dir.index % FAT32_ENTRY_PER_SECTOR;
    uint32_t file_len = ((struct fat32_dir_entry *)fat32_table_buf)[index].size;
    return file_len;
}

int64_t fat32_lseek(struct file *file, int64_t offset, uint64_t whence)
{
    if (whence == SEEK_SET)
    {
        file->cfo = offset;
    }
    else if (whence == SEEK_CUR)
    {
        file->cfo = file->cfo + offset;
    }
    else if (whence == SEEK_END)
    {
        /* Calculate file length */
        uint32_t file_len = get_file_len(file);
        file->cfo = file_len + offset;
    }
    else
    {
        printk("fat32_lseek: whence not implemented\n");
        while (1)
            ;
    }
    return file->cfo;
}

uint64_t fat32_table_sector_of_cluster(uint32_t cluster)
{
    return fat32_volume.first_fat_sec + cluster / (VIRTIO_BLK_SECTOR_SIZE / sizeof(uint32_t));
}

int64_t fat32_extend_filesz(struct file *file, uint64_t new_size)
{
    uint64_t sector = cluster_to_sector(file->fat32_file.dir.cluster) + file->fat32_file.dir.index / FAT32_ENTRY_PER_SECTOR;

    virtio_blk_read_sector(sector, fat32_table_buf);
    uint32_t index = file->fat32_file.dir.index % FAT32_ENTRY_PER_SECTOR;
    uint32_t original_file_len = ((struct fat32_dir_entry *)fat32_table_buf)[index].size;
    ((struct fat32_dir_entry *)fat32_table_buf)[index].size = new_size;

    virtio_blk_write_sector(sector, fat32_table_buf);

    uint32_t clusters_required = new_size / (fat32_volume.sec_per_cluster * VIRTIO_BLK_SECTOR_SIZE);
    uint32_t clusters_original = original_file_len / (fat32_volume.sec_per_cluster * VIRTIO_BLK_SECTOR_SIZE);
    uint32_t new_clusters = clusters_required - clusters_original;

    uint32_t cluster = file->fat32_file.cluster;
    while (1)
    {
        uint32_t next_cluster_number = next_cluster(cluster);
        if (next_cluster_number >= 0x0ffffff8)
        {
            break;
        }
        cluster = next_cluster_number;
    }

    for (int i = 0; i < new_clusters; i++)
    {
        uint32_t cluster_to_append;
        for (int j = 2; j < fat32_volume.fat_sz * VIRTIO_BLK_SECTOR_SIZE / sizeof(uint32_t); j++)
        {
            if (next_cluster(j) == 0)
            {
                cluster_to_append = j;
                break;
            }
        }
        uint64_t fat_sector = fat32_table_sector_of_cluster(cluster);
        virtio_blk_read_sector(fat_sector, fat32_table_buf);
        uint32_t index_in_sector = cluster * 4 % VIRTIO_BLK_SECTOR_SIZE;
        *(uint32_t *)(fat32_table_buf + index_in_sector) = cluster_to_append;
        virtio_blk_write_sector(fat_sector, fat32_table_buf);
        cluster = cluster_to_append;
    }

    uint64_t fat_sector = fat32_table_sector_of_cluster(cluster);
    virtio_blk_read_sector(fat_sector, fat32_table_buf);
    uint32_t index_in_sector = cluster * 4 % VIRTIO_BLK_SECTOR_SIZE;
    *(uint32_t *)(fat32_table_buf + index_in_sector) = 0x0fffffff;
    virtio_blk_write_sector(fat_sector, fat32_table_buf);

    return 0;
}

int64_t fat32_read(struct file *file, void *buf, uint64_t len)
{
    uint64_t ret = 0;
    uint64_t now_cluster_cnt = file->cfo / (fat32_volume.sec_per_cluster * VIRTIO_BLK_SECTOR_SIZE);
    uint64_t now_cluster = file->fat32_file.cluster;
    for (int i = 0; i < now_cluster_cnt; i++)
    {
        now_cluster = next_cluster(now_cluster);
    }
    for (; len;)
    {
        uint64_t cluster = now_cluster;
        uint64_t sec = cluster_to_sector(cluster) + file->cfo % (fat32_volume.sec_per_cluster * VIRTIO_BLK_SECTOR_SIZE) / VIRTIO_BLK_SECTOR_SIZE;
        uint64_t offset = file->cfo % VIRTIO_BLK_SECTOR_SIZE;
        uint64_t read_len = VIRTIO_BLK_SECTOR_SIZE - offset;
        if (read_len > len)
        {
            read_len = len;
        }
        uint32_t file_len = get_file_len(file);
        if (file->cfo >= file_len)
        {
            break;
        }
        if (file->cfo + read_len > file_len)
        {
            read_len = file_len - file->cfo;
        }
        if (read_len == 0)
        {  
            break;
        }
        virtio_blk_read_sector(sec, fat32_buf);
        memcpy(buf, fat32_buf + offset, read_len);
        buf += read_len;
        len -= read_len;
        file->cfo += read_len;
        ret += read_len;
        if (file->cfo % (fat32_volume.sec_per_cluster * VIRTIO_BLK_SECTOR_SIZE) == 0)
        {
            now_cluster = next_cluster(now_cluster);
        }
    }
    return ret;
}

int64_t fat32_write(struct file *file, const void *buf, uint64_t len)
{
    uint64_t ret = 0;
    uint64_t now_cluster_cnt = file->cfo / (fat32_volume.sec_per_cluster * VIRTIO_BLK_SECTOR_SIZE);
    uint64_t now_cluster = file->fat32_file.cluster;
    for (int i = 0; i < now_cluster_cnt; i++)
    {
        now_cluster = next_cluster(now_cluster);
    }
    for (; len;)
    {
        uint64_t cluster = now_cluster;
        uint64_t sec = cluster_to_sector(cluster) + file->cfo % (fat32_volume.sec_per_cluster * VIRTIO_BLK_SECTOR_SIZE) / VIRTIO_BLK_SECTOR_SIZE;
        uint64_t offset = file->cfo % VIRTIO_BLK_SECTOR_SIZE;
        uint64_t write_len = VIRTIO_BLK_SECTOR_SIZE - offset;
        if (write_len > len)
        {
            write_len = len;
        }
        if (write_len == 0)
        {
            break;
        }
        virtio_blk_read_sector(sec, fat32_buf);
        memcpy(fat32_buf + offset, buf, write_len);
        virtio_blk_write_sector(sec, fat32_buf);
        buf += write_len;
        len -= write_len;
        file->cfo += write_len;
        ret += write_len;
        if (file->cfo % (fat32_volume.sec_per_cluster * VIRTIO_BLK_SECTOR_SIZE) == 0)
        {
            now_cluster = next_cluster(now_cluster);
        }
    }
    if (file->cfo > get_file_len(file))
    {
        fat32_extend_filesz(file, file->cfo);
    }
    return ret;
}
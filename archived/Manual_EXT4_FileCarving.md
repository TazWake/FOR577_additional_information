# EXT4 Manual File Carving Guide (Including Multi‑Partition Raw Images)

This guide explains how to manually locate and carve a file from an EXT4 filesystem when you only know the inode number. It covers both **single‑partition** images and **multi‑partition** raw images such as GPT layouts.

**Note**: This guide is experimental and needs testing.

---

## 1. Identify the Correct Partition Containing the EXT4 Filesystem

If the raw image has multiple partitions (GPT layout example):

```text
Disk /mnt/ewf/ewf1: 40 GiB
Device             Start      End       Sectors  Size  Type
/mnt/ewf/ewf1p1    227328     83886046  83658719 39.9G Linux filesystem
/mnt/ewf/ewf1p14   2048       10239      8192    4M    BIOS boot
/mnt/ewf/ewf1p15   10240      227327    217088   106M  EFI System
```

Your EXT4 filesystem will almost always be the **Linux filesystem** partition (`ewf1p1`).

**Record the sector offset of that partition:**

- Partition start sector: **227,328**
- Sector size: **512 bytes**
- **Partition byte offset** = `227,328 × 512 = 116,391,936 bytes`  

You **must add this offset** to any calculation when carving from the raw image.

---

## 2. Extract Filesystem Geometry

Run:

```bash
sudo dumpe2fs /dev/mapper/ewf1p1 | grep -E "Block size|Inode size|Inodes per group|Blocks per group"
```

Record:

- Block size (e.g., 4096)
- Inode size (e.g., 256)
- Inodes per group (e.g., 8192)
- Blocks per group

---

## 3. Determine Block Group for Inode 3770

```text
inode = 3770
inode_group      = (inode - 1) / inodes_per_group
index_in_group   = (inode - 1) % inodes_per_group
```

Example (8192 inodes per group):

```text
inode_group = 0
index_in_group = 3769
```

---

## 4. Locate the Inode Table for That Block Group

Run:

```bash
sudo dumpe2fs /dev/mapper/ewf1p1 | grep -A20 "Group 0"
```

Find:

```text
Inode table at BLOCK X
```

Record `inode_table_block`.

---

## 5. Calculate Byte Offset of the Inode Within the Partition

```text
inode_offset =
    inode_table_block * block_size
  + index_in_group * inode_size
```

Example:

```text
inode_table_block = 256
block_size = 4096
inode_size = 256
index = 3769

inode_offset = (256 × 4096) + (3769 × 256)
inode_offset = 1,048,576 + 964,864
inode_offset = 2,013,440 bytes
```

This offset is **relative to the START of the EXT4 partition**.

To read the inode from the raw image:

```text
raw_offset = partition_byte_offset + inode_offset
```

Example:

```text
raw_offset = 116,391,936 + 2,013,440
raw_offset = 118,405,376
```

---

## 6. View the Inode Contents Using `xxd`

```bash
xxd -s 118405376 -l 256 /mnt/ewf/ewf1 > inode3770.hex
```

---

## 7. Parse the EXT4 Extent Tree

At offset **0x28** inside the inode:

```text
0x00–0x01  mode
0x04–0x07  size_lo
…
0x28–0x33  extent header (eh_magic, entries, max, depth, generation)
0x34–0x3F  first extent or extent_idx
```

For leaf extents (`eh_depth = 0`), each extent has:

```text
ee_block    (logical block offset)
ee_len      (number of blocks)
ee_start    (physical block number on disk)
```

---

## 8. Convert Physical Block to Byte Offset

For each extent:

```text
extent_offset = (ee_start × block_size)
extent_length_bytes = (ee_len × block_size)
```

Then add the **partition offset**:

```text
raw_extent_offset = partition_offset + extent_offset
```

---

## 9. Carve the File Data Using `xxd`

Example:

```bash
xxd -s  raw_extent_offset  -l extent_length_bytes  /mnt/ewf/ewf1 > part1.bin
```

Repeat this for each extent.

Then reconstruct the file:

```bash
cat part1.bin part2.bin part3.bin > recovered_file
```

---

## 10. Optional: Verify Against Mounted Filesystem

```bash
sha256sum recovered_file
sha256sum /mnt/ewf1/path/to/file
```

---

## Summary Workflow

1. Identify the Linux partition  
2. Compute the partition byte offset  
3. Calculate inode location  
4. Parse extent tree  
5. Convert extents → disk offsets  
6. Use `xxd` to carve  

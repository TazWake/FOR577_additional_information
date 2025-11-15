# EXT4 Manual File Extraction Cheat Sheet

(Full disk image -> known inode -> recover file in hex)

This guide assumes:

- A **full disk image** (e.g., disk.img)
- EXT4 filesystem with an intact superblock
- You know the **inode number** of the target file
- You can use `xxd`, `dd`, or any hex editor

---

## 0. Identify filesystem offset (if full disk image)

```bash
fdisk -l disk.img
```

Compute filesystem offset:

```bash
FS_OFFSET = start_sector * sector_size
```

---

## 1. Read the superblock (1024 bytes from FS start)

```bash
xxd -g4 -s $((FS_OFFSET + 1024)) -l 2048 disk.img
```

Extract:

- `s_inodes_per_group`
- `s_inode_size`
- `s_blocks_per_group`
- `s_log_block_size`

Compute:

```bash
BLOCK_SIZE = 1024 << s_log_block_size
```

---

## 2. Determine inode’s block group + index

Given INO = inode number:

```bash
GROUP = (INO - 1) / s_inodes_per_group
INDEX = (INO - 1) % s_inodes_per_group
```

---

## 3. Locate the group descriptor

Group descriptor table starts at:

- block 2 (if BLOCK_SIZE = 1024)
- block 1 (if BLOCK_SIZE ≥ 2048)

Compute:

```bash
GD_TABLE_OFFSET = FS_OFFSET + (GD_BLOCK * BLOCK_SIZE)
GD_OFFSET = GD_TABLE_OFFSET + GROUP * 32
```

View descriptor:

```bash
xxd -g4 -s $GD_OFFSET -l 64 disk.img
```

Extract:

```bash
bg_inode_table  (start block of inode table)
```

---

## 4. Locate the inode on disk

Compute inode table offset:

```bash
INODE_TABLE_OFFSET = FS_OFFSET + (bg_inode_table * BLOCK_SIZE)
```

Then:

```bash
INODE_OFFSET = INODE_TABLE_OFFSET + INDEX * s_inode_size
```

Dump inode:

```bash
xxd -g4 -s $INODE_OFFSET -l $s_inode_size disk.img
```

Identify:

- File size (`i_size`)
- EXTENTS flag (0x80000)
- `i_block` content (extent tree or block pointers)

---

## 5. Parse extents (normal EXT4 case)

Extent header in `i_block`:

```bash
eh_magic = 0xf30a
eh_entries = number of extents
eh_depth = 0 for leaf nodes
```

Each extent entry:

```bash
ee_block     = logical block index
ee_len       = number of blocks
ee_start_lo  = first physical block (low)
ee_start_hi  = first physical block (high)
```

Physical block:

```bash
PHYS = (ee_start_hi << 32) | ee_start_lo
```

---

## 6. Convert block numbers -> byte offsets

For each extent:

```bash
DATA_OFFSET = FS_OFFSET + (PHYS * BLOCK_SIZE)
```

Extract N blocks (until full file size obtained):

```bash
dd if=disk.img of=output.bin bs=$BLOCK_SIZE    skip=$((PHYS + (FS_OFFSET / BLOCK_SIZE))) count=$BLOCKS
```

For multiple extents:

- Process in order of `ee_block`
- Concatenate extracted parts
- Trim final file to `i_size` bytes

---

## 7. Legacy non-extent inodes

If EXTENTS flag is **not** set:

- `i_block` contains:
  - 12 direct blocks
  - 1 single indirect
  - 1 double indirect
  - 1 triple indirect
Use same "block -> byte offset" mapping.

---

## 8. Forensic notes

- btime/mtime/ctime come from **inode**, not journal.
- Deleted files: inode may point to reallocated extents.
- Sparse files: extents may represent holes.

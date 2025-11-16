# XFS Manual File Extraction Cheat Sheet

(Full disk image -> known inode -> recover file manually via hex)

This guide assumes:

- A **full disk image** (e.g., disk.img)
- An intact XFS superblock
- You know the **inode number** or have located the inode record
- You can use `xxd`, `dd`, or any hex editor
- Focus on **XFS v5** (most common on modern Linux)

---

## 0. Identify filesystem offset (if full disk image)

If the disk image contains partitions:

```bash
fdisk -l disk.img
```

Compute filesystem offset:

```bash
FS_OFFSET = start_sector * sector_size
```

For a pure XFS filesystem image:

```bash
FS_OFFSET = 0
```

---

## 1. Locate and read the XFS superblock

Primary superblock is always at **byte offset 0** of the filesystem.

```bash
xxd -g4 -s $FS_OFFSET -l 512 disk.img
```

Extract important fields:

- `sb_inodesize`
- `sb_blocksize`
- `sb_agcount`
- `sb_agblocks`
- `sb_inopblock` = blocksize / inodesize

---

## 2. Understand the XFS layout (Allocation Groups)

XFS splits the volume into **AGs (allocation groups)**.

Each AG contains:

- AG Superblock
- AG Free space structures
- AG Inode B+trees
- Inode chunks

Compute AG size:

```bash
AG_SIZE = sb_agblocks * sb_blocksize
```

Compute any AG's base offset:

```bash
AG_OFFSET = FS_OFFSET + (AG_number * AG_SIZE)
```

---

## 3. If you have the inode number -> Determine AG + index

XFS inode numbers encode the AG:

```bash
AG = inode_number >> sb_inopblog
AG_inode_index = inode_number & ((1 << sb_inopblog) - 1)
```

Common shortcut:

```bash
AG = inode_number / inodes_per_AG
INDEX = inode_number % inodes_per_AG
```

---

## 4. Locate the inode chunk

XFS allocates inodes in **chunks of 64 inodes**, stored consecutively.

Use the AG Inode B+tree root:

AGI header is always at:

```bash
AGI = AG_OFFSET + (sector_size * 2)
```

Dump AGI:

```bash
xxd -g4 -s $AGI -l 256 disk.img
```

Extract:

- `agi_root`  (root of the inode B+tree)
- `agi_level` (tree height)

---

## 5. Walk the inode B+tree (if needed)

If `agi_level = 1`:

- Directly contains inode chunk records.

If greater:

- Walk internal nodes like any B+tree:
  - Compare inode numbers
  - Follow the appropriate block pointer (`bc_ptrs[]`)

Each inode chunk record contains:

- Base inode number of chunk
- Disk block address of the inode chunk

---

## 6. Compute the inode's byte offset

Once you know the block containing the 64-inode chunk:

```bash
INODE_CHUNK_BLOCK = value_from_btree_record
INODE_CHUNK_OFFSET = AG_OFFSET + (INODE_CHUNK_BLOCK * sb_blocksize)
```

Compute inode's position inside the chunk:

```bash
INODE_OFFSET = INODE_CHUNK_OFFSET + (INDEX_within_chunk * sb_inodesize)
```

Dump inode:

```bash
xxd -g4 -s $INODE_OFFSET -l $sb_inodesize disk.img
```

---

## 7. Parse the inode core + data fork

XFS inode has:

- **Core header** (timestamps, mode, size, flags)
- **Data fork** (depending on format)

Check the **format type**:

- `XFS_DINODE_FMT_EXTENTS` -> extents directly in inode
- `XFS_DINODE_FMT_BTREE`   -> extent pointers in B+tree
- `XFS_DINODE_FMT_LOCAL`   -> small file stored inline

---

## 8. Extract data from extent-based file (most common)

Each extent structure contains:

- Starting file offset (logical)
- Starting block (physical)
- Length in blocks

Compute block -> byte offset:

```bash
DATA_OFFSET = FS_OFFSET + (physical_block * sb_blocksize)
```

Extract data:

```bash
dd if=disk.img of=extracted.bin    bs=$sb_blocksize skip=$physical_block count=$num_blocks
```

Concatenate all extents in logical order and trim to inode's file size.

---

## 9. Extract small "local-format" files

These live entirely inside the inode data fork.

Dump directly from the inode:

```bash
xxd -s (INODE_OFFSET + data_fork_offset) -l file_size disk.img
```

---

## 10. Extract from B-tree files (large fragmented files)

If file uses B-tree extents:

- Walk leaf level blocks from the B-tree root in order.
- Each leaf block contains extent records.
- Extract each extent as in step #8.

---

## 11. Forensic notes (important)

- XFS does NOT journal file content - only metadata.
- Deleted file recovery is difficult unless inode chunk not overwritten.
- Extents may be reallocated immediately after deletion.
- XFS aggressively reuses freed space -> carved files often corrupted.
- Timestamps include:
  - atime, mtime, ctime
  - **crtime** (creation time) - XFS always supports it.

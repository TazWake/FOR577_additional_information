# EXT4 Advanced Forensics Guide

## Purpose

This guide covers **advanced EXT4 forensics techniques** for complex recovery scenarios including multi-partition disk images, manual extent tree parsing, raw hex carving, and situations where standard tools fail.

**When to use this guide:**
- Working with multi-partition raw disk images (GPT, MBR layouts)
- Standard tools (debugfs, extundelete) are unavailable or failing
- Filesystem is severely corrupted and requires manual parsing
- Need to understand extent tree structures for expert testimony
- Recovering files from fragmented or non-contiguous blocks
- Educational purposes to understand EXT4 internals

**When NOT to use this guide:**
- Simple file recovery with known inode (see [EXT4_BasicFileRecovery.md](EXT4_BasicFileRecovery.md))
- Deleted file recovery with working journal (see [EXT4_DeletedFileCarving.md](EXT4_DeletedFileCarving.md))

## Prerequisites

- **Expert-level:** This guide requires deep understanding of filesystem structures
- Root/sudo access
- `xxd` or `hexdump` for hex parsing
- `dd` for block extraction
- Calculator for offset arithmetic (or `bc` command)
- Patience and attention to detail

**WARNING:** These techniques are complex and error-prone. Always work on forensic copies. Verify results whenever possible.

## Table of Contents

- [Understanding Multi-Partition Images](#understanding-multi-partition-images)
- [EXT4 Extent Tree Deep Dive](#ext4-extent-tree-deep-dive)
- [Step-by-Step: Manual File Carving from Multi-Partition Image](#step-by-step-manual-file-carving-from-multi-partition-image)
- [Advanced Tools and Techniques](#advanced-tools-and-techniques)
- [Filesystem Integrity and Metadata Analysis](#filesystem-integrity-and-metadata-analysis)
- [Troubleshooting Complex Scenarios](#troubleshooting-complex-scenarios)
- [Glossary](#glossary)

---

## Understanding Multi-Partition Images

### Partition Table Types

#### GPT (GUID Partition Table)

Modern partition scheme supporting large disks (>2TB) and many partitions.

**Example GPT layout:**
```
Disk /mnt/ewf/ewf1: 40 GiB, 42949672960 bytes
Disklabel type: gpt

Device             Start      End       Sectors  Size  Type
/mnt/ewf/ewf1p1    227328     83886046  83658719 39.9G Linux filesystem
/mnt/ewf/ewf1p14   2048       10239      8192    4M    BIOS boot
/mnt/ewf/ewf1p15   10240      227327    217088   106M  EFI System
```

**Key fields:**
- **Start:** First sector of partition
- **End:** Last sector of partition
- **Sectors:** Total sectors in partition
- **Size:** Human-readable size
- **Type:** Partition type (Linux filesystem = EXT4/XFS/etc.)

#### MBR (Master Boot Record)

Legacy partition scheme, limited to 2TB and 4 primary partitions.

**Example MBR layout:**
```
Device        Boot    Start      End      Sectors   Size  Id Type
image.dd1     *       2048       1050623  1048576   512M  83 Linux
image.dd2             1050624    83886079 82835456  39.5G 83 Linux
```

### Identifying the EXT4 Partition

**View partition table:**
```bash
# GPT partitions
sudo fdisk -l /path/to/image.dd

# Or use parted
sudo parted /path/to/image.dd print
```

**Identify EXT4 filesystem:**
```bash
# Scan for filesystem signatures
sudo file -s /path/to/image.dd

# Check specific partition offset
sudo blkid -p -o value -s TYPE --offset $((START_SECTOR * 512)) /path/to/image.dd
```

**Look for:**
- Type: "Linux filesystem" (GPT) or "83" (MBR)
- Usually the largest partition
- Not "BIOS boot", "EFI System", or "swap"

### Calculating Partition Byte Offset

**Critical for all subsequent operations:**

```
Partition byte offset = Start sector × Sector size
```

**Standard sector size:** 512 bytes (verify with `fdisk -l`)

**Example:**
```
Start sector: 227,328
Sector size: 512 bytes
Partition offset = 227,328 × 512 = 116,391,936 bytes
```

**Why this matters:**
- All filesystem offsets are relative to **partition start**
- When working with full disk images, add partition offset
- Single-partition images have offset = 0

---

## EXT4 Extent Tree Deep Dive

### Extent vs. Indirect Block Pointers

**Legacy (EXT2/EXT3):** Used indirect block pointers
- Inefficient for large files
- Required multiple levels of indirection
- Limited file size

**Modern (EXT4):** Uses extent trees
- Efficient: Each extent covers contiguous block range
- Format: `(logical_block_start-logical_block_end): physical_block_start-physical_block_end`
- Example: `(0-127): 10485760-10485887` means 128 blocks starting at block 10485760

### Extent Header Structure

Located at offset **0x28** (40 bytes) within inode:

```
Offset  Size  Field         Description
0x00    2     eh_magic      Magic number (0xF30A)
0x02    2     eh_entries    Number of valid entries
0x04    2     eh_max        Maximum entries this node can hold
0x06    2     eh_depth      Tree depth (0=leaf, >0=index node)
0x08    2     eh_generation Generation counter
```

**Verify extent tree:**
```bash
# Extract inode and check for magic number 0xF30A at offset 0x28
xxd -s $INODE_OFFSET -l 256 image.dd | grep -A1 "0028:"
```

### Extent Entry Structure (Leaf Node)

Each extent entry is **12 bytes** (if `eh_depth = 0`):

```
Offset  Size  Field      Description
0x00    4     ee_block   First logical block covered
0x04    2     ee_len     Number of blocks covered (max 32768)
0x06    2     ee_start_hi High 16 bits of physical block (for >2TB)
0x08    4     ee_start_lo Low 32 bits of physical block
```

**Calculate physical block number:**
```
physical_block = (ee_start_hi << 32) | ee_start_lo
```

For filesystems <2TB, `ee_start_hi` is usually 0.

### Extent Index Node (Internal Node)

If `eh_depth > 0`, entries are **12-byte index entries** pointing to child nodes:

```
Offset  Size  Field      Description
0x00    4     ei_block   First logical block in subtree
0x04    2     ei_leaf_lo Low 32 bits of child node block
0x06    2     ei_leaf_hi High 16 bits of child node block
0x08    4     ei_unused  Unused
```

**Navigate extent tree:**
1. Start at inode extent header
2. If `eh_depth = 0`, entries are leaf extents (actual data locations)
3. If `eh_depth > 0`, entries point to child nodes
4. Read child node, repeat until `eh_depth = 0`

### Practical Example: Parsing Extent Tree

**Inode hex dump (starting at extent header offset 0x28):**
```
0028: 0a f3 02 00 04 00 00 00  00 00 00 00 00 00 00 00
0038: 00 00 00 00 80 00 00 00  a0 00 00 00 00 9f ff 00
```

**Parse header (offset 0x28-0x37):**
- `0a f3` = 0xF30A (magic - correct!)
- `02 00` = 2 entries
- `04 00` = max 4 entries
- `00 00` = depth 0 (leaf node)

**Parse first extent (offset 0x38-0x43):**
- `00 00 00 00` = ee_block (logical block 0)
- `80 00` = ee_len (128 blocks)
- `00 00` = ee_start_hi (0)
- `a0 00 9f 00` = ee_start_lo (10485760 in little-endian)

**Interpretation:**
- Logical blocks 0-127 (first 128 blocks of file)
- Stored at physical blocks 10485760-10485887
- With 4KB blocks, this is 512KB of data

---

## Step-by-Step: Manual File Carving from Multi-Partition Image

### Scenario

**You have:**
- Full disk image: `/mnt/ewf/ewf1` (40 GB, GPT layout)
- Target partition: `/mnt/ewf/ewf1p1` (starts at sector 227328)
- Target inode: 3770
- No access to debugfs/mount capabilities

**Goal:** Manually carve the file using only `xxd`, `dd`, and `dumpe2fs`.

### Step 1: Calculate Partition Offset

```bash
# From partition table
START_SECTOR=227328
SECTOR_SIZE=512

# Calculate byte offset
PARTITION_OFFSET=$((START_SECTOR * SECTOR_SIZE))
echo "Partition starts at byte: $PARTITION_OFFSET"
# Output: 116391936
```

### Step 2: Extract Filesystem Geometry

**If you can mount the partition:**
```bash
sudo dumpe2fs /dev/mapper/ewf1p1 | grep -E "Block size|Inode size|Inodes per group"
```

**If partition isn't mountable, read superblock manually:**

Superblock is at offset 1024 bytes from partition start.

```bash
# Extract superblock
SUPERBLOCK_OFFSET=$((PARTITION_OFFSET + 1024))
sudo xxd -s $SUPERBLOCK_OFFSET -l 1024 /mnt/ewf/ewf1 > superblock.hex

# Parse key fields (example for reference)
# Offset 0x18: s_inodes_per_group (4 bytes)
# Offset 0x1C: s_blocks_per_group (4 bytes)
# Offset 0x58: s_inode_size (2 bytes)
```

**For this example, assume:**
- Block size: 4096 bytes
- Inode size: 256 bytes
- Inodes per group: 8192

### Step 3: Calculate Inode Group and Index

```bash
INODE=3770
INODES_PER_GROUP=8192

# Calculate block group
INODE_GROUP=$(( (INODE - 1) / INODES_PER_GROUP ))
echo "Inode $INODE is in block group: $INODE_GROUP"
# Output: 0

# Calculate index within group
INDEX_IN_GROUP=$(( (INODE - 1) % INODES_PER_GROUP ))
echo "Index within group: $INDEX_IN_GROUP"
# Output: 3769
```

### Step 4: Locate Inode Table for Block Group

**Using dumpe2fs:**
```bash
sudo dumpe2fs /dev/mapper/ewf1p1 | grep -A20 "Group 0" | grep "Inode table"
```

**Example output:**
```
Inode table at 256-511 (bg #0 + 256)
```

**Record:** `inode_table_block = 256`

**If dumpe2fs unavailable, parse group descriptor:**
Group descriptor table starts after superblock. Each group descriptor is 64 bytes (EXT4) or 32 bytes (EXT3).

### Step 5: Calculate Inode Byte Offset Within Partition

```bash
INODE_TABLE_BLOCK=256
BLOCK_SIZE=4096
INODE_SIZE=256
INDEX=3769

# Inode offset within partition
INODE_OFFSET=$(( (INODE_TABLE_BLOCK * BLOCK_SIZE) + (INDEX * INODE_SIZE) ))
echo "Inode offset within partition: $INODE_OFFSET bytes"
# Output: 2013440

# Inode offset within full disk image
RAW_INODE_OFFSET=$(( PARTITION_OFFSET + INODE_OFFSET ))
echo "Inode offset in disk image: $RAW_INODE_OFFSET bytes"
# Output: 118405376
```

### Step 6: Extract Inode with xxd

```bash
# Extract 256-byte inode
sudo xxd -s $RAW_INODE_OFFSET -l 256 /mnt/ewf/ewf1 > inode3770.hex

# View inode
cat inode3770.hex | less
```

### Step 7: Parse Extent Tree from Inode

**Locate extent header at offset 0x28 within inode:**

```bash
# View extent header area
cat inode3770.hex | grep -A8 "0028:"
```

**Example output:**
```
00000028: 0a f3 02 00 04 00 00 00  00 00 00 00 01 00 04 00  ................
00000038: 00 00 00 00 80 00 00 00  20 00 a0 00 00 00 00 00  ........ .......
00000048: 80 00 00 00 20 00 00 00  21 00 a0 00 00 00 00 00  .... ...!.......
```

**Parse header (bytes 0-15 of extent area):**
- Magic: `0a f3` → 0xF30A ✓
- Entries: `02 00` → 2 extents
- Max: `04 00` → 4 max entries
- Depth: `00 00` → 0 (leaf)

**Parse first extent (bytes 16-27 of extent area):**
```
00 00 00 00  = ee_block (logical block 0)
80 00        = ee_len (128 blocks, little-endian = 0x0080)
00 00        = ee_start_hi (0)
20 00 a0 00  = ee_start_lo (little-endian = 0x00a00020 = 10485792)
```

**Parse second extent:**
```
80 00 00 00  = ee_block (logical block 128)
20 00        = ee_len (32 blocks)
00 00        = ee_start_hi (0)
21 00 a0 00  = ee_start_lo (little-endian = 0x00a00021 = 10485793)
```

**Little-endian conversion example:**
```
20 00 a0 00 (hex bytes)
→ Reverse byte order: 00 a0 00 20
→ Decimal: 10,485,792
```

### Step 8: Convert Physical Blocks to Byte Offsets

For each extent, calculate where data resides on disk:

**Extent 1:**
```bash
PHYSICAL_BLOCK_1=10485792
BLOCK_COUNT_1=128
BLOCK_SIZE=4096

# Offset within partition
EXTENT1_PARTITION_OFFSET=$(( PHYSICAL_BLOCK_1 * BLOCK_SIZE ))
EXTENT1_LENGTH=$(( BLOCK_COUNT_1 * BLOCK_SIZE ))

echo "Extent 1 partition offset: $EXTENT1_PARTITION_OFFSET"
# Output: 42965630976

# Offset within full disk image
EXTENT1_RAW_OFFSET=$(( PARTITION_OFFSET + EXTENT1_PARTITION_OFFSET ))
echo "Extent 1 raw offset: $EXTENT1_RAW_OFFSET"
# Output: 43082022912

echo "Extent 1 length: $EXTENT1_LENGTH bytes"
# Output: 524288 (512 KB)
```

**Extent 2:**
```bash
PHYSICAL_BLOCK_2=10485793
BLOCK_COUNT_2=32

EXTENT2_PARTITION_OFFSET=$(( PHYSICAL_BLOCK_2 * BLOCK_SIZE ))
EXTENT2_LENGTH=$(( BLOCK_COUNT_2 * BLOCK_SIZE ))
EXTENT2_RAW_OFFSET=$(( PARTITION_OFFSET + EXTENT2_PARTITION_OFFSET ))

echo "Extent 2 raw offset: $EXTENT2_RAW_OFFSET"
# Output: 43082026912

echo "Extent 2 length: $EXTENT2_LENGTH bytes"
# Output: 131072 (128 KB)
```

### Step 9: Carve File Data with xxd

**Extract each extent:**

```bash
# Extent 1 (first 512 KB of file)
sudo xxd -s $EXTENT1_RAW_OFFSET -l $EXTENT1_LENGTH /mnt/ewf/ewf1 > extent1.bin

# Extent 2 (next 128 KB of file)
sudo xxd -s $EXTENT2_RAW_OFFSET -l $EXTENT2_LENGTH /mnt/ewf/ewf1 > extent2.bin
```

**Alternative using dd (faster for large files):**
```bash
# Calculate skip blocks for dd
EXTENT1_SKIP_BLOCKS=$(( EXTENT1_RAW_OFFSET / 4096 ))
EXTENT1_COUNT=128

sudo dd if=/mnt/ewf/ewf1 bs=4096 skip=$EXTENT1_SKIP_BLOCKS count=$EXTENT1_COUNT of=extent1.bin

EXTENT2_SKIP_BLOCKS=$(( EXTENT2_RAW_OFFSET / 4096 ))
EXTENT2_COUNT=32

sudo dd if=/mnt/ewf/ewf1 bs=4096 skip=$EXTENT2_SKIP_BLOCKS count=$EXTENT2_COUNT of=extent2.bin
```

### Step 10: Reconstruct File

**Concatenate extents in logical order:**

```bash
# Extents MUST be in logical block order
cat extent1.bin extent2.bin > recovered_file_inode3770.bin

# Verify file size
ls -lh recovered_file_inode3770.bin

# Check file type
file recovered_file_inode3770.bin

# Calculate hash
sha256sum recovered_file_inode3770.bin
```

### Step 11: Verify Recovery (if possible)

**If you can mount the filesystem:**
```bash
# Mount read-only
sudo mount -o ro /dev/mapper/ewf1p1 /mnt/evidence

# Find original file (if not deleted)
sudo debugfs -R "ncheck <3770>" /dev/mapper/ewf1p1

# Compare hashes
sha256sum /mnt/evidence/path/to/file
sha256sum recovered_file_inode3770.bin
```

---

## Advanced Tools and Techniques

### Using losetup with Partition Offsets

Mount specific partition from multi-partition image:

```bash
# Calculate offset in bytes
PARTITION_START_SECTOR=227328
SECTOR_SIZE=512
OFFSET=$(( PARTITION_START_SECTOR * SECTOR_SIZE ))

# Create loop device at partition offset
sudo losetup --find --show --offset $OFFSET /path/to/disk_image.dd
# Output: /dev/loop0

# Now use standard tools
sudo debugfs /dev/loop0
sudo dumpe2fs /dev/loop0

# Cleanup when done
sudo losetup -d /dev/loop0
```

### Extended Attributes and Metadata

EXT4 supports extended attributes (ACLs, capabilities, SELinux labels).

**View extended attributes on mounted filesystem:**
```bash
# List all extended attributes
sudo getfattr -d -m '.*' /path/to/file

# View specific attributes
sudo getfattr -n security.selinux /path/to/file
sudo getfattr -n security.capability /path/to/file
```

**Check file attributes (immutable, append-only, etc.):**
```bash
sudo lsattr /path/to/file
```

**Attribute flags:**
- `i` - Immutable (cannot be modified, deleted, or renamed)
- `a` - Append-only
- `e` - Extent format (uses extent tree)
- `s` - Secure deletion (overwrite on delete)
- `u` - Undeletable (prevent deletion)

### Analyzing EXT4 Features

**Check filesystem features:**
```bash
sudo tune2fs -l /dev/loop0p1 | grep 'Filesystem features'
```

**Key features:**
- `extent` - Uses extent trees (EXT4)
- `flex_bg` - Flexible block groups
- `64bit` - Supports filesystems >16TB
- `metadata_csum` - Metadata checksumming (integrity)
- `encrypt` - Filesystem-level encryption support

**Implications for recovery:**
- `encrypt`: Data may be encrypted, recovery requires keys
- `metadata_csum`: Can verify inode/extent tree integrity
- `64bit`: Physical block numbers can be >32 bits

---

## Filesystem Integrity and Metadata Analysis

### Read-Only Filesystem Check

**Always run fsck in read-only mode on evidence:**

```bash
# EXT4 filesystem check (read-only, no modifications)
sudo fsck.ext4 -n /dev/loop0p1

# More verbose
sudo fsck.ext4 -n -v /dev/loop0p1
```

**Flags:**
- `-n` - No modifications (read-only check)
- `-v` - Verbose output
- `-f` - Force check even if filesystem appears clean

**What to look for:**
- Inode errors (corruption indicators)
- Block allocation mismatches
- Orphaned inodes
- Filesystem inconsistencies

### Extract Metadata-Only Image

Create lightweight metadata image for analysis:

```bash
# Create metadata image (no data blocks)
sudo e2image -r /dev/loop0p1 /cases/metadata_image.img

# Much smaller than full image
ls -lh /cases/metadata_image.img

# Can be analyzed with debugfs
sudo debugfs /cases/metadata_image.img
```

**Use cases:**
- Faster analysis (no data blocks)
- Share filesystem structure without sensitive data
- Preserve metadata for later analysis

### Filesystem Timeline Analysis

**Extract all timestamps:**
```bash
# Mount read-only
sudo mount -o ro /dev/loop0p1 /mnt/evidence

# Use find to extract all timestamps
sudo find /mnt/evidence -printf "%T@ %p\n" | sort -n > filesystem_timeline.txt

# Or with full timestamp details
sudo find /mnt/evidence -printf "%T+ %p\n" > timeline_readable.txt
```

**For deleted files, extract from inode tables (complex).**

---

## Troubleshooting Complex Scenarios

### Corrupted Extent Trees

**Symptoms:**
- debugfs reports extent errors
- File size doesn't match recovered data
- Extent magic number (0xF30A) not found

**Solutions:**
1. **Check for indirect block pointers** (legacy format):
   - If no extent header, file may use old format
   - Requires parsing indirect, double-indirect, triple-indirect blocks

2. **Attempt partial recovery:**
   - Even with corrupt extent tree, some extents may be valid
   - Parse each extent separately, skip corrupt entries

3. **Use file carving tools:**
   - photorec, scalpel, foremost
   - Signature-based carving doesn't rely on filesystem metadata

### Large Files (>4GB)

**Challenges:**
- Multiple extent entries (more parsing)
- May have index nodes (eh_depth > 0)
- Block numbers may require 64-bit addressing

**Solutions:**
```bash
# Check for 64-bit feature
sudo tune2fs -l /dev/loop0p1 | grep -i 64bit

# When parsing extents, combine hi and lo words:
physical_block = (ee_start_hi << 32) | ee_start_lo
```

### Fragmented Files

**Symptoms:**
- Many extent entries
- Non-contiguous physical blocks

**Solutions:**
- Extract each extent separately
- Verify logical block order matches file layout
- Concatenate in correct sequence

**Example with 5 extents:**
```bash
# Extract all extents
for i in {1..5}; do
  # Calculate offset and length for extent $i
  # Extract to extent_$i.bin
done

# Concatenate in logical order
cat extent_1.bin extent_2.bin extent_3.bin extent_4.bin extent_5.bin > recovered.bin
```

### Filesystem Encryption

**EXT4 filesystem-level encryption (fscrypt):**

**Detection:**
```bash
sudo tune2fs -l /dev/loop0p1 | grep -i encrypt
```

**If present:**
- Individual files/directories can be encrypted
- Recovery requires encryption keys (typically stored in kernel keyring)
- Without keys, data is unrecoverable
- Metadata (filenames, sizes in some cases) may still be visible

**Encrypted file indicators:**
- Filenames may appear as random strings
- File contents are encrypted (no recognizable signatures)

---

## Glossary

**Allocation Group (AG)** - XFS equivalent to EXT4 block groups (not applicable to EXT4).

**Block Group** - EXT filesystems divide disk into groups, each with its own inode table and data blocks.

**Extent** - Contiguous range of blocks; EXT4 uses extent trees for efficient large file storage.

**Extent Index (ei)** - Entry in internal extent tree node pointing to child node.

**Extent Leaf (ee)** - Entry in leaf extent tree node pointing to actual data blocks.

**Little-Endian** - Byte ordering where least significant byte comes first (used by x86/x86-64).

**GPT (GUID Partition Table)** - Modern partition scheme supporting large disks and many partitions.

**MBR (Master Boot Record)** - Legacy partition scheme limited to 2TB and 4 primary partitions.

**Partition Offset** - Byte offset from start of disk to start of partition.

**Sector** - Smallest addressable unit on disk (typically 512 or 4096 bytes).

**Superblock** - Critical filesystem structure at offset 1024, contains geometry and state.

---

## Related Documentation

**Prerequisites:**
- [EXT4_BasicFileRecovery.md](EXT4_BasicFileRecovery.md) - Start here for simple recovery scenarios
- [EXT4_DeletedFileCarving.md](EXT4_DeletedFileCarving.md) - Deleted file recovery techniques

**Related Filesystems:**
- [Manual_XFS_File_Extraction_CheatSheet.md](Manual_XFS_File_Extraction_CheatSheet.md) - XFS manual recovery techniques

**External Resources:**
- EXT4 Disk Layout: https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout
- EXT4 Data Structures: https://www.kernel.org/doc/html/latest/filesystems/ext4/

---

**Part of FOR577 Additional Information**
These materials support **SANS FOR577: Linux Incident Response and Threat Hunting**.

---

**Document Version:** 1.0
**Last Updated:** 2025
**Maintained by:** FOR577 Instruction Team

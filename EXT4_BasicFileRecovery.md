# EXT4 Basic File Recovery Guide

## Purpose

This guide covers **quick file recovery** from EXT4 filesystems when you know the inode number of the file you want to recover. Use this guide for straightforward recovery scenarios on single-partition images or mounted filesystems.

**When to use this guide:**
- You have an inode number and need to recover the file quickly
- You want to extract file metadata and timestamps
- You're working with a single-partition disk image or mounted filesystem
- You need basic filesystem information for your report

**When NOT to use this guide:**
- Recovering deleted files (see [EXT4_DeletedFileCarving.md](EXT4_DeletedFileCarving.md))
- Multi-partition images requiring offset calculations (see [EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md))
- Manual extent tree parsing or raw hex carving (see [EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md))

## Prerequisites

- Root or sudo access
- `e2fsprogs` package installed (dumpe2fs, debugfs, tune2fs)
- Disk image mounted as loop device or direct access to partition device

## Table of Contents

- [Quick Start](#quick-start)
- [Step 1: Identify Filesystem](#step-1-identify-filesystem)
- [Step 2: Get Filesystem Information](#step-2-get-filesystem-information)
- [Step 3: Inspect Inode Metadata](#step-3-inspect-inode-metadata)
- [Step 4: Recover File Contents](#step-4-recover-file-contents)
- [Additional Useful Commands](#additional-useful-commands)
- [Troubleshooting](#troubleshooting)
- [Glossary](#glossary)

---

## Quick Start

If you already know the inode number and have the filesystem accessible:

```bash
# View inode metadata
sudo debugfs -R "stat <inode_number>" /dev/loop0p1

# Recover the file
sudo debugfs -R "dump <inode_number> recovered_file.bin" /dev/loop0p1
```

Replace `/dev/loop0p1` with your actual device and `<inode_number>` with the target inode.

---

## Step 1: Identify Filesystem

Before working with an EXT4 filesystem, confirm the filesystem type and locate the correct partition.

### Identify Filesystem Type

Use `blkid` to verify the filesystem type:

```bash
sudo blkid /dev/loop0p1
```

**Expected output:**
```
/dev/loop0p1: UUID="abc123..." TYPE="ext4" PARTUUID="xyz789..."
```

Verify `TYPE="ext4"` (or `ext3` for older filesystems).

### Locate Partitions in Multi-Partition Images

If working with a full disk image (not just a partition):

```bash
sudo fdisk -l image.dd
```

or

```bash
sudo parted image.dd print
```

**Example output:**
```
Device        Start      End       Sectors  Size  Type
image.dd1     2048       1050623   1048576  512M  EFI System
image.dd2     1050624    83886079  82835456 39.5G Linux filesystem
```

The **Linux filesystem** partition is your EXT4 filesystem.

### Mount Image as Loop Device

If you have a partition image or need to access a specific partition:

```bash
# For single-partition image
sudo losetup --find --show filesystem.dd
# Output: /dev/loop0

# For multi-partition image with partition 2
sudo losetup --find --show --partscan disk.dd
# Output: /dev/loop0
# Partitions appear as /dev/loop0p1, /dev/loop0p2, etc.
```

---

## Step 2: Get Filesystem Information

Understanding filesystem geometry is essential for forensic documentation and troubleshooting.

### Display Superblock Information

Use `dumpe2fs` to view comprehensive filesystem metadata:

```bash
sudo dumpe2fs -h /dev/loop0p1
```

**Key fields to record:**

| Field | Purpose | Example Value |
|-------|---------|---------------|
| Block count | Total filesystem blocks | 10485760 |
| Block size | Size of each block (bytes) | 4096 |
| Inode count | Total inodes | 2621440 |
| Inode size | Size of each inode (bytes) | 256 |
| Inodes per group | Inodes in each block group | 8192 |
| Blocks per group | Blocks in each block group | 32768 |
| First block | Starting block number | 0 |

**Forensic notes:**
- Block size is typically 4096 bytes (4K)
- Inode size is typically 128 or 256 bytes
- These values are needed for manual calculations (see Advanced guide)

### Check Last Mount and Write Times

Verify when the filesystem was last accessed:

```bash
sudo tune2fs -l /dev/loop0p1 | grep -E 'Last (mount|write) time'
```

**Example output:**
```
Last mount time:          Mon Nov 20 14:32:15 2023
Last write time:          Mon Nov 20 14:35:42 2023
```

**Forensic relevance:**
- Last mount time indicates when filesystem was last accessed
- Last write time shows most recent modification
- Critical for timeline reconstruction

### View Filesystem Features

Check enabled filesystem features:

```bash
sudo tune2fs -l /dev/loop0p1 | grep 'Filesystem features'
```

**Example output:**
```
Filesystem features:      has_journal ext_attr resize_inode dir_index filetype needs_recovery extent 64bit flex_bg sparse_super large_file huge_file dir_nlink extra_isize metadata_csum
```

**Important features:**
- `has_journal` - Journaling enabled (EXT3/EXT4)
- `extent` - Uses extent trees (EXT4, more efficient than indirect blocks)
- `needs_recovery` - Filesystem not cleanly unmounted
- `metadata_csum` - Metadata checksumming enabled

---

## Step 3: Inspect Inode Metadata

Before recovering a file, examine its metadata to verify it's the correct file and understand its properties.

### View Complete Inode Information

```bash
sudo debugfs -R "stat <inode_number>" /dev/loop0p1
```

Replace `<inode_number>` with your target inode (e.g., `stat <12345>`).

**Example output:**
```
Inode: 12345   Type: regular    Mode:  0644   Flags: 0x80000
Generation: 3456789    Version: 0x00000000:00000001
User:  1000   Group:  1000   Project:     0   Size: 524288
File ACL: 0
Links: 1   Blockcount: 1024
Fragment:  Address: 0    Number: 0    Size: 0
 ctime: 0x6547a8b2:12345678 -- Mon Nov 20 14:30:42 2023
 atime: 0x6547a8c0:87654321 -- Mon Nov 20 14:30:48 2023
 mtime: 0x6547a8b0:11223344 -- Mon Nov 20 14:30:40 2023
crtime: 0x6547a890:99887766 -- Mon Nov 20 14:30:08 2023
Size of extra inode fields: 32
Inode checksum: 0xabcd1234
EXTENTS:
(0-127): 10485760-10485887
```

### Understanding Inode Output

| Field | Description | Forensic Significance |
|-------|-------------|----------------------|
| **Type** | File type (regular, directory, symlink) | Verify expected file type |
| **Mode** | Permissions (octal) | Check for suspicious permissions (e.g., 0777) |
| **Flags** | EXT4-specific flags (hex) | 0x80000 = extents used |
| **User/Group** | Owner UID/GID | Identify file ownership |
| **Size** | File size in bytes | Verify expected file size |
| **Links** | Hard link count | >1 indicates hard links exist |
| **ctime** | Inode change time | Last metadata change |
| **mtime** | Modification time | Last content modification |
| **atime** | Access time | Last file read (may be disabled) |
| **crtime** | Creation time | File creation timestamp (EXT4 only) |
| **EXTENTS** | Physical block locations | Where file data resides on disk |

**Flags reference (hex values):**
- `0x80000` (524288) - File uses extent tree
- `0x10` (16) - Immutable (cannot be modified)
- `0x20` (32) - Append-only
- `0x100` (256) - Do not update atime

### Map Inode to Filepath

If the file isn't deleted, find its path:

```bash
sudo debugfs -R "ncheck <inode_number>" /dev/loop0p1
```

**Example output:**
```
Inode    Pathname
12345    /home/user/documents/evidence.txt
```

**Note:** This only works for files still in the directory tree. Deleted files won't have paths.

---

## Step 4: Recover File Contents

Once you've verified the inode metadata, recover the actual file data.

### Recover File by Inode

```bash
sudo debugfs -R "dump <inode_number> /path/to/output/recovered_file.bin" /dev/loop0p1
```

**Example:**
```bash
sudo debugfs -R "dump <12345> /cases/case001/recovered_evidence.txt" /dev/loop0p1
```

**Important notes:**
- Works even if the file is deleted (as long as blocks haven't been reallocated)
- Output path must be writable by the current user (or use sudo)
- File will be recovered with original size and content
- Metadata (timestamps, permissions) must be recorded separately

### Verify Recovery

After recovering the file, verify its integrity:

```bash
# Check file size
ls -lh recovered_file.bin

# View file type
file recovered_file.bin

# Calculate hash (for evidence documentation)
sha256sum recovered_file.bin
```

### Recover File with Original Name

If you know the original filename:

```bash
# First, get the filename from ncheck
FILENAME=$(sudo debugfs -R "ncheck <inode_number>" /dev/loop0p1 | tail -1 | awk '{print $2}' | xargs basename)

# Then recover with original name
sudo debugfs -R "dump <inode_number> /cases/case001/$FILENAME" /dev/loop0p1
```

---

## Additional Useful Commands

### View File Blocks

List all physical blocks used by a file:

```bash
sudo debugfs -R "blocks <inode_number>" /dev/loop0p1
```

**Example output:**
```
10485760 10485761 10485762 10485763...
```

Each number represents a filesystem block number where file data resides.

### Calculate File Offset on Disk

To find where file data starts on the physical disk:

```bash
# Get first block number
FIRST_BLOCK=$(sudo debugfs -R "blocks <inode_number>" /dev/loop0p1 | awk '{print $1}')

# Get block size
BLOCK_SIZE=$(sudo dumpe2fs -h /dev/loop0p1 2>/dev/null | grep 'Block size' | awk '{print $3}')

# Calculate byte offset
BYTE_OFFSET=$((FIRST_BLOCK * BLOCK_SIZE))

echo "First byte of file data is at offset: $BYTE_OFFSET bytes"
```

### Check File Integrity on Mounted Filesystem

If you have the original file mounted (for comparison):

```bash
# Compare recovered file against original
sha256sum recovered_file.bin
sha256sum /mnt/evidence/original_file.txt
```

### View Raw Block Contents

To examine the raw hex of a specific block:

```bash
# Get block number from blocks command
sudo dd if=/dev/loop0p1 bs=4096 skip=<block_number> count=1 | xxd | less
```

Replace `bs=4096` with your filesystem's block size if different.

---

## Troubleshooting

### Error: "Filesystem is mounted read-write"

**Problem:** Trying to use debugfs on a read-write mounted filesystem.

**Solution:**
```bash
# Option 1: Remount read-only
sudo mount -o remount,ro /dev/loop0p1

# Option 2: Unmount (if possible)
sudo umount /dev/loop0p1

# Option 3: Use debugfs in catastrophic mode (DANGEROUS - last resort)
sudo debugfs -c /dev/loop0p1
```

### Error: "Inode does not exist" or "Bad inode number"

**Problem:** Invalid inode number or inode was never used.

**Solutions:**
- Verify inode number is correct
- Check total inode count: `sudo dumpe2fs -h /dev/loop0p1 | grep 'Inode count'`
- Ensure inode number is within valid range (1 to inode count)
- First usable inode is typically 11 or higher (inodes 1-10 are reserved)

### Recovered File is Empty or Wrong Size

**Possible causes:**
1. File was deleted and blocks were reallocated
2. Filesystem journaling overwrote data
3. Extent tree is corrupted

**Solutions:**
- Check extent list in `stat` output - if empty, data is gone
- Try journal recovery (see [EXT4_DeletedFileCarving.md](EXT4_DeletedFileCarving.md))
- Use advanced carving techniques (see [EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md))

### Permission Denied Errors

**Problem:** Insufficient privileges to access device or write output.

**Solution:**
```bash
# Run with sudo
sudo debugfs -R "dump <inode> /tmp/recovered.bin" /dev/loop0p1

# Or change output directory permissions
sudo mkdir -p /cases/output
sudo chown $(whoami):$(whoami) /cases/output
debugfs -R "dump <inode> /cases/output/file.bin" /dev/loop0p1
```

### Loop Device Not Found

**Problem:** Loop device wasn't created or has wrong number.

**Solution:**
```bash
# List all loop devices
losetup -a

# Create new loop device
sudo losetup --find --show --partscan image.dd

# Manual loop device creation
sudo losetup /dev/loop0 image.dd
sudo partprobe /dev/loop0
```

---

## Glossary

**Block** - Fixed-size data unit used by filesystems (typically 4096 bytes for EXT4).

**Block Group** - EXT filesystems divide the disk into block groups, each containing a portion of inodes and data blocks.

**debugfs** - Interactive filesystem debugger for EXT2/EXT3/EXT4, used for low-level filesystem inspection and recovery.

**dumpe2fs** - Command to display EXT2/EXT3/EXT4 filesystem information, including superblock and block group descriptors.

**Extent** - Contiguous range of blocks; EXT4 uses extent trees instead of indirect block pointers for efficiency.

**Inode** - Data structure storing file metadata (ownership, permissions, timestamps) and pointers to data blocks.

**Inode Number** - Unique identifier for each inode within a filesystem.

**Loop Device** - Virtual block device that makes a file accessible as a block device (e.g., mounting disk images).

**Superblock** - Critical filesystem metadata structure containing geometry, state, and feature information.

**tune2fs** - Tool to adjust tunable filesystem parameters and display filesystem information.

---

## Related Documentation

**Next Steps:**
- [EXT4_DeletedFileCarving.md](EXT4_DeletedFileCarving.md) - Recover deleted files using journal analysis and directory carving
- [EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md) - Multi-partition images, manual extent parsing, and advanced carving techniques
- [Manual_XFS_File_Extraction_CheatSheet.md](Manual_XFS_File_Extraction_CheatSheet.md) - File recovery for XFS filesystems

**External Resources:**
- EXT4 Disk Layout: https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout
- e2fsprogs documentation: http://e2fsprogs.sourceforge.net/

---

**Part of FOR577 Additional Information**
These materials support **SANS FOR577: Linux Incident Response and Threat Hunting**.

---

**Document Version:** 1.0
**Last Updated:** 2025
**Maintained by:** FOR577 Instruction Team

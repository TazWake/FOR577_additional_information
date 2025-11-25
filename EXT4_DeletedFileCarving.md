# EXT4 Deleted File Carving Guide

## Purpose

This guide covers **recovering deleted files** from EXT4 filesystems using journal analysis, directory enumeration, and inode table inspection. Use this guide when files have been deleted but you need to recover them.

**When to use this guide:**
- Recovering deleted files where you don't know the inode number
- Analyzing the filesystem journal for deleted file metadata
- Enumerating directory entries including deleted files
- Searching inode tables for recoverable deleted files
- Mapping blocks back to inodes to identify file owners

**When NOT to use this guide:**
- You already know the inode number (see [EXT4_BasicFileRecovery.md](EXT4_BasicFileRecovery.md))
- Multi-partition images requiring offset calculations (see [EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md))
- Manual hex parsing of extent trees (see [EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md))

## Prerequisites

- Root or sudo access
- `e2fsprogs` package installed (debugfs, dumpe2fs, tune2fs)
- Disk image mounted as loop device or direct access to partition
- Basic understanding of EXT4 filesystem structure

**IMPORTANT:** Work on forensic copies, never on original evidence. Deleted file recovery may modify filesystem metadata.

## Table of Contents

- [Quick Start](#quick-start)
- [Understanding Deleted Files in EXT4](#understanding-deleted-files-in-ext4)
- [Step 1: Analyze the Filesystem Journal](#step-1-analyze-the-filesystem-journal)
- [Step 2: Enumerate Directory Entries](#step-2-enumerate-directory-entries)
- [Step 3: Search Inode Tables](#step-3-search-inode-tables)
- [Step 4: Map Blocks to Inodes](#step-4-map-blocks-to-inodes)
- [Step 5: Recover Deleted File Data](#step-5-recover-deleted-file-data)
- [Automated Recovery Tools](#automated-recovery-tools)
- [Troubleshooting](#troubleshooting)
- [Glossary](#glossary)

---

## Quick Start

If you need to quickly search for and recover deleted files:

```bash
# Check if journal exists
sudo tune2fs -l /dev/loop0p1 | grep 'Filesystem features' | grep has_journal

# View directory entries (including deleted)
sudo debugfs -R "ls -d /path/to/directory" /dev/loop0p1

# Search journal for deleted file metadata
sudo debugfs -R "logdump" /dev/loop0p1 | grep -A10 "unlink"

# Once you find an inode, recover it
sudo debugfs -R "dump <inode> recovered_file.bin" /dev/loop0p1
```

---

## Understanding Deleted Files in EXT4

### How EXT4 Handles File Deletion

When a file is deleted in EXT4:

1. **Directory entry** is marked as deleted (but often still readable)
2. **Inode link count** is decremented to 0
3. **Inode deletion time** is recorded in the inode
4. **Data blocks** are marked as free in the block bitmap (but content remains until overwritten)
5. **Journal** may contain records of the deletion transaction

**Key insight:** Deleted file data often remains on disk until blocks are reallocated. Recovery success depends on:
- Time since deletion
- Filesystem activity since deletion
- Whether journal contained deletion metadata
- Whether blocks have been reallocated

### Recovery Success Factors

| Factor | High Success | Low Success |
|--------|-------------|-------------|
| **Time since deletion** | Minutes to hours | Days to weeks |
| **Filesystem activity** | Minimal writes | Heavy write activity |
| **Journaling** | Journal contains metadata | Journal has cycled |
| **File size** | Small files (few blocks) | Large fragmented files |
| **Block reallocation** | Blocks still unallocated | Blocks overwritten |

---

## Step 1: Analyze the Filesystem Journal

The EXT3/EXT4 journal records filesystem transactions and may contain metadata about recently deleted files.

### Verify Journal Exists

```bash
sudo tune2fs -l /dev/loop0p1 | grep -i journal
```

**Expected output:**
```
Filesystem features:      has_journal ext_attr resize_inode...
Journal inode:            8
Journal backup:           inode blocks
Journal size:             128M
```

If `has_journal` is not present, skip to [Step 2](#step-2-enumerate-directory-entries).

### Dump Complete Journal

```bash
sudo debugfs -R "logdump" /dev/loop0p1 > /cases/journal_dump.txt
```

**Warning:** Journal dumps can be very large (hundreds of MB). Pipe to `less` or save to file.

### Search Journal for Specific Inode

If you know the inode number of a deleted file:

```bash
sudo debugfs -R "logdump -i <inode_number>" /dev/loop0p1
```

**Example:**
```bash
sudo debugfs -R "logdump -i <12345>" /dev/loop0p1
```

### Search Journal for Specific Block

If you know a block number:

```bash
sudo debugfs -R "logdump -b <block_number>" /dev/loop0p1
```

### Analyze Journal for Deletion Events

Search journal dump for deletion-related operations:

```bash
# Search for unlink operations (file deletion)
grep -i "unlink" /cases/journal_dump.txt

# Search for specific filename
grep -i "evidence.txt" /cases/journal_dump.txt

# Look for inode deletions with timestamps
grep -A5 -B5 "dtime" /cases/journal_dump.txt
```

**Example journal entry:**
```
Journal starts at block 1, transaction 1234
  FS block 5678 logged at sequence 1234, journal block 2
    (inode block for inode 12345)
    Inode: 12345   Type: regular
    Deletion time: Mon Nov 20 15:30:42 2023
    dtime: 0x6547a8b2
```

**Forensic value:**
- Confirms file existed and was deleted
- Provides deletion timestamp
- May reveal original filename
- Shows inode number for recovery

---

## Step 2: Enumerate Directory Entries

EXT4 directory entries often remain readable even after files are deleted.

### List Directory with Deleted Entries

```bash
sudo debugfs -R "ls -d /path/to/directory" /dev/loop0p1
```

The `-d` flag shows deleted entries.

**Example output:**
```
 2 (12) .    2 (12) ..    12 (20) file1.txt
 13 (24) file2.dat    0 (28) <3770>    0 (32) <3771>
```

**Understanding the output:**
- `2 (12) .` - Inode 2, entry length 12 bytes, current directory
- `12 (20) file1.txt` - Inode 12, entry length 20, filename "file1.txt"
- `0 (28) <3770>` - **Deleted entry**, was inode 3770, entry length 28

**Key indicators of deleted files:**
- Inode number = 0
- Filename shown as `<inode_number>` in angle brackets
- Original inode number is preserved

### List Directory Recursively

To enumerate an entire directory tree:

```bash
sudo debugfs /dev/loop0p1
debugfs:  ls -d -R /
```

This shows all directories and their deleted entries.

### Extract Deleted Inodes from Directory Listing

```bash
# Save directory listing
sudo debugfs -R "ls -d /" /dev/loop0p1 > /cases/dir_listing.txt

# Extract deleted inode numbers
grep '<[0-9]*>' /cases/dir_listing.txt | sed 's/.*<\([0-9]*\)>.*/\1/' > /cases/deleted_inodes.txt

# Show unique deleted inodes
sort -u /cases/deleted_inodes.txt
```

---

## Step 3: Search Inode Tables

Directly examine inode tables to find deleted but potentially recoverable files.

### Locate Inode Tables

First, identify inode table locations for each block group:

```bash
sudo dumpe2fs /dev/loop0p1 | grep -E "Group [0-9]+|Inode table"
```

**Example output:**
```
Group 0: (Blocks 0-32767)
  Inode table at 256-511 (bg #0 + 256)
Group 1: (Blocks 32768-65535)
  Inode table at 32768-33023 (bg #1 + 0)
```

Record the inode table block ranges.

### Dump Inode Table for Analysis

Extract inode table from a specific block group:

```bash
# Get filesystem block size
BLOCK_SIZE=$(sudo dumpe2fs -h /dev/loop0p1 2>/dev/null | grep 'Block size' | awk '{print $3}')

# Dump inode table for group 0 (blocks 256-511)
sudo dd if=/dev/loop0p1 bs=$BLOCK_SIZE skip=256 count=256 of=/cases/inode_table_group0.bin
```

### Scan for Deleted Inodes

Deleted inodes have specific characteristics:
- `dtime` (deletion time) is non-zero
- Link count is 0
- May still have extent pointers intact

**Manual examination:**
```bash
# Examine inode table with hexdump
xxd /cases/inode_table_group0.bin | less

# Look for deletion time field (offset varies by inode size)
# For 256-byte inodes, dtime is typically at offset +0x14
```

**Automated search with debugfs:**
```bash
# List all inodes in filesystem
sudo debugfs -R "stat <1>" /dev/loop0p1 2>&1 | grep "Type:"

# Or iterate through inode range
for i in {11..1000}; do
  sudo debugfs -R "stat <$i>" /dev/loop0p1 2>/dev/null | grep -q "Links: 0" && echo "Deleted inode: $i"
done
```

---

## Step 4: Map Blocks to Inodes

When you have file content but don't know the inode, use block-to-inode mapping.

### Find Inode Owning a Block

```bash
sudo debugfs -R "icheck <block_number>" /dev/loop0p1
```

**Important:** `icheck` takes a **block number**, not an inode number. Do NOT use angle brackets.

**Example:**
```bash
sudo debugfs -R "icheck 10485760" /dev/loop0p1
```

**Output:**
```
Block    Inode number
10485760 12345
```

This shows that block 10485760 belongs to inode 12345.

### Find All Blocks Owned by an Inode

Reverse operation - given an inode, find all its blocks:

```bash
sudo debugfs -R "blocks <inode_number>" /dev/loop0p1
```

**Example:**
```bash
sudo debugfs -R "blocks <12345>" /dev/loop0p1
```

**Output:**
```
10485760 10485761 10485762 10485763
```

### Search for Data Patterns in Blocks

To find blocks containing specific data (e.g., file signature):

```bash
# Search for JPEG signature (FF D8 FF)
sudo grep -a -b --only-matching -P '\xFF\xD8\xFF' /dev/loop0p1 | head -20

# Convert byte offsets to block numbers
# Offset ÷ block_size = block number
```

Then use `icheck` to identify the owning inode.

---

## Step 5: Recover Deleted File Data

Once you've identified deleted file inodes, attempt recovery.

### Attempt Direct Recovery

Even though the file is deleted, if blocks weren't reallocated:

```bash
sudo debugfs -R "dump <inode_number> /cases/recovered_deleted_file.bin" /dev/loop0p1
```

**Success indicators:**
- File size matches expected size
- File type detection works (`file` command)
- File contains expected data

**Failure indicators:**
- Empty file (0 bytes)
- File filled with zeros
- Random data (blocks were reallocated)

### Verify Inode Before Recovery

Always check inode metadata first:

```bash
sudo debugfs -R "stat <inode_number>" /dev/loop0p1
```

**Check these fields:**
- **Links:** Should be 0 (deleted)
- **dtime:** Should have deletion timestamp
- **Size:** File size (0 = no data to recover)
- **EXTENTS:** If present, data may be recoverable

**Example good candidate for recovery:**
```
Inode: 3770   Type: regular    Mode:  0644   Flags: 0x80000
Links: 0   Blockcount: 1024
Deletion time: Mon Nov 20 15:30:42 2023
Size: 524288
EXTENTS:
(0-127): 10485760-10485887
```

**Example poor candidate:**
```
Inode: 3771   Type: regular    Mode:  0644   Flags: 0x0
Links: 0   Blockcount: 0
Deletion time: Mon Nov 20 15:30:42 2023
Size: 0
EXTENTS:
```

### Batch Recovery of Multiple Deleted Files

```bash
#!/bin/bash
# Recover all deleted inodes from a list

DELETED_INODES_FILE="/cases/deleted_inodes.txt"
OUTPUT_DIR="/cases/recovered_files"

mkdir -p "$OUTPUT_DIR"

while read inode; do
  echo "Attempting to recover inode $inode..."

  # Check if inode has data
  SIZE=$(sudo debugfs -R "stat <$inode>" /dev/loop0p1 2>/dev/null | grep "Size:" | awk '{print $2}')

  if [ "$SIZE" -gt 0 ]; then
    sudo debugfs -R "dump <$inode> $OUTPUT_DIR/inode_${inode}.bin" /dev/loop0p1
    echo "  Recovered $SIZE bytes to $OUTPUT_DIR/inode_${inode}.bin"
  else
    echo "  Inode $inode has no data (size=0), skipping"
  fi
done < "$DELETED_INODES_FILE"
```

---

## Automated Recovery Tools

While this guide focuses on manual techniques, automated tools can accelerate recovery.

### extundelete

**Purpose:** Recover deleted files from EXT3/EXT4 filesystems.

**Installation:**
```bash
sudo apt install extundelete
```

**Usage:**
```bash
# Unmount filesystem first (or use read-only loop device)
sudo umount /dev/loop0p1

# Recover all deleted files from a directory
sudo extundelete /dev/loop0p1 --restore-directory /home/user/documents

# Recover all deleted files
sudo extundelete /dev/loop0p1 --restore-all

# Recover files deleted after a specific time
sudo extundelete /dev/loop0p1 --after $(date -d '2023-11-20' +%s) --restore-all

# Output goes to ./RECOVERED_FILES/ directory
```

**Advantages:**
- Automated recovery workflow
- Preserves directory structure
- Filters by date
- No manual inode tracking

**Limitations:**
- May not recover all files (depends on journal and block allocation)
- Requires unmounted filesystem
- Less control than manual techniques

### e2image for Metadata Extraction

Create a metadata-only image for safer analysis:

```bash
# Extract metadata without data blocks
sudo e2image -r /dev/loop0p1 /cases/metadata.img

# Analyze metadata image instead of full filesystem
sudo debugfs /cases/metadata.img
```

**Advantages:**
- Much smaller than full image
- Preserves inode structure
- Safe for analysis (no data blocks)

---

## Troubleshooting

### No Deleted Entries Found in Directory Listing

**Possible causes:**
1. Directory structure was overwritten
2. Filesystem was defragmented/compacted
3. Files were securely deleted (shred, wipe)

**Solutions:**
- Search journal for historical directory entries
- Search inode tables directly (Step 3)
- Use file carving tools (photorec, scalpel) for signature-based recovery

### Journal is Empty or Doesn't Contain Deletion Events

**Possible causes:**
1. Journal has cycled (older transactions overwritten)
2. File was deleted long ago
3. Journal size is small relative to filesystem activity

**Solutions:**
- Skip journal analysis, proceed to directory enumeration (Step 2)
- Search inode tables directly (Step 3)
- Examine filesystem more broadly with automated tools

### Recovered File is Corrupted or Incomplete

**Possible causes:**
1. Some data blocks were reallocated
2. File was fragmented and some extents lost
3. Extent tree was partially corrupted

**Solutions:**
```bash
# Verify extent list
sudo debugfs -R "stat <inode>" /dev/loop0p1 | grep EXTENTS

# Check for gaps in block ranges
sudo debugfs -R "blocks <inode>" /dev/loop0p1

# Attempt partial recovery
# Even corrupted files may contain forensic value
```

### Permission Denied During Recovery

**Problem:** Can't write recovered files to output directory.

**Solutions:**
```bash
# Use sudo for entire command
sudo debugfs -R "dump <inode> /cases/file.bin" /dev/loop0p1

# Or fix directory permissions
sudo mkdir -p /cases/recovered
sudo chown $(whoami):$(whoami) /cases/recovered
debugfs -R "dump <inode> /cases/recovered/file.bin" /dev/loop0p1
```

### extundelete Reports "No files found"

**Possible causes:**
1. Filesystem was cleanly mounted/unmounted (journal replayed)
2. Blocks were reallocated quickly
3. Deletion occurred before journal started

**Solutions:**
- Try manual inode table search (Step 3)
- Use signature-based carving (photorec)
- Check if file data exists with block search patterns

---

## Glossary

**Block Bitmap** - Data structure tracking which blocks are allocated (used) vs. free.

**debugfs** - Interactive filesystem debugger for EXT2/EXT3/EXT4.

**Deletion Time (dtime)** - Timestamp recorded in inode when file is deleted.

**Directory Entry** - Record in directory linking filename to inode number.

**extundelete** - Third-party tool for automated deleted file recovery from EXT3/EXT4.

**icheck** - debugfs command mapping block numbers to inode numbers.

**Journal (Journaling)** - EXT3/EXT4 feature recording filesystem transactions for crash recovery; may contain deleted file metadata.

**Link Count** - Number of directory entries pointing to an inode; 0 indicates deleted file.

**logdump** - debugfs command to dump and analyze filesystem journal contents.

**ncheck** - debugfs command mapping inode numbers to file paths.

---

## Related Documentation

**Previous Guide:**
- [EXT4_BasicFileRecovery.md](EXT4_BasicFileRecovery.md) - Basic file recovery when inode number is known

**Next Steps:**
- [EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md) - Multi-partition images, manual extent parsing, advanced carving

**Related Topics:**
- [Manual_XFS_File_Extraction_CheatSheet.md](Manual_XFS_File_Extraction_CheatSheet.md) - Deleted file recovery for XFS filesystems

---

**Part of FOR577 Additional Information**
These materials support **SANS FOR577: Linux Incident Response and Threat Hunting**.

---

**Document Version:** 1.0
**Last Updated:** 2025
**Maintained by:** FOR577 Instruction Team

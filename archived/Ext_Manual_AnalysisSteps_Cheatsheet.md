# EXT3/EXT4 Forensics Cheat Sheet

This guide provides reliable, DFIR‑safe commands for analyzing EXT3/EXT4 filesystems **without The Sleuth Kit**.  
All commands work against **disk images or loop devices**, not live systems.

---

## 1. Identify Filesystem Structure (block size, inode size, groups)

### dumpe2fs

```bash
dumpe2fs -h /dev/loop0p1
```

Shows: block size, inode size, inodes per group, blocks per group, FS features.

### tune2fs

```bash
tune2fs -l /dev/loop0p1
```

Shows: superblock fields, timestamps, feature flags.

---

## 2. Inspect an Inode Directly

### debugfs - Inspect inode

```bash
debugfs -R "stat <inode>" /dev/loop0p1
```

Displays inode metadata, extents, timestamps.

---

## 3. Dump File Contents When Given an Inode

### debugfs - Dump file by inode

```bash
debugfs -R "dump <inode> recovered_file.bin" /dev/loop0p1
```

Dump file content by inode — works on deleted files if blocks still allocated.

---

## 4. Show Journal Information

### Journal metadata (superblock)

```bash
dumpe2fs -h /dev/loop0p1 | grep -i journal
```

### Parsed journal entries

```bash
debugfs -R "logdump" /dev/loop0p1
```

### Target specific inode or block

```bash
debugfs -R "logdump -i <inode>" /dev/loop0p1
debugfs -R "logdump -b <block>" /dev/loop0p1
```

---

## 5. Dump Inode Tables

### Identify inode table locations

```bash
dumpe2fs -h /dev/loop0p1
```

### Dump entire inode table block range

(Example: group 0 inode table at block 256, FS block size = 4096)

```bash
dd if=/dev/loop0p1 bs=4096 skip=256 count=<N> of=inode_table_group0.bin
```

---

## 6. Confirm Last Mount Time of Filesystem

```bash
tune2fs -l /dev/loop0p1 | grep 'Last mount time'
```

---

## 7. Confirm Last Write Time of Filesystem

```bash
tune2fs -l /dev/loop0p1 | grep 'Last write time'
```

---

## 8. Additional Useful e2fsprogs Commands

### Extract raw filesystem metadata

```bash
e2image -r /dev/loop0p1 fs_metadata.img
```

### List directory entries (even deleted ones)

```bash
debugfs -R "ls -d /path" /dev/loop0p1
```

### Check which inode owns a *block* (block → inode mapping)

⚠️ **Note:** `icheck` takes a *block number*, NOT an inode. Unlike most other debugfs commands do not use `<>` around the number.

```bash
debugfs -R "icheck block_number" /dev/loop0p1
```

### Show blocks belonging to an inode

```bash
debugfs -R "blocks <inode>" /dev/loop0p1
```

### Inspect raw blocks

```bash
dd if=/dev/loop0p1 bs=4096 skip=<block> count=1 | xxd
```

---

## Summary Table

| Task | Recommended Command |
|------|---------------------|
| Identify FS structure | `dumpe2fs -h`, `tune2fs -l` |
| Inspect inode | `debugfs -R "stat <inode>"` |
| Dump file by inode | `debugfs -R "dump <inode> file.bin"` |
| Show journal info | `debugfs -R "logdump"` |
| Dump inode table | `dd` (after locating table via `dumpe2fs`) |
| Last mount time | `tune2fs -l \| grep 'Last mount time'` |
| Last write time | `tune2fs -l \| grep 'Last write time'` |
| List directory entries | `debugfs -R "ls -d /path"` |
| Map block → inode | `debugfs -R "icheck <block>"` |
| Show blocks for inode | `debugfs -R "blocks <inode>"` |
| Extract metadata image | `e2image -r` |

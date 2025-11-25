# EXT3/EXT4 Forensics Cheat Sheet (No TSK Required)

This cheat sheet covers the essential tools and workflows used when analyzing EXT3/EXT4 filesystems *without* The Sleuth Kit. It also includes guidance for manual inode analysis, extent parsing, and raw carving.

---

## Filesystem Identification & Geometry

### **dumpe2fs**

View superblock, block group layout, inode size, block size, journal state.

```bash
dumpe2fs /dev/loopX | less
```

### **blkid**

Identify filesystem type and UUID.

```bash
blkid /dev/loopX
```

### **fdisk / parted**

Locate partition offsets in multi-partition images.

```bash
fdisk -l image.dd
```

---

## Deep EXT3/EXT4 Analysis Tools

### **debugfs**

The most powerful native EXT tool.

- `stat <inode>` — view inode metadata  
- `ncheck <inode>` — map inode → path  
- `icheck <block>` — map block → inode  
- `dump <inode>` — recover deleted files  
- `logdump` — examine filesystem journal  

```bash
debugfs -R "stat <inode>" /dev/loopX
```

---

## Metadata & Attribute Tools

### **lsattr**

Shows immutable/append-only/extents flags.

```bash
lsattr -aR /mnt/fs
```

### **getfattr / setfattr**

View extended attributes (ACLs, capabilities, SELinux labels).

```bash
getfattr -d filename
```

---

## Block-Level Recovery Tools

### **dd + xxd / hexdump**

Used for raw block carving.

```bash
xxd -s OFFSET -l LENGTH image.dd > carved.bin
```

### **losetup**

Attach a filesystem partition inside a multi-partition image.

```bash
losetup --find --offset $((START_SECTOR*512)) image.dd
```

---

## Integrity & Consistency Tools

### **fsck.ext3 / fsck.ext4**

Run in *read-only* mode to validate metadata.

```bash
fsck.ext4 -n /dev/loopX
```

### **tune2fs**

Check mount counts, last mount time, feature flags.

```bash
tune2fs -l /dev/loopX
```

---

## EXT4 Extent Tree Quick Reference

### **Extent Header (offset 0x28)**

- `eh_magic` = 0xF30A  
- `eh_entries` = number of extent entries  
- `eh_max` = max entries in this node  
- `eh_depth` = 0 (leaf) or >0 (index node)  

### **Extent Entry (12 bytes)**

- `ee_block` — logical file block  
- `ee_len` — length in blocks  
- `ee_start` — physical block  

```bash
disk_offset = ee_start * block_size
```

---

## Manual Carving Workflow

1. Identify correct partition  
2. Compute partition byte offset  
3. Determine inode group  
4. Locate inode table  
5. Compute inode byte offset  
6. Extract inode with xxd  
7. Parse extents  
8. Convert extents → raw offsets  
9. Carve with xxd  
10. Reassemble if multiple extents  

---

## Decision Tree Diagram

<img width="520" height="700" alt="ext_forensics_decision_tree" src="https://github.com/user-attachments/assets/43cf6d5a-24af-4e2d-8de6-0c661cf8a54f" />

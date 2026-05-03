#!/usr/bin/env python3
"""Manual UBIFS file extractor - bypasses index, just collects all valid nodes."""

import struct, os, sys, zlib
from collections import defaultdict

try:
    import lzo
    HAS_LZO = True
except ImportError:
    HAS_LZO = False
    print("WARNING: python-lzo not installed. LZO files will be skipped.")

UBIFS_NODE_MAGIC = b'\x31\x18\x10\x06'

UBIFS_INO_NODE = 0
UBIFS_DATA_NODE = 1
UBIFS_DENT_NODE = 2
UBIFS_XENT_NODE = 3
UBIFS_TRUN_NODE = 4
UBIFS_PAD_NODE = 5
UBIFS_SB_NODE = 6
UBIFS_MST_NODE = 7

UBIFS_ITYPE_REG = 0
UBIFS_ITYPE_DIR = 1
UBIFS_ITYPE_LNK = 2

UBIFS_COMPR_NONE = 0
UBIFS_COMPR_LZO = 1
UBIFS_COMPR_ZLIB = 2
UBIFS_COMPR_ZSTD = 3

def crc32_ubifs(payload):
    """UBIFS CRC: init=0, then inverted. Confirmed empirically against superblock."""
    return (~zlib.crc32(payload, 0)) & 0xFFFFFFFF

def parse_key(key_bytes):
    inum = struct.unpack('<I', key_bytes[:4])[0]
    val2 = struct.unpack('<I', key_bytes[4:8])[0]
    key_type = (val2 >> 29) & 0x7
    block_or_hash = val2 & 0x1FFFFFFF
    return inum, key_type, block_or_hash

def decompress(data, compr_type, expected_size=None):
    if compr_type == UBIFS_COMPR_NONE:
        return data
    elif compr_type == UBIFS_COMPR_LZO:
        if not HAS_LZO:
            return None
        try:
            if expected_size:
                return lzo.decompress(data, False, expected_size)
            return lzo.decompress(data)
        except Exception:
            return None
    elif compr_type == UBIFS_COMPR_ZLIB:
        try:
            return zlib.decompress(data, -15)
        except Exception:
            return None
    elif compr_type == UBIFS_COMPR_ZSTD:
        try:
            import zstandard
            return zstandard.decompress(data)
        except Exception:
            return None
    return None

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <volume.bin> <output_dir>")
        sys.exit(1)
    
    fname = sys.argv[1]
    outdir = sys.argv[2]
    
    print(f"Reading {fname}...")
    with open(fname, 'rb') as f:
        data = f.read()
    print(f"  {len(data)} bytes")
    
    inodes = {}
    dentries = []
    data_nodes = defaultdict(list)
    
    nodes_seen = 0
    nodes_valid = 0
    nodes_crc_fail = 0
    type_counts = defaultdict(int)
    
    pos = 0
    while pos < len(data) - 24:
        idx = data.find(UBIFS_NODE_MAGIC, pos)
        if idx < 0:
            break
        pos = idx
        
        magic = data[pos:pos+4]
        crc = struct.unpack('<I', data[pos+4:pos+8])[0]
        sqnum = struct.unpack('<Q', data[pos+8:pos+16])[0]
        node_len = struct.unpack('<I', data[pos+16:pos+20])[0]
        node_type = data[pos+20]
        
        nodes_seen += 1
        
        if node_len < 24 or node_len > 1024*1024 or pos + node_len > len(data):
            pos += 4
            continue
        
        node_data = data[pos:pos+node_len]
        computed_crc = crc32_ubifs(node_data[8:])
        if computed_crc != crc:
            nodes_crc_fail += 1
            pos += 4
            continue
        
        nodes_valid += 1
        type_counts[node_type] += 1
        
        if node_type == UBIFS_INO_NODE:
            key = node_data[24:40]
            inum, _, _ = parse_key(key)
            size = struct.unpack('<Q', node_data[48:56])[0]
            mtime = struct.unpack('<Q', node_data[72:80])[0]
            uid = struct.unpack('<I', node_data[100:104])[0]
            gid = struct.unpack('<I', node_data[104:108])[0]
            mode = struct.unpack('<I', node_data[108:112])[0]
            data_len = struct.unpack('<I', node_data[116:120])[0]
            inode_data = node_data[160:160+data_len]
            
            if inum not in inodes or inodes[inum]['sqnum'] < sqnum:
                inodes[inum] = {
                    'sqnum': sqnum, 'size': size, 'mode': mode,
                    'uid': uid, 'gid': gid, 'mtime': mtime,
                    'data': inode_data,
                }
        
        elif node_type == UBIFS_DENT_NODE:
            key = node_data[24:40]
            parent_inum, _, _ = parse_key(key)
            child_inum = struct.unpack('<Q', node_data[40:48])[0]
            dtype = node_data[49]
            nlen = struct.unpack('<H', node_data[50:52])[0]
            name = node_data[56:56+nlen].decode('utf-8', errors='replace')
            
            dentries.append({
                'sqnum': sqnum, 'parent': parent_inum, 'child': child_inum,
                'name': name, 'type': dtype,
            })
        
        elif node_type == UBIFS_DATA_NODE:
            key = node_data[24:40]
            inum, _, block_num = parse_key(key)
            decompressed_size = struct.unpack('<I', node_data[40:44])[0]
            compr_type = struct.unpack('<H', node_data[44:46])[0]
            content = node_data[48:node_len]
            
            data_nodes[inum].append({
                'sqnum': sqnum, 'block': block_num,
                'content': content, 'compr_type': compr_type,
                'decompressed_size': decompressed_size,
            })
        
        pos += node_len
    
    print(f"\nScan complete:")
    print(f"  Magics found: {nodes_seen}")
    print(f"  Valid CRC: {nodes_valid}")
    print(f"  CRC failures: {nodes_crc_fail}")
    print(f"  Node type breakdown:")
    for t, c in sorted(type_counts.items()):
        names = {0:'INO', 1:'DATA', 2:'DENT', 3:'XENT', 4:'TRUN', 5:'PAD', 6:'SB', 7:'MST', 8:'REF', 9:'IDX', 10:'CS', 11:'ORPH'}
        print(f'    type {t} ({names.get(t, "?")}): {c}')
    print(f"  Inodes: {len(inodes)}")
    print(f"  Dentries: {len(dentries)}")
    print(f"  Inodes with data: {len(data_nodes)}")
    
    children_by_parent = defaultdict(dict)
    for d in dentries:
        existing = children_by_parent[d['parent']].get(d['name'])
        if existing is None or existing['sqnum'] < d['sqnum']:
            children_by_parent[d['parent']][d['name']] = d
    
    paths = {1: ''}
    inode_types = {1: UBIFS_ITYPE_DIR}
    queue = [1]
    while queue:
        parent = queue.pop()
        for name, d in children_by_parent.get(parent, {}).items():
            if d['child'] in paths:
                continue
            child_path = paths[parent] + '/' + name if paths[parent] else name
            paths[d['child']] = child_path
            inode_types[d['child']] = d['type']
            if d['type'] == UBIFS_ITYPE_DIR:
                queue.append(d['child'])
    
    print(f"\nReachable inodes: {len(paths)}")
    
    os.makedirs(outdir, exist_ok=True)
    
    files_written = 0
    files_failed = 0
    dirs_made = 0
    symlinks_made = 0
    
    for inum, path in paths.items():
        if not path:
            continue
        full_path = os.path.join(outdir, path.lstrip('/'))
        itype = inode_types.get(inum, UBIFS_ITYPE_REG)
        
        if itype == UBIFS_ITYPE_DIR:
            try:
                os.makedirs(full_path, exist_ok=True)
                dirs_made += 1
            except Exception as e:
                print(f"  dir fail {path}: {e}")
        
        elif itype == UBIFS_ITYPE_LNK:
            ino = inodes.get(inum)
            if ino:
                target = ino['data'].split(b'\x00')[0].decode('utf-8', errors='replace')
                try:
                    parent_dir = os.path.dirname(full_path)
                    os.makedirs(parent_dir, exist_ok=True)
                    if os.path.lexists(full_path):
                        os.remove(full_path)
                    os.symlink(target, full_path)
                    symlinks_made += 1
                except Exception:
                    with open(full_path + '.symlink_target', 'w') as f:
                        f.write(target)
        
        elif itype == UBIFS_ITYPE_REG:
            ino = inodes.get(inum)
            if not ino:
                continue
            
            blocks_by_num = {}
            for dn in data_nodes.get(inum, []):
                # Sanity: block * 4096 should not exceed ino size by much
                if dn['block'] * 4096 > ino['size'] + 65536:
                    continue
                if dn['block'] not in blocks_by_num or blocks_by_num[dn['block']]['sqnum'] < dn['sqnum']:
                    blocks_by_num[dn['block']] = dn
            
            try:
                parent_dir = os.path.dirname(full_path)
                if parent_dir:
                    os.makedirs(parent_dir, exist_ok=True)
                # Build content into bytearray, then write
                content = bytearray()
                for block_num in sorted(blocks_by_num.keys()):
                    dn = blocks_by_num[block_num]
                    decomp = decompress(dn['content'], dn['compr_type'], dn['decompressed_size'])
                    if decomp is None:
                        decomp = b'\x00' * dn['decompressed_size']
                    expected_offset = block_num * 4096
                    if len(content) < expected_offset:
                        content.extend(b'\x00' * (expected_offset - len(content)))
                    content.extend(decomp)
                # Truncate to inode size
                if len(content) > ino['size']:
                    content = content[:ino['size']]
                with open(full_path, 'wb') as f:
                    f.write(content)
                files_written += 1
            except Exception as e:
                import traceback
                print(f"  file fail {path}: {type(e).__name__}: {e}")
                files_failed += 1
    
    print(f"\nExtraction complete:")
    print(f"  Directories: {dirs_made}")
    print(f"  Files: {files_written}")
    print(f"  File failures: {files_failed}")
    print(f"  Symlinks: {symlinks_made}")
    print(f"  Output: {outdir}/")

if __name__ == '__main__':
    main()

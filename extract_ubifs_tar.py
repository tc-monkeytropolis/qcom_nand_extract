#!/usr/bin/env python3
"""Manual UBIFS extractor that emits a tarball preserving mode/uid/gid/mtime/symlinks."""

import struct, os, sys, zlib, tarfile, io, stat
from collections import defaultdict

try:
    import lzo
    HAS_LZO = True
except ImportError:
    HAS_LZO = False

UBIFS_NODE_MAGIC = b'\x31\x18\x10\x06'
UBIFS_INO_NODE = 0
UBIFS_DATA_NODE = 1
UBIFS_DENT_NODE = 2
UBIFS_ITYPE_REG = 0
UBIFS_ITYPE_DIR = 1
UBIFS_ITYPE_LNK = 2
UBIFS_ITYPE_BLK = 3
UBIFS_ITYPE_CHR = 4
UBIFS_ITYPE_FIFO = 5
UBIFS_ITYPE_SOCK = 6
UBIFS_COMPR_NONE = 0
UBIFS_COMPR_LZO = 1
UBIFS_COMPR_ZLIB = 2
UBIFS_COMPR_ZSTD = 3

def crc32_ubifs(payload):
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
        if not HAS_LZO: return None
        try:
            if expected_size:
                return lzo.decompress(data, False, expected_size)
            return lzo.decompress(data)
        except Exception:
            return None
    elif compr_type == UBIFS_COMPR_ZLIB:
        try: return zlib.decompress(data, -15)
        except Exception: return None
    elif compr_type == UBIFS_COMPR_ZSTD:
        try:
            import zstandard
            return zstandard.decompress(data)
        except Exception: return None
    return None

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <volume.bin> <output.tar>")
        sys.exit(1)
    fname, outname = sys.argv[1], sys.argv[2]

    with open(fname, 'rb') as f:
        data = f.read()
    print(f"Read {len(data)} bytes")

    inodes = {}
    dentries = []
    data_nodes = defaultdict(list)

    pos = 0
    while pos < len(data) - 24:
        idx = data.find(UBIFS_NODE_MAGIC, pos)
        if idx < 0: break
        pos = idx
        crc = struct.unpack('<I', data[pos+4:pos+8])[0]
        sqnum = struct.unpack('<Q', data[pos+8:pos+16])[0]
        node_len = struct.unpack('<I', data[pos+16:pos+20])[0]
        node_type = data[pos+20]
        if node_len < 24 or node_len > 1024*1024 or pos+node_len > len(data):
            pos += 4; continue
        nd = data[pos:pos+node_len]
        if crc32_ubifs(nd[8:]) != crc:
            pos += 4; continue

        if node_type == UBIFS_INO_NODE:
            key = nd[24:40]
            inum, _, _ = parse_key(key)
            size = struct.unpack('<Q', nd[48:56])[0]
            mtime = struct.unpack('<Q', nd[72:80])[0]
            uid = struct.unpack('<I', nd[96:100])[0]
            gid = struct.unpack('<I', nd[100:104])[0]
            mode = struct.unpack('<I', nd[104:108])[0]
            data_len = struct.unpack('<I', nd[112:116])[0]
            inode_data = nd[160:160+data_len]
            if inum not in inodes or inodes[inum]['sqnum'] < sqnum:
                inodes[inum] = {'sqnum':sqnum,'size':size,'mode':mode,
                                'uid':uid,'gid':gid,'mtime':mtime,'data':inode_data}
        elif node_type == UBIFS_DENT_NODE:
            key = nd[24:40]
            parent_inum, _, _ = parse_key(key)
            child_inum = struct.unpack('<Q', nd[40:48])[0]
            dtype = nd[49]
            nlen = struct.unpack('<H', nd[50:52])[0]
            name = nd[56:56+nlen].decode('utf-8', errors='replace')
            dentries.append({'sqnum':sqnum,'parent':parent_inum,
                             'child':child_inum,'name':name,'type':dtype})
        elif node_type == UBIFS_DATA_NODE:
            key = nd[24:40]
            inum, _, block_num = parse_key(key)
            decompressed_size = struct.unpack('<I', nd[40:44])[0]
            compr_type = struct.unpack('<H', nd[44:46])[0]
            content = nd[48:node_len]
            data_nodes[inum].append({'sqnum':sqnum,'block':block_num,
                                     'content':content,'compr_type':compr_type,
                                     'decompressed_size':decompressed_size})
        pos += node_len

    print(f"Inodes: {len(inodes)}, Dentries: {len(dentries)}, Inodes with data: {len(data_nodes)}")

    # Resolve dentries (keep latest sqnum per parent+name)
    children_by_parent = defaultdict(dict)
    for d in dentries:
        existing = children_by_parent[d['parent']].get(d['name'])
        if existing is None or existing['sqnum'] < d['sqnum']:
            children_by_parent[d['parent']][d['name']] = d

    # Walk tree from root inode 1
    paths = {1: '.'}
    inode_types = {1: UBIFS_ITYPE_DIR}
    queue = [1]
    while queue:
        parent = queue.pop()
        for name, d in children_by_parent.get(parent, {}).items():
            if d['child'] in paths: continue
            child_path = paths[parent] + '/' + name
            paths[d['child']] = child_path
            inode_types[d['child']] = d['type']
            if d['type'] == UBIFS_ITYPE_DIR:
                queue.append(d['child'])

    print(f"Reachable inodes: {len(paths)}")

    # Write tarball
    files_added = 0
    with tarfile.open(outname, 'w') as tar:
        # Sort so directories come before their contents
        for inum, path in sorted(paths.items(), key=lambda kv: kv[1]):
            if inum == 1:
                # Root dir entry
                ti = tarfile.TarInfo('.')
                ti.type = tarfile.DIRTYPE
                ino = inodes.get(1)
                if ino:
                    ti.mode = ino['mode'] & 0o7777
                    ti.uid = ino['uid']; ti.gid = ino['gid']
                    ti.mtime = ino['mtime']
                else:
                    ti.mode = 0o755
                tar.addfile(ti)
                files_added += 1
                continue
            
            itype = inode_types.get(inum)
            ino = inodes.get(inum)
            if not ino:
                continue
            ti = tarfile.TarInfo(path)
            ti.mode = ino['mode'] & 0o7777
            ti.uid = ino['uid']; ti.gid = ino['gid']
            ti.mtime = ino['mtime']

            if itype == UBIFS_ITYPE_DIR:
                ti.type = tarfile.DIRTYPE
                tar.addfile(ti)
                files_added += 1

            elif itype == UBIFS_ITYPE_LNK:
                ti.type = tarfile.SYMTYPE
                target = ino['data'].split(b'\x00')[0].decode('utf-8', errors='replace')
                ti.linkname = target
                tar.addfile(ti)
                files_added += 1

            elif itype == UBIFS_ITYPE_REG:
                blocks_by_num = {}
                for dn in data_nodes.get(inum, []):
                    if dn['block'] * 4096 > ino['size'] + 65536: continue
                    if dn['block'] not in blocks_by_num or blocks_by_num[dn['block']]['sqnum'] < dn['sqnum']:
                        blocks_by_num[dn['block']] = dn
                content = bytearray()
                for bn in sorted(blocks_by_num.keys()):
                    dn = blocks_by_num[bn]
                    decomp = decompress(dn['content'], dn['compr_type'], dn['decompressed_size'])
                    if decomp is None:
                        decomp = b'\x00' * dn['decompressed_size']
                    expected = bn * 4096
                    if len(content) < expected:
                        content.extend(b'\x00' * (expected - len(content)))
                    content.extend(decomp)
                if len(content) > ino['size']:
                    content = content[:ino['size']]
                ti.type = tarfile.REGTYPE
                ti.size = len(content)
                tar.addfile(ti, io.BytesIO(bytes(content)))
                files_added += 1

            elif itype in (UBIFS_ITYPE_BLK, UBIFS_ITYPE_CHR):
                ti.type = tarfile.BLKTYPE if itype == UBIFS_ITYPE_BLK else tarfile.CHRTYPE
                # Major/minor stored in the first 8 bytes of inode data as __le32 each
                if len(ino['data']) >= 8:
                    ti.devmajor = struct.unpack('<I', ino['data'][0:4])[0]
                    ti.devminor = struct.unpack('<I', ino['data'][4:8])[0]
                tar.addfile(ti)
                files_added += 1

            elif itype == UBIFS_ITYPE_FIFO:
                ti.type = tarfile.FIFOTYPE
                tar.addfile(ti)
                files_added += 1

    print(f"Wrote {outname} ({files_added} entries)")

if __name__ == '__main__':
    main()

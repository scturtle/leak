#!/usr/bin/env python3

def parse_map_entry(line):
    line = line[:-1].decode()
    rg, *_, name = line.split()
    if name == '[heap]' or name[0] == '/':
        return [int(c, 16) for c in rg.split('-')] + [name]
    return None

def parse_info(f):
    import struct
    infos = []
    while True:
        bs = f.read(24)
        if not bs:
            break
        size, addr, depth = struct.unpack('QQQ', bs)
        bt = struct.unpack('Q' * depth, f.read(8 * depth))
        infos.append((size, addr, bt))
    return infos

def addr2line(exe, addr):
    import subprocess
    return subprocess.check_output(
        ['addr2line', '-Cfs', '-e', exe, hex(addr)]).decode().split('\n')

def show(map_entries, info):
    size, _, bt = info
    print('=' * 20, "leak size {}".format(size), '=' * 20)
    for fr, addr in enumerate(bt):
        for start, end, name in map_entries:
            if start <= addr < end:
                break
        else:
            print('addr not found')
            return
        if map_entries[0][2] != name:
            addr -= start
        func, loc, _ = addr2line(name, addr)
        print('#{}: {}\n\t{}'.format(fr, loc, func))
    print()

def main(args):
    with open(args.dumpfile, 'rb') as f:
        map_entries = []
        for line in f:
            if line == b'MAP_END\n':
                break
            entry = parse_map_entry(line)
            if entry:
                map_entries.append(entry)
        infos = parse_info(f)

    for info in infos:
        show(map_entries, info)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--dumpfile', default='/tmp/leak_dump')
    args = parser.parse_args()
    main(args)

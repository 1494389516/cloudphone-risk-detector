"""Read a bounded function range from a thin ARM64 Mach-O image."""
import struct


def text_bytes(image, address, length):
    data = image.read_bytes()
    magic, cpu, _, _, ncmds, _, _, _ = struct.unpack_from('<8I', data)
    assert magic == 0xfeedfacf and cpu == 0x100000c, 'Expected thin arm64 Mach-O'
    pos = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, pos)
        assert size >= 8 and pos + size <= len(data)
        if cmd == 0x19:
            segname, vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<16sQQQQ', data, pos + 8)
            if segname.rstrip(b'\0') == b'__TEXT' and vmaddr <= address and address + length <= vmaddr + filesize:
                offset = fileoff + address - vmaddr
                assert offset + length <= len(data)
                return offset, data[offset:offset + length]
        pos += size
    raise RuntimeError('Function range does not fit file-backed __TEXT')


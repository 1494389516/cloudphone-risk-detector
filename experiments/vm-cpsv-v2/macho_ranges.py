"""Read a bounded function range from a thin ARM64 Mach-O image."""
import struct


class MachOError(ValueError):
    """Raised for malformed or out-of-contract Mach-O input (never `assert`)."""


def text_bytes(image, address, length):
    data = image.read_bytes()
    if len(data) < 32:
        raise MachOError('Truncated Mach-O header: need 32 bytes')
    magic, cpu, _, _, ncmds, _, _, _ = struct.unpack_from('<8I', data)
    if magic != 0xfeedfacf or cpu != 0x100000c:
        raise MachOError('Expected thin arm64 Mach-O')
    if ncmds < 0 or ncmds > 4096:
        raise MachOError('Implausible load-command count')
    pos = 32
    for _ in range(ncmds):
        if pos + 8 > len(data):
            raise MachOError('Truncated load command header')
        cmd, size = struct.unpack_from('<II', data, pos)
        if size < 8 or pos + size > len(data):
            raise MachOError('Load command overruns file')
        if cmd == 0x19:
            if pos + 8 + 40 > len(data):
                raise MachOError('Truncated __TEXT segment command')
            segname, vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<16sQQQQ', data, pos + 8)
            if segname.rstrip(b'\0') == b'__TEXT' and vmaddr <= address and address + length <= vmaddr + filesize:
                offset = fileoff + address - vmaddr
                if offset + length > len(data):
                    raise MachOError('Function range overruns file')
                return offset, data[offset:offset + length]
        pos += size
    raise RuntimeError('Function range does not fit file-backed __TEXT')

#!/usr/bin/env python3
"""Extract the NTQQ sign function offset from wrapper.node.

Usage: python3 extract_sign_offset.py <path_to_wrapper.node>

Outputs the virtual address offset as hex (e.g. 0x56D81D1) on success.
Exit code 0 on success, 1 on failure.
"""

import struct
import sys

PATTERN = bytes([0x29, 0xf2, 0x4c, 0x8d, 0x44, 0x24])


def read_elf_exec_segment(data):
    """Parse ELF64 program headers, return (p_offset, p_vaddr, p_filesz) for the R+E PT_LOAD segment."""
    if data[:4] != b'\x7fELF':
        raise ValueError("Not an ELF file")
    if data[4] != 2:  # ELFCLASS64
        raise ValueError("Not ELF64")

    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, off)[0]
        p_flags = struct.unpack_from('<I', data, off + 4)[0]
        p_offset = struct.unpack_from('<Q', data, off + 0x08)[0]
        p_vaddr = struct.unpack_from('<Q', data, off + 0x10)[0]
        p_filesz = struct.unpack_from('<Q', data, off + 0x20)[0]

        # PT_LOAD (1) with PF_X (1) executable flag
        if p_type == 1 and (p_flags & 1):
            return p_offset, p_vaddr, p_filesz

    raise ValueError("No executable PT_LOAD segment found")


def extract_sign_offset(wrapper_path):
    with open(wrapper_path, 'rb') as f:
        data = f.read()

    text_offset, text_vaddr, text_size = read_elf_exec_segment(data)
    text_delta = text_vaddr - text_offset

    # Search for pattern in executable segment
    matches = []
    idx = text_offset
    end = text_offset + text_size
    while True:
        idx = data.find(PATTERN, idx, end)
        if idx == -1:
            break
        matches.append(idx)
        idx += 1

    if len(matches) == 0:
        raise ValueError("Pattern not found")
    if len(matches) > 1:
        raise ValueError(f"Pattern matched {len(matches)} times (expected 1)")

    match = matches[0]

    # Verify: preceding 12 bytes must contain 0x8b (mov opcode)
    pre = data[max(0, match - 12):match]
    if 0x8b not in pre:
        raise ValueError("Pre-check failed: no mov instruction before pattern")

    # Verify: stack offset (byte after pattern) in range 0x20..0x80
    stack_offset = data[match + 6]
    if not (0x20 <= stack_offset <= 0x80):
        raise ValueError(f"Stack offset 0x{stack_offset:02x} out of range")

    # Find CALL instruction (0xE8) after the pattern
    e8_offset = None
    for i in range(match + 6, match + 20):
        if data[i] == 0xE8:
            e8_offset = i
            break

    if e8_offset is None:
        raise ValueError("CALL instruction (0xE8) not found after pattern")

    # Parse 4-byte signed relative offset
    disp = struct.unpack_from('<i', data, e8_offset + 1)[0]

    # Calculate target VA
    call_va = e8_offset + text_delta
    target_va = call_va + 5 + disp

    # Verify function prologue
    prologue_file_off = target_va - text_delta
    prologue = data[prologue_file_off:prologue_file_off + 8]
    expected = bytes([0x55, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41])
    if prologue != expected:
        raise ValueError(
            f"Prologue mismatch at 0x{target_va:x}: "
            f"got {prologue.hex()}, expected {expected.hex()}"
        )

    return target_va


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <wrapper.node>", file=sys.stderr)
        sys.exit(1)

    wrapper_path = sys.argv[1]
    try:
        offset = extract_sign_offset(wrapper_path)
        print(f"0x{offset:X}")
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

"""Minimal read-only PE32 helpers for the scanner reference."""

import struct
from collections import namedtuple


Section = namedtuple("Section", ["name", "va", "raw", "raw_size", "image_base"])


def load_pe(path):
    """Load section metadata for a 32-bit x86 PE file."""
    with open(path, "rb") as stream:
        data = stream.read()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not a PE file")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("invalid PE header")

    machine, section_count = struct.unpack_from("<HH", data, pe_offset + 4)
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional_offset = pe_offset + 24
    if machine != 0x14C or optional_size < 32 or optional_offset + optional_size > len(data):
        raise ValueError("only PE32 x86 files are supported by this reference")
    if struct.unpack_from("<H", data, optional_offset)[0] != 0x10B:
        raise ValueError("only PE32 optional headers are supported")
    image_base = struct.unpack_from("<I", data, optional_offset + 28)[0]

    section_offset = optional_offset + optional_size
    if section_offset + section_count * 40 > len(data):
        raise ValueError("truncated PE section table")
    sections = []
    for index in range(section_count):
        offset = section_offset + index * 40
        name = data[offset:offset + 8].rstrip(b"\0").decode("latin1")
        virtual_address = struct.unpack_from("<I", data, offset + 12)[0]
        raw_size = struct.unpack_from("<I", data, offset + 16)[0]
        raw_offset = struct.unpack_from("<I", data, offset + 20)[0]
        sections.append(Section(name, virtual_address, raw_offset, raw_size, image_base))
    return data, sections


def get_image_base(sections):
    if not sections:
        raise ValueError("PE file has no sections")
    return sections[0].image_base


def va2off(data, sections, va):
    if not sections:
        return None
    rva = va - get_image_base(sections)
    for section in sections:
        if section.va <= rva < section.va + section.raw_size:
            offset = section.raw + (rva - section.va)
            return offset if 0 <= offset < len(data) else None
    return None


def read_va(data, sections, va, size):
    offset = va2off(data, sections, va)
    if offset is None or size < 0 or offset + size > len(data):
        return None
    rva = va - get_image_base(sections)
    section = next((item for item in sections
                    if item.va <= rva < item.va + item.raw_size), None)
    if section is None or rva + size > section.va + section.raw_size:
        return None
    return data[offset:offset + size]

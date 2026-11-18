# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
"""Image-free unit tests for PEB read boundaries in
:class:`volatility3.framework.symbols.windows.extensions.EPROCESS`.

A forged or truncated PEB can have a mapped first page while the rest of the
structure (or the page a cross-page field lands on) is unmapped. These tests
build real Intel32/Intel32e translation layers backed by controllable RAM and
verify that:

1. field/structure reads honour page boundaries,
2. legitimate PEBs and absent/default fields keep their previous results, and
3. a failed read never leaves a cached PEB behind, and separate process
   objects cannot observe each other's cached PEB.
"""
import json
import os
import struct
import sys
import tempfile
import unittest

_REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)
sys.path.insert(0, _REPO_ROOT)

from volatility3.framework import constants, contexts, exceptions, interfaces
from volatility3.framework.layers import intel
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import extensions

PAGE = 0x1000
RAM_SIZE = 16 * 1024 * 1024


class RAM(interfaces.layers.DataLayerInterface):
    """Flat RAM backed by a bytearray with selectable unmapped pages."""

    def __init__(self, context, config_path, name, size, metadata=None):
        super().__init__(context, config_path, name, metadata)
        self._size = size
        self.data = bytearray(size)
        self.unmapped = set()

    @property
    def minimum_address(self):
        return 0

    @property
    def maximum_address(self):
        return self._size - 1

    def is_valid(self, offset, length=1):
        if offset < 0 or offset + length > self._size:
            return False
        first = offset // PAGE
        last = (offset + length - 1) // PAGE
        return all(p not in self.unmapped for p in range(first, last + 1))

    def read(self, address, length, pad=False):
        if not self.is_valid(address, length):
            raise exceptions.InvalidAddressException(
                self.name, address, f"Unmapped RAM at {address:#x}"
            )
        return bytes(self.data[address : address + length])

    def write(self, address, data):
        self.data[address : address + len(data)] = data


def _ptr():
    return {"kind": "pointer", "subtype": {"kind": "base", "name": "void"}}


def _base(name):
    return {"kind": "base", "name": name}


def _int(size, signed=False):
    return {"kind": "int", "size": size, "signed": signed, "endian": "little"}


def _base_types(psize):
    return {
        "unsigned long": _int(4),
        "int": _int(4, True),
        "long": _int(4),
        "unsigned long long": _int(8),
        "long long": _int(8, True),
        "unsigned int": _int(4),
        "unsigned short": _int(2),
        "unsigned char": {"kind": "char", "size": 1,
                          "signed": False, "endian": "little"},
        "pointer": _int(psize),
        "void": {"kind": "void", "size": 0,
                 "signed": True, "endian": "little"},
    }


def _mini_isf(arch):
    is64 = arch == "intel32e"
    psize = 8 if is64 else 4
    peb_size = 0x380 if is64 else 0x250
    eprocess_fields = {
        "Peb": (0x100, _ptr()),
        "UniqueProcessId": (0x100 + psize, _ptr()),
        "ImageFileName": (
            0x100 + 2 * psize,
            {"kind": "array", "count": 16,
             "subtype": _base("unsigned char")},
        ),
        "CreateTime": (
            0x100 + 2 * psize + 16,
            {"kind": "struct", "name": "_KSYSTEM_TIME"},
        ),
        "Pcb": (0x200, {"kind": "struct", "name": "_KPROCESS"}),
        "ThreadListHead": (0x300, {"kind": "struct", "name": "_LIST_ENTRY"}),
        "Wow64Process": (
            0x380,
            {"kind": "pointer",
             "subtype": {"kind": "struct", "name": "_EWOW64PROCESS"}},
        ),
    }
    peb_fields = {
        "InheritedAddressSpace": (0, _base("unsigned char")),
        "BeingDebugged": (2, _base("unsigned char")),
        "Ldr": (psize * 2, _ptr()),
        "ProcessParameters": (psize * 3, _ptr()),
        "ImageBaseAddress": (psize * 4, _ptr()),
        "TailField": (peb_size - psize, _ptr()),
    }
    structs = {
        "_EPROCESS": (0x400, eprocess_fields),
        "_KPROCESS": (0x80, {"DirectoryTableBase": (0, _ptr())}),
        "_PEB": (peb_size, peb_fields),
        "_KSYSTEM_TIME": (
            12,
            {
                "LowPart": (0, _base("unsigned long")),
                "High1Time": (4, _base("long")),
                "High2Time": (8, _base("long")),
            },
        ),
        "_LIST_ENTRY": (
            2 * psize,
            {"Flink": (0, _ptr()), "Blink": (psize, _ptr())},
        ),
        "_EWOW64PROCESS": (psize, {"Peb": (0, _ptr())}),
    }
    user_types = {}
    for name, (size, fields) in structs.items():
        user_types[name] = {
            "kind": "struct",
            "size": size,
            "fields": {n: {"offset": o, "type": t} for n, (o, t) in
                       fields.items()},
        }
    return {
        "metadata": {"format": "4.1.0",
                     "producer": {"name": "test", "version": "0.0.1"}},
        "symbols": {},
        "enums": {},
        "base_types": _base_types(psize),
        "user_types": user_types,
    }, peb_size


def _build_world(arch):
    """Returns (ctx, phys, vmem, table_name, peb_size, dtb)."""
    ctx = contexts.Context()
    phys = RAM(ctx, "memory.physical", "memory", RAM_SIZE)
    ctx.add_layer(phys)

    if arch == "intel32":
        pd_pa, pt_pa = 0x100000, 0x101000
        for i in range(1024):
            phys.data[pt_pa + i * 4 : pt_pa + i * 4 + 4] = struct.pack(
                "<I", (i * PAGE) | 0x3
            )
        phys.data[pd_pa : pd_pa + 4] = struct.pack("<I", pt_pa | 0x3)
        layer_cls, dtb = intel.WindowsIntel, pd_pa
    else:
        pml4_pa, pdpt_pa, pd_pa, pt_pa = (0x200000, 0x201000, 0x202000, 0x203000)
        for i in range(2048):
            phys.data[pt_pa + i * 8 : pt_pa + i * 8 + 8] = struct.pack(
                "<Q", (i * PAGE) | 0x3
            )
        for i in range(4):
            phys.data[pd_pa + i * 8 : pd_pa + i * 8 + 8] = struct.pack(
                "<Q", (pt_pa + i * 0x1000) | 0x3
            )
        phys.data[pdpt_pa : pdpt_pa + 8] = struct.pack("<Q", pd_pa | 0x3)
        phys.data[pml4_pa : pml4_pa + 8] = struct.pack("<Q", pdpt_pa | 0x3)
        layer_cls, dtb = intel.WindowsIntel32e, pml4_pa

    ctx.config["vmem.memory_layer"] = "memory"
    ctx.config["vmem.page_map_offset"] = dtb
    vmem = layer_cls(ctx, "vmem", "vmem")
    ctx.add_layer(vmem)

    isf, peb_size = _mini_isf(arch)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as handle:
        json.dump(isf, handle)
        isf_path = handle.name
    try:
        table = intermed.IntermediateSymbolTable(
            ctx, config_path="temporary",
            name=f"mini_{arch}", isf_url=f"file://{isf_path}",
        )
    finally:
        os.unlink(isf_path)
    ctx.symbol_space.append(table)
    table.set_type_class("_EPROCESS", extensions.EPROCESS)
    return ctx, phys, vmem, table.name, peb_size, dtb


def _make_eprocess(ctx, vmem, phys, table, peb_va, dtb, eproc_va=0x4000):
    psize = vmem.bits_per_register // 8
    fmt = "<I" if psize == 4 else "<Q"
    eproc_pa = vmem.translate(eproc_va)[0]
    phys.data[eproc_pa + 0x100 : eproc_pa + 0x100 + psize] = struct.pack(
        fmt, peb_va
    )
    phys.data[eproc_pa + 0x100 + psize : eproc_pa + 0x100 + 2 * psize] = (
        struct.pack(fmt, 0x100)
    )
    phys.data[eproc_pa + 0x200 : eproc_pa + 0x200 + psize] = struct.pack(
        fmt, dtb
    )
    name = b"test.exe\x00"
    phys.data[
        eproc_pa + 0x100 + 2 * psize :
        eproc_pa + 0x100 + 2 * psize + len(name)
    ] = name
    return ctx.object(
        table + constants.BANG + "_EPROCESS",
        layer_name=vmem.name, offset=eproc_va,
    )


class PebBoundaryTests(unittest.TestCase):
    def test_page_boundaries_and_cache_for_arch(self):
        for arch in ("intel32", "intel32e"):
            with self.subTest(arch=arch):
                # 1. fully mapped cross-page PEB is accepted and cached
                ctx, phys, vmem, table, peb_size, dtb = _build_world(arch)
                peb_va = 0x10000 - peb_size + 0x40
                self.assertTrue(vmem.is_valid(peb_va, peb_size))
                eproc = _make_eprocess(ctx, vmem, phys, table, peb_va, dtb)
                peb = eproc.get_peb()
                self.assertEqual(peb.vol.offset, peb_va)
                self.assertIs(eproc.get_peb(), peb)

                # 2. a truncated PEB (last page unmapped) is rejected with a
                #    locatable InvalidAddressException
                ctx, phys, vmem, table, peb_size, dtb = _build_world(arch)
                peb_va = 0x10000 - peb_size + 0x40
                phys.unmapped.add((peb_va + peb_size - 1) // PAGE)
                eproc = _make_eprocess(ctx, vmem, phys, table, peb_va, dtb)
                with self.assertRaises(exceptions.InvalidAddressException) as cm:
                    eproc.get_peb()
                self.assertEqual(cm.exception.invalid_address, peb_va)
                self.assertTrue(cm.exception.layer_name.startswith("vmem_Process"))

                # 3. a fully unmapped PEB page is rejected
                ctx, phys, vmem, table, peb_size, dtb = _build_world(arch)
                phys.unmapped.add(0x7)
                eproc = _make_eprocess(ctx, vmem, phys, table, 0x7000, dtb)
                with self.assertRaises(exceptions.InvalidAddressException):
                    eproc.get_peb()

                # 4. failure must not poison the object cache: once the page
                #    is mapped the retry returns a usable PEB
                ctx, phys, vmem, table, peb_size, dtb = _build_world(arch)
                phys.unmapped.add(0x7)
                eproc = _make_eprocess(ctx, vmem, phys, table, 0x7000, dtb)
                with self.assertRaises(exceptions.InvalidAddressException):
                    eproc.get_peb()
                phys.unmapped.discard(0x7)
                recovered = eproc.get_peb()
                self.assertEqual(recovered.vol.offset, 0x7000)

                # 5. separate EPROCESS objects never share a PEB and a bad
                #    PEB on the second cannot return the first object's cache
                ctx, phys, vmem, table, peb_size, dtb = _build_world(arch)
                eproc_a = _make_eprocess(
                    ctx, vmem, phys, table, 0x5000, dtb, eproc_va=0x4000
                )
                eproc_b = _make_eprocess(
                    ctx, vmem, phys, table, 0x8000, dtb, eproc_va=0x4400
                )
                self.assertIsNot(eproc_a.get_peb(), eproc_b.get_peb())
                eproc_bad = _make_eprocess(
                    ctx, vmem, phys, table, 0x9000, dtb, eproc_va=0x4800
                )
                phys.unmapped.add(0x9)
                with self.assertRaises(exceptions.InvalidAddressException):
                    eproc_bad.get_peb()

    def test_default_and_absent_fields_keep_working(self):
        for arch in ("intel32", "intel32e"):
            with self.subTest(arch=arch):
                # A mapped but all-zero PEB must still construct and expose
                # zero-valued (absent/default) pointer members exactly like
                # the previous behaviour.
                ctx, phys, vmem, table, _peb_size, dtb = _build_world(arch)
                eproc = _make_eprocess(ctx, vmem, phys, table, 0x5000, dtb)
                peb = eproc.get_peb()
                self.assertEqual(int(peb.Ldr), 0)
                self.assertEqual(int(peb.ProcessParameters), 0)
                self.assertIs(peb.Ldr, peb.Ldr)

                # Peb == 0 with the null page unmapped (as on real Windows)
                # keeps raising InvalidAddressException from the first gate.
                ctx, phys, vmem, table, _peb_size, dtb = _build_world(arch)
                phys.unmapped.add(0)
                eproc = _make_eprocess(ctx, vmem, phys, table, 0, dtb)
                with self.assertRaises(exceptions.InvalidAddressException):
                    eproc.get_peb()

    def test_get_peb32_boundaries_and_contract(self):
        # WOW64 path uses the 32-bit wow64 symbol table
        ctx, phys, vmem, _t, _s, dtb = _build_world("intel32")
        wow_table = (
            __import__(
                "volatility3.framework.symbols.windows",
                fromlist=["WindowsKernelIntermedSymbols"],
            ).WindowsKernelIntermedSymbols.create(
                ctx, "temporary", "windows", "wow64"
            )
        )
        peb32_size = ctx.symbol_space.get_type(
            wow_table + constants.BANG + "_PEB32"
        ).size
        table = next(
            n for n in ctx.symbol_space
            if n.startswith("mini_intel32")
        )

        # valid cross-page PEB32 through the full get_peb32() call chain
        peb32_va = 0x10000 - peb32_size + 0x20
        ewow_va = 0xA000
        ewow_pa = vmem.translate(ewow_va)[0]
        phys.data[ewow_pa : ewow_pa + 4] = struct.pack("<I", peb32_va)
        eproc_pa = vmem.translate(0x4000)[0]
        phys.data[eproc_pa + 0x380 : eproc_pa + 0x384] = struct.pack(
            "<I", ewow_va
        )
        phys.data[eproc_pa + 0x200 : eproc_pa + 0x204] = struct.pack(
            "<I", dtb
        )
        eproc = ctx.object(
            table + constants.BANG + "_EPROCESS",
            layer_name="vmem", offset=0x4000,
        )
        self.assertTrue(eproc.get_is_wow64())
        peb32 = eproc.get_peb32()
        self.assertEqual(peb32.vol.offset, peb32_va)
        self.assertIs(eproc.get_peb32(), peb32)

        # truncated PEB32 -> locatable InvalidAddressException
        ctx, phys, vmem, _t, _s, dtb = _build_world("intel32")
        phys.unmapped.add((peb32_va + peb32_size - 1) // PAGE)
        ewow_pa = vmem.translate(ewow_va)[0]
        phys.data[ewow_pa : ewow_pa + 4] = struct.pack("<I", peb32_va)
        eproc_pa = vmem.translate(0x4000)[0]
        phys.data[eproc_pa + 0x380 : eproc_pa + 0x384] = struct.pack(
            "<I", ewow_va
        )
        phys.data[eproc_pa + 0x200 : eproc_pa + 0x204] = struct.pack(
            "<I", dtb
        )
        table = next(n for n in ctx.symbol_space if n.startswith("mini_intel32"))
        eproc = ctx.object(
            table + constants.BANG + "_EPROCESS",
            layer_name="vmem", offset=0x4000,
        )
        with self.assertRaises(exceptions.InvalidAddressException) as cm:
            eproc.get_peb32()
        self.assertEqual(cm.exception.invalid_address, peb32_va)

        # non-WOW64 process still returns None
        ctx, phys, vmem, table, _s, dtb = _build_world("intel32")
        eproc = _make_eprocess(ctx, vmem, phys, table, 0x5000, dtb)
        self.assertIsNone(eproc.get_peb32())


if __name__ == "__main__":
    unittest.main()

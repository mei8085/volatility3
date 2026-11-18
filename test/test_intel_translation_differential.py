"""Differential unit tests for Intel page-table translation layers.

These tests run the same synthetic page tables through two read strategies
(bulk reads versus byte-by-byte reads) and under different page-table cache
states (cold versus warmed), and require the outcomes to agree.

Only local synthetic memory layers (``physical.BufferDataLayer``) are used,
so the tests need no memory image and run under the existing pytest entry
point, e.g. ``pytest test/test_intel_translation_differential.py
--volatility=vol.py``.

Differential results are recorded separately as:

1. the virtual-to-physical mapping (``TranslationProbe.va_pa_map``),
2. the cross-page failure offset (``TranslationProbe.failure_offset`` and
   ``TranslationProbe.read_fail_va`` together with
   ``TranslationProbe.remaining_length``),
3. the cache state the record was captured under
   (``TranslationProbe.cache_state``), which must never change the result
   and must not keep a stale mapping alive after a bad entry is fixed.
"""

import dataclasses
import struct
from typing import List, Optional, Tuple, Type

import pytest

from volatility3.framework import contexts, exceptions, interfaces
from volatility3.framework.interfaces.configuration import path_join
from volatility3.framework.layers import intel, physical

PAGE_SIZE = 0x1000
PRESENT_RW = 0x3

# Physical layout of the synthetic 64-bit (Intel32e) memory
PML4 = 0x1000
PDPT = 0x2000
PD = 0x3000
PT = 0x4000
PDPT_HIGH = 0x5000
PD_HIGH = 0x6000
PT_HIGH = 0x7000
DATA1 = 0x10000
DATA2 = 0x11000
DATA3 = 0x12000
DATA4 = 0x20000

# PTE with the Linux PROT_NONE bit set and the PRESENT bit clear.  The PFN
# field is chosen so that the Linux inversion yields physical page DATA1.
PROTNONE_ENTRY = 0x3FFFFFFEF100
# PTE with the Windows transition bit (11) set and the PRESENT bit clear.
TRANSITION_ENTRY = 0x10000 | (1 << 11)

# Virtual addresses inside the synthetic 64-bit tables
VA_PAGE1 = 0x1000
VA_PAGE2 = 0x2000
VA_UNMAPPED = 0x3000
VA_PAGE4 = 0x4000
VA_PROTNONE = 0x8000
VA_TRANSITION = 0x9000
VA_HIGH_CANONICAL = 0xFFFF800000000000

CACHE_STATES = ("cold", "warm")


def _set_entry64(buffer: bytearray, table: int, index: int, value: int) -> None:
    struct.pack_into("<Q", buffer, table + index * 8, value)


def _set_entry32(buffer: bytearray, table: int, index: int, value: int) -> None:
    struct.pack_into("<I", buffer, table + index * 4, value)


def build_buffer_64() -> bytearray:
    """Synthetic physical memory holding a 4-level Intel32e page table.

    VA_PAGE1 -> DATA1, VA_PAGE2 -> DATA2 (physically contiguous with DATA1),
    VA_UNMAPPED unmapped, VA_PAGE4 -> DATA3, VA_PROTNONE a Linux PROT_NONE
    entry, VA_TRANSITION a Windows transition entry and the high canonical
    VA_HIGH_CANONICAL -> DATA4.
    """
    buffer = bytearray(DATA4 + PAGE_SIZE)
    for address, fill in (
        (DATA1, 0xAA),
        (DATA2, 0xBB),
        (DATA3, 0xCC),
        (DATA4, 0xDD),
    ):
        buffer[address : address + PAGE_SIZE] = bytes([fill]) * PAGE_SIZE
    _set_entry64(buffer, PML4, 0, PDPT | PRESENT_RW)
    _set_entry64(buffer, PML4, 0x100, PDPT_HIGH | PRESENT_RW)
    _set_entry64(buffer, PDPT, 0, PD | PRESENT_RW)
    _set_entry64(buffer, PD, 0, PT | PRESENT_RW)
    _set_entry64(buffer, PDPT_HIGH, 0, PD_HIGH | PRESENT_RW)
    _set_entry64(buffer, PD_HIGH, 0, PT_HIGH | PRESENT_RW)
    _set_entry64(buffer, PT, 1, DATA1 | PRESENT_RW)
    _set_entry64(buffer, PT, 2, DATA2 | PRESENT_RW)
    # PT[3] is left zero: VA_UNMAPPED is not present
    _set_entry64(buffer, PT, 4, DATA3 | PRESENT_RW)
    _set_entry64(buffer, PT, 8, PROTNONE_ENTRY)
    _set_entry64(buffer, PT, 9, TRANSITION_ENTRY)
    _set_entry64(buffer, PT_HIGH, 0, DATA4 | PRESENT_RW)
    return buffer


def build_buffer_32() -> bytearray:
    """Synthetic physical memory holding a 2-level 32-bit Intel page table
    mapping the first and the very last 32-bit virtual pages."""
    pd32, pt32, pt32_last = 0x1000, 0x2000, 0x3000
    data_first, data_last = 0x10000, 0x11000
    buffer = bytearray(data_last + PAGE_SIZE)
    buffer[data_first : data_first + PAGE_SIZE] = bytes([0xAA]) * PAGE_SIZE
    buffer[data_last : data_last + PAGE_SIZE] = bytes([0xBB]) * PAGE_SIZE
    _set_entry32(buffer, pd32, 0, pt32 | PRESENT_RW)
    _set_entry32(buffer, pd32, 1023, pt32_last | PRESENT_RW)
    _set_entry32(buffer, pt32, 1, data_first | PRESENT_RW)
    _set_entry32(buffer, pt32_last, 1023, data_last | PRESENT_RW)
    return buffer


def build_layer(
    buffer: bytearray,
    layer_class: Type[intel.Intel] = intel.Intel32e,
    page_map_offset: int = PML4,
    name: str = "translation",
) -> Tuple[contexts.Context, interfaces.layers.TranslationLayerInterface]:
    """Build a context with a single synthetic physical layer and a
    translation layer of ``layer_class`` on top of it."""
    context = contexts.Context()
    memory = physical.BufferDataLayer(context, "memory", "memory", buffer)
    context.layers.add_layer(memory)
    config_path = path_join("test_translation", name)
    context.config[path_join(config_path, "memory_layer")] = "memory"
    context.config[path_join(config_path, "page_map_offset")] = page_map_offset
    layer = layer_class(context, config_path=config_path, name=name)
    context.layers.add_layer(layer)
    return context, layer


def clear_translation_caches(layer: intel.Intel) -> None:
    """Drop every cached page-table walk and read of ``layer``."""
    layer.read.cache_clear()
    layer._translate_entry.cache_clear()
    layer._get_valid_table.cache_clear()


@dataclasses.dataclass(frozen=True)
class TranslationProbe:
    """One differential record for a virtual address range.

    The three recorded differential results are kept in separate fields:
    ``va_pa_map`` (virtual-to-physical mapping), ``failure_offset`` /
    ``read_fail_va`` / ``remaining_length`` (cross-page failure position)
    and ``cache_state`` (the page-table cache state when captured).
    """

    cache_state: str
    strategy: str
    va_pa_map: Tuple[Tuple[int, Optional[int]], ...]
    failure_offset: Optional[int]
    read_fail_va: Optional[int]
    remaining_length: int


def _probe_bulk(layer, base: int, length: int, cache_state: str) -> TranslationProbe:
    """Record a probe using a single bulk mapping/read of the range."""
    chunks = list(layer.mapping(base, length, ignore_errors=True))
    mapped = {}
    failure_offset = None
    expected = base
    mapped_total = 0
    for offset, size, mapped_offset, _mapped_size, _layer_name in chunks:
        if failure_offset is None and offset > expected:
            failure_offset = expected
        for i in range(size):
            mapped[offset + i - base] = mapped_offset + i
        expected = offset + size
        mapped_total += size
    if failure_offset is None and expected < base + length:
        failure_offset = expected
    va_pa_map = tuple((base + i, mapped.get(i)) for i in range(length))
    try:
        layer.read(base, length)
        read_fail_va = None
    except exceptions.InvalidAddressException as exc:
        read_fail_va = exc.invalid_address
    return TranslationProbe(
        cache_state,
        "bulk",
        va_pa_map,
        failure_offset,
        read_fail_va,
        length - mapped_total,
    )


def _probe_byte(layer, base: int, length: int, cache_state: str) -> TranslationProbe:
    """Record a probe reading and mapping the range one byte at a time."""
    va_pa: List[Tuple[int, Optional[int]]] = []
    failure_offset = None
    read_fail_va = None
    mapped_total = 0
    for i in range(length):
        va = base + i
        try:
            chunk = list(layer.mapping(va, 1))
            pa: Optional[int] = chunk[0][2] if len(chunk) == 1 else None
        except exceptions.InvalidAddressException:
            pa = None
        va_pa.append((va, pa))
        if pa is None:
            if failure_offset is None:
                failure_offset = va
        else:
            mapped_total += 1
        try:
            layer.read(va, 1)
        except exceptions.InvalidAddressException as exc:
            if read_fail_va is None:
                read_fail_va = exc.invalid_address
    return TranslationProbe(
        cache_state,
        "byte",
        tuple(va_pa),
        failure_offset,
        read_fail_va,
        length - mapped_total,
    )


def probe(
    layer, base: int, length: int, strategy: str, cache_state: str
) -> TranslationProbe:
    """Record a probe of ``[base, base + length)`` under a cache state.

    ``cold`` clears all page-table caches immediately before probing,
    ``warm`` first populates the caches with an identical throwaway probe.
    """
    if cache_state not in CACHE_STATES:
        raise ValueError(f"Unknown cache state {cache_state}")
    clear_translation_caches(layer)
    if cache_state == "warm":
        _probe_bulk(layer, base, length, cache_state)
        _probe_byte(layer, base, length, cache_state)
    if strategy == "bulk":
        return _probe_bulk(layer, base, length, cache_state)
    if strategy == "byte":
        return _probe_byte(layer, base, length, cache_state)
    raise ValueError(f"Unknown strategy {strategy}")


def assert_same_mapping(
    reference: TranslationProbe, candidate: TranslationProbe
) -> None:
    """Assert the virtual-to-physical mappings of two probes agree, with
    the virtual address, physical address and failure position recorded as
    independent assertions."""
    assert len(reference.va_pa_map) == len(candidate.va_pa_map)
    for (ref_va, ref_pa), (cand_va, cand_pa) in zip(
        reference.va_pa_map, candidate.va_pa_map
    ):
        assert ref_va == cand_va, (
            f"virtual address mismatch between {reference.strategy}/"
            f"{reference.cache_state} and {candidate.strategy}/"
            f"{candidate.cache_state}"
        )
        assert ref_pa == cand_pa, (
            f"physical address mismatch at virtual address {hex(ref_va)}: "
            f"{reference.strategy}/{reference.cache_state} mapped "
            f"{None if ref_pa is None else hex(ref_pa)} but "
            f"{candidate.strategy}/{candidate.cache_state} mapped "
            f"{None if cand_pa is None else hex(cand_pa)}"
        )


def assert_same_failure(
    reference: TranslationProbe, candidate: TranslationProbe
) -> None:
    """Assert two probes failed at the same offset with the same remaining
    length."""
    assert reference.failure_offset == candidate.failure_offset, (
        f"failure offset mismatch: {reference.strategy}/"
        f"{reference.cache_state} failed at {reference.failure_offset!r}, "
        f"{candidate.strategy}/{candidate.cache_state} at "
        f"{candidate.failure_offset!r}"
    )
    assert reference.read_fail_va == candidate.read_fail_va, (
        f"read failure position mismatch: {reference.strategy}/"
        f"{reference.cache_state} reported {reference.read_fail_va!r}, "
        f"{candidate.strategy}/{candidate.cache_state} reported "
        f"{candidate.read_fail_va!r}"
    )
    assert reference.remaining_length == candidate.remaining_length, (
        f"remaining length mismatch: {reference.strategy}/"
        f"{reference.cache_state} left {reference.remaining_length}, "
        f"{candidate.strategy}/{candidate.cache_state} left "
        f"{candidate.remaining_length}"
    )


# Cross-page range: starts near the end of VA_PAGE1, spans VA_PAGE2 and
# ends inside the unmapped VA_UNMAPPED page.
CROSS_PAGE_BASE = 0x1F00
CROSS_PAGE_LENGTH = 0x1200


@pytest.mark.parametrize("cache_state", CACHE_STATES)
def test_virtual_to_physical_mapping_bulk_matches_byte(cache_state):
    """Differential record 1: bulk and byte-by-byte strategies must produce
    the same virtual-to-physical mapping across a cross-page range."""
    _context, layer = build_layer(build_buffer_64())
    bulk = probe(layer, CROSS_PAGE_BASE, CROSS_PAGE_LENGTH, "bulk", cache_state)
    byte = probe(layer, CROSS_PAGE_BASE, CROSS_PAGE_LENGTH, "byte", cache_state)

    assert_same_mapping(bulk, byte)

    # Independent assertions on individual virtual/physical addresses
    pa_of = dict(bulk.va_pa_map)
    assert pa_of[CROSS_PAGE_BASE] == DATA1 + 0xF00
    assert pa_of[0x1FFF] == DATA1 + 0xFFF
    assert pa_of[VA_PAGE2] == DATA2
    assert pa_of[0x2FFF] == DATA2 + 0xFFF
    assert pa_of[VA_UNMAPPED] is None


@pytest.mark.parametrize("cache_state", CACHE_STATES)
def test_cross_page_failure_offset_bulk_matches_byte(cache_state):
    """Differential record 2: bulk and byte-by-byte strategies must report
    the same cross-page failure offset and remaining length."""
    _context, layer = build_layer(build_buffer_64())
    bulk = probe(layer, CROSS_PAGE_BASE, CROSS_PAGE_LENGTH, "bulk", cache_state)
    byte = probe(layer, CROSS_PAGE_BASE, CROSS_PAGE_LENGTH, "byte", cache_state)

    assert_same_failure(bulk, byte)

    # Independent assertions on the failure position and remaining length
    assert bulk.failure_offset == VA_UNMAPPED
    assert bulk.read_fail_va == VA_UNMAPPED
    assert bulk.remaining_length == CROSS_PAGE_LENGTH - (VA_UNMAPPED - CROSS_PAGE_BASE)


def test_cache_states_produce_identical_records():
    """Differential record 3: cold and warm page-table cache states must
    not change any recorded result."""
    _context, layer = build_layer(build_buffer_64())
    records = {
        (strategy, cache_state): probe(
            layer, CROSS_PAGE_BASE, CROSS_PAGE_LENGTH, strategy, cache_state
        )
        for strategy in ("bulk", "byte")
        for cache_state in CACHE_STATES
    }
    reference = records[("bulk", "cold")]
    for record in records.values():
        assert record.cache_state in CACHE_STATES
        assert_same_mapping(reference, record)
        assert_same_failure(reference, record)


def test_cross_page_read_content_bulk_matches_byte():
    """A bulk read spanning two mapped pages returns the same bytes as
    byte-by-byte reads."""
    _context, layer = build_layer(build_buffer_64())
    base, length = 0x1800, 0x1000
    clear_translation_caches(layer)
    bulk_data = layer.read(base, length)
    clear_translation_caches(layer)
    byte_data = b"".join(layer.read(base + i, 1) for i in range(length))

    assert bulk_data == byte_data
    assert bulk_data == bytes([0xAA]) * 0x800 + bytes([0xBB]) * 0x800


@pytest.mark.parametrize("cache_state", CACHE_STATES)
def test_permission_conflict_protnone_linux_maps_intel_faults(cache_state):
    """Permission conflict: a PROT_NONE entry (PRESENT clear) is valid for
    the Linux layer but faults on the plain Intel layer."""
    buffer = build_buffer_64()
    _context, linux_layer = build_layer(buffer, intel.LinuxIntel32e, name="linux")
    _context2, intel_layer = build_layer(buffer, intel.Intel32e, name="intel")

    for layer in (linux_layer, intel_layer):
        clear_translation_caches(layer)
        if cache_state == "warm":
            with pytest.raises(exceptions.InvalidAddressException):
                # Populate the caches with a neighbouring unmapped address
                layer.read(VA_UNMAPPED, 1)

    # Linux: PROT_NONE counts as present, the PFN is inverted onto DATA1
    linux_pa, linux_base = linux_layer.translate(VA_PROTNONE)
    assert linux_pa == DATA1
    assert linux_base == "memory"
    assert linux_layer.read(VA_PROTNONE, 4) == bytes([0xAA]) * 4

    # Intel: PRESENT is clear, so the very same entry faults at VA_PROTNONE
    with pytest.raises(exceptions.PagedInvalidAddressException) as excinfo:
        intel_layer.translate(VA_PROTNONE)
    assert excinfo.value.invalid_address == VA_PROTNONE
    assert excinfo.value.invalid_bits == 12


@pytest.mark.parametrize("cache_state", CACHE_STATES)
def test_permission_conflict_transition_windows_maps_intel_faults(cache_state):
    """Permission conflict: a Windows transition entry (bit 11, PRESENT
    clear) is valid for the Windows layer but faults on the plain Intel
    and Linux layers."""
    buffer = build_buffer_64()
    _context, windows_layer = build_layer(buffer, intel.WindowsIntel32e, name="windows")
    _context2, intel_layer = build_layer(buffer, intel.Intel32e, name="intel")
    _context3, linux_layer = build_layer(buffer, intel.LinuxIntel32e, name="linux")

    for layer in (windows_layer, intel_layer, linux_layer):
        clear_translation_caches(layer)
        if cache_state == "warm":
            with pytest.raises(exceptions.InvalidAddressException):
                # Populate the caches with a neighbouring unmapped address
                layer.read(VA_UNMAPPED, 1)

    windows_pa, windows_base = windows_layer.translate(VA_TRANSITION)
    assert windows_pa == DATA1
    assert windows_base == "memory"

    for layer in (intel_layer, linux_layer):
        with pytest.raises(exceptions.PagedInvalidAddressException) as excinfo:
            layer.translate(VA_TRANSITION)
        assert excinfo.value.invalid_address == VA_TRANSITION
        assert excinfo.value.invalid_bits == 12


@pytest.mark.parametrize("cache_state", CACHE_STATES)
def test_address_width_boundaries_32bit(cache_state):
    """Address width boundary: the last 32-bit page is reachable, and a
    read crossing the 32-bit boundary fails at the same position for bulk
    and byte-by-byte reads."""
    _context, layer = build_layer(
        build_buffer_32(), intel.Intel, page_map_offset=0x1000
    )
    assert layer.maximum_address == 0xFFFFFFFF

    last_page = 0xFFFFF000
    bulk = probe(layer, last_page, PAGE_SIZE, "bulk", cache_state)
    byte = probe(layer, last_page, PAGE_SIZE, "byte", cache_state)
    assert_same_mapping(bulk, byte)
    assert bulk.failure_offset is None
    assert bulk.remaining_length == 0

    pa_of = dict(bulk.va_pa_map)
    assert pa_of[last_page] == 0x11000
    assert pa_of[0xFFFFFFFF] == 0x11FFF
    assert layer.read(0xFFFFFFFC, 4) == bytes([0xBB]) * 4

    # Crossing the 32-bit address boundary fails at 2**32 for both strategies
    bulk = probe(layer, 0xFFFFF800, PAGE_SIZE, "bulk", cache_state)
    byte = probe(layer, 0xFFFFF800, PAGE_SIZE, "byte", cache_state)
    assert_same_failure(bulk, byte)
    assert bulk.failure_offset == 0x100000000
    assert bulk.read_fail_va == 0x100000000
    assert bulk.remaining_length == 0x800


@pytest.mark.parametrize("cache_state", CACHE_STATES)
def test_address_width_boundaries_64bit(cache_state):
    """Address width boundary: the 48-bit virtual space ends at 2**48 - 1,
    high canonical addresses translate, and the fault level differs between
    a missing PML4 entry and a missing page-table entry."""
    _context, layer = build_layer(build_buffer_64())
    assert layer.maximum_address == 0xFFFFFFFFFFFF
    assert layer.canonicalize(1 << 47) == VA_HIGH_CANONICAL

    # High canonical address maps through PML4[0x100] like a low address
    bulk = probe(layer, VA_HIGH_CANONICAL, 0x1800, "bulk", cache_state)
    byte = probe(layer, VA_HIGH_CANONICAL, 0x1800, "byte", cache_state)
    assert_same_mapping(bulk, byte)
    assert_same_failure(bulk, byte)
    pa_of = dict(bulk.va_pa_map)
    assert pa_of[VA_HIGH_CANONICAL] == DATA4
    assert pa_of[VA_HIGH_CANONICAL + 0xFFF] == DATA4 + 0xFFF
    assert bulk.failure_offset == VA_HIGH_CANONICAL + PAGE_SIZE
    assert bulk.remaining_length == 0x800

    # Top of the low canonical range misses on the PML4 entry, leaving all
    # 39 lower bits undetermined
    clear_translation_caches(layer)
    with pytest.raises(exceptions.PagedInvalidAddressException) as excinfo:
        layer.translate(0x7FFFFFFFFFFF)
    assert excinfo.value.invalid_address == 0x7FFFFFFFF000
    assert excinfo.value.invalid_bits == 39

    # A missing leaf entry misses at the page-table level (12 bits)
    with pytest.raises(exceptions.PagedInvalidAddressException) as excinfo:
        layer.translate(VA_UNMAPPED)
    assert excinfo.value.invalid_address == VA_UNMAPPED
    assert excinfo.value.invalid_bits == 12


def test_bad_entry_does_not_leak_into_following_pages():
    """A bad entry must not poison the translation of the pages after it:
    the mapped page following the unmapped one keeps its own physical
    address in both strategies and cache states."""
    _context, layer = build_layer(build_buffer_64())
    base, length = VA_UNMAPPED, 0x2000
    for cache_state in CACHE_STATES:
        bulk = probe(layer, base, length, "bulk", cache_state)
        byte = probe(layer, base, length, "byte", cache_state)
        assert_same_mapping(bulk, byte)
        assert_same_failure(bulk, byte)
        pa_of = dict(bulk.va_pa_map)
        assert pa_of[VA_UNMAPPED] is None
        assert pa_of[VA_PAGE4] == DATA3
        assert bulk.failure_offset == VA_UNMAPPED
        assert bulk.remaining_length == PAGE_SIZE


def test_no_stale_mapping_after_bad_entry_is_fixed():
    """After a bad entry is fixed in the synthetic memory and the caches
    are cleared, the layer must use the new mapping and agree with a
    freshly built layer: no stale mapping may survive."""
    buffer = build_buffer_64()
    _context, layer = build_layer(buffer)

    # The entry starts bad in every cache state
    before = probe(layer, VA_UNMAPPED, PAGE_SIZE, "bulk", "cold")
    assert before.failure_offset == VA_UNMAPPED
    assert dict(before.va_pa_map)[VA_UNMAPPED] is None

    # Fix the bad entry to point at DATA4 and break the following one
    _set_entry64(buffer, PT, 3, DATA4 | PRESENT_RW)
    _set_entry64(buffer, PT, 4, 0)
    clear_translation_caches(layer)

    # A fresh layer over the same memory is the reference
    _context_ref, reference_layer = build_layer(buffer, name="reference")

    for cache_state in CACHE_STATES:
        candidate = probe(layer, VA_UNMAPPED, PAGE_SIZE, "bulk", cache_state)
        reference = probe(reference_layer, VA_UNMAPPED, PAGE_SIZE, "bulk", cache_state)
        assert_same_mapping(reference, candidate)
        assert_same_failure(reference, candidate)

    pa_of = dict(probe(layer, VA_UNMAPPED, PAGE_SIZE, "bulk", "cold").va_pa_map)
    assert pa_of[VA_UNMAPPED] == DATA4
    # The entry broken by the mutation must now fault at its own address
    after = probe(layer, VA_PAGE4, PAGE_SIZE, "bulk", "cold")
    assert after.failure_offset == VA_PAGE4
    assert dict(after.va_pa_map)[VA_PAGE4] is None

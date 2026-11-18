"""Integrity tests for DKOM double-linked process list enumeration.

DKOM (Direct Kernel Object Manipulation) rootkits hide processes by corrupting
the circular ``PsActiveProcessHead`` list: an ``ActiveProcessLinks`` entry is
pointed at unmapped memory, at a partially mapped page, or rearranged into a
cycle that never reaches the sentinel.  When volatility3 walks that list (the
``LIST_ENTRY.to_list`` iterator used by ``windows.pslist.PsList``), a walk over
corrupted memory must satisfy three criteria:

1. Termination: the walk always ends.  It is bounded by the set of links
   already visited and by unreadable pointers, so a cycle or an out-of-bounds
   pointer cannot make it loop or raise ``InvalidAddressException`` midway.
2. Uniqueness: every reachable ``EPROCESS`` is delivered at most once, even
   though ``PsList`` walks the list forward and then backward.
3. Post-failure state: the first unreadable link ends the walk.  Nothing that
   merely follows the corrupt node in memory is reported as a valid list
   entry, the iterator is exhausted, and a later scan starts from a clean
   slate instead of reusing state from the failed one.

The tests build small synthetic memory images offline (a minimal ISF symbol
table plus a sparse buffer layer) so every failure position can be exercised
deterministically: start at the sentinel or at any node, break the first,
middle or last link, walk forward or backward, and break it with an unmapped,
canonical or null pointer.

They are plain unit tests and need no memory image.  The repository-level
``conftest.py`` requires the ``--volatility`` option, so run them with::

    python3 -m pytest test/test_windows_process_list_integrity.py --volatility=vol.py
"""

import itertools
import json
import struct
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

import pytest

from volatility3.framework import contexts
from volatility3.framework.layers import physical
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import extensions
from volatility3.plugins.windows.pslist import PsList

SYMBOL_TABLE = "test"
KERNEL_MODULE = "kernel"
LAYER_NAME = "memory"
EPROCESS_TYPE = f"{SYMBOL_TABLE}!_EPROCESS"
LINK_MEMBER = "ActiveProcessLinks"

POINTER_SIZE = 8
LIST_ENTRY_SIZE = 2 * POINTER_SIZE
# Offset of ActiveProcessLinks and UniqueProcessId within _EPROCESS
LINK_OFFSET = 0x10
PID_OFFSET = 0x30
EPROCESS_SIZE = 0x80
PID_LINK_OFFSET = PID_OFFSET - LINK_OFFSET

BUFFER_SIZE = 0x4000
MODULE_OFFSET = 0x1000
SYMBOL_ADDRESS = 0x100
HEAD = MODULE_OFFSET + SYMBOL_ADDRESS
A, B, C = 0x1800, 0x1900, 0x1A00
RING = (HEAD, A, B, C)
PIDS = {A: 4, B: 100, C: 200}
# Plausible but unreferenced structure planted behind a corrupt link.
DECOY_LINK = 0x2800
DECOY_PID = 0xDEAD
# A link with only its Flink mapped; its Blink falls off the end of memory.
PARTIAL_LINK = 0x1FF8
MAX_STEPS = 32

# Pointer values that never resolve to mapped memory.
OOB_POINTERS = [
    pytest.param(0xDEAD0000, id="unmapped"),
    pytest.param(0xFFFF800000000000, id="canonical-high"),
    pytest.param(0, id="null"),
]

FAULT_LOCATIONS = [
    pytest.param(HEAD, id="head"),
    pytest.param(A, id="first"),
    pytest.param(B, id="middle"),
    pytest.param(C, id="last"),
]

DIRECTIONS = [
    pytest.param(True, id="forward"),
    pytest.param(False, id="backward"),
]


def _isf() -> Dict:
    """A minimal 64-bit intermediate symbol table for process lists."""
    return {
        "metadata": {
            "format": "6.1.0",
            "producer": {"name": "volatility3-unit-test", "version": "1.0.0"},
        },
        "base_types": {
            "pointer": {
                "kind": "int",
                "size": POINTER_SIZE,
                "signed": False,
                "endian": "little",
            },
            "unsigned long": {
                "kind": "int",
                "size": 4,
                "signed": False,
                "endian": "little",
            },
        },
        "user_types": {
            "_LIST_ENTRY": {
                "kind": "struct",
                "size": LIST_ENTRY_SIZE,
                "fields": {
                    "Flink": {
                        "offset": 0,
                        "type": {
                            "kind": "pointer",
                            "subtype": {"kind": "struct", "name": "_LIST_ENTRY"},
                        },
                    },
                    "Blink": {
                        "offset": POINTER_SIZE,
                        "type": {
                            "kind": "pointer",
                            "subtype": {"kind": "struct", "name": "_LIST_ENTRY"},
                        },
                    },
                },
            },
            "_EPROCESS": {
                "kind": "struct",
                "size": EPROCESS_SIZE,
                "fields": {
                    LINK_MEMBER: {
                        "offset": LINK_OFFSET,
                        "type": {"kind": "struct", "name": "_LIST_ENTRY"},
                    },
                    "UniqueProcessId": {
                        "offset": PID_OFFSET,
                        "type": {"kind": "base", "name": "unsigned long"},
                    },
                },
            },
        },
        "enums": {},
        "symbols": {"PsActiveProcessHead": {"address": SYMBOL_ADDRESS}},
    }


def _valid_regions(holes: Iterable[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Subtract unmapped ``[start, end)`` holes from the full address range."""
    regions = [(0, BUFFER_SIZE)]
    for hole_start, hole_end in holes:
        remaining = []
        for start, stop in regions:
            if hole_end <= start or stop <= hole_start:
                remaining.append((start, stop))
                continue
            if start < hole_start:
                remaining.append((start, hole_start))
            if hole_end < stop:
                remaining.append((hole_end, stop))
        regions = remaining
    return regions


class SparseBufferDataLayer(physical.BufferDataLayer):
    """A buffer layer with explicit valid regions and true pointer masking.

    ``BufferDataLayer`` derives its address mask from the buffer size, which
    would alias large pointers back into the buffer and hide out-of-bounds
    bugs.  Kernel pointers are not truncated that way, so this layer keeps a
    full-width pointer mask and lets tests remove byte ranges to model
    unmapped memory.
    """

    def __init__(
        self,
        context: contexts.Context,
        config_path: str,
        name: str,
        buffer: bytes,
        regions: Sequence[Tuple[int, int]],
        pointer_bits: int = POINTER_SIZE * 8,
    ) -> None:
        self._regions = tuple(regions)
        self._address_mask = (1 << pointer_bits) - 1
        super().__init__(
            context=context, config_path=config_path, name=name, buffer=buffer
        )

    @property
    def address_mask(self) -> int:
        return self._address_mask

    def is_valid(self, offset: int, length: int = 1) -> bool:
        end = offset + length
        return any(start <= offset and end <= stop for start, stop in self._regions)


class MemoryImage:
    """A synthetic address space containing a circular process list."""

    def __init__(
        self,
        ring: Sequence[int] = RING,
        pids: Optional[Dict[int, int]] = None,
    ) -> None:
        self._ring = tuple(ring)
        self._buffer = bytearray(BUFFER_SIZE)
        self._holes: List[Tuple[int, int]] = []
        self._context: Optional[contexts.Context] = None
        for index, link in enumerate(self._ring):
            self._write_pointer(
                link, "Flink", self._ring[(index + 1) % len(self._ring)]
            )
            self._write_pointer(link, "Blink", self._ring[index - 1])
        for link, pid in (pids if pids is not None else PIDS).items():
            struct.pack_into("<I", self._buffer, link + PID_LINK_OFFSET, pid)

    @staticmethod
    def _pointer_offset(link: int, direction: str) -> int:
        return link + (0 if direction == "Flink" else POINTER_SIZE)

    def _write_pointer(self, link: int, direction: str, value: int) -> None:
        struct.pack_into(
            "<Q", self._buffer, self._pointer_offset(link, direction), value
        )

    def set_pointer(self, link: int, direction: str, value: int) -> None:
        """Point a link at ``value``, both in the image and in the live layer."""
        self._write_pointer(link, direction, value)
        if self._context is not None:
            self._context.layers[LAYER_NAME].write(
                self._pointer_offset(link, direction), struct.pack("<Q", value)
            )

    def drop_link(self, link: int) -> None:
        """Make a node's own ``_LIST_ENTRY`` unreadable; call before ``build``.

        The hole covers exactly the sixteen link bytes, so only that node is
        lost and its neighbours stay untouched.
        """
        self._holes.append((link, link + LIST_ENTRY_SIZE))

    def make_partial_link(self, link: int) -> None:
        """Leave a node's Flink mapped and place its Blink outside memory."""
        self._holes.append((link + POINTER_SIZE, link + LIST_ENTRY_SIZE))

    def add_decoy(self, link: int, pid: int = DECOY_PID) -> None:
        """Plant a plausible process that no list pointer references."""
        self._write_pointer(link, "Flink", link)
        self._write_pointer(link, "Blink", link)
        struct.pack_into("<I", self._buffer, link + PID_LINK_OFFSET, pid)

    def build(self, tmp_path) -> contexts.Context:
        """Create a context whose kernel module is this image."""
        isf_path = tmp_path / "process_list.json"
        isf_path.write_text(json.dumps(_isf()))
        context = contexts.Context()
        context.layers.add_layer(
            SparseBufferDataLayer(
                context,
                "cfg",
                LAYER_NAME,
                bytes(self._buffer),
                _valid_regions(self._holes),
            )
        )
        table = intermed.IntermediateSymbolTable(
            context,
            "cfg",
            SYMBOL_TABLE,
            isf_path.as_uri(),
            validate=False,
            class_types={"_LIST_ENTRY": extensions.LIST_ENTRY},
        )
        context.symbol_space.append(table)
        contexts.Module.create(
            context,
            module_name=KERNEL_MODULE,
            layer_name=LAYER_NAME,
            offset=MODULE_OFFSET,
            symbol_table_name=SYMBOL_TABLE,
        )
        self._context = context
        return context


class ListSimulator:
    """Independent model of the expected walk over a (possibly broken) ring.

    ``to_list`` distinguishes two failures that look alike but differ in the
    result:

    * If a *pointer* to a node is unreadable - null, unmapped, or pointing at a
      link whose sixteen bytes are not all mapped - the node is never
      delivered and the walk stops at its predecessor.
    * If a node is readable but its own *outgoing* pointer is unreadable, the
      node is delivered once and the walk then stops.

    Simulating those rules independently of the implementation is what lets
    the tests prove containment: nothing past the failure point appears.
    """

    def __init__(
        self,
        ring: Sequence[int] = RING,
        unreadable: Iterable[int] = (),
        broken_outgoing: Iterable[int] = (),
    ) -> None:
        self.ring = tuple(ring)
        self.unreadable: Set[int] = set(unreadable)
        self.broken_outgoing: Set[int] = set(broken_outgoing)

    def walk(
        self, start: int = HEAD, forward: bool = True, sentinel: bool = True
    ) -> List[int]:
        if start in self.unreadable or start in self.broken_outgoing:
            # The starting pointer is fetched before anything is yielded.
            return []
        step = 1 if forward else -1
        result = [] if sentinel else [start]
        seen = {start}
        current = start
        while current not in self.broken_outgoing:
            following = self.ring[(self.ring.index(current) + step) % len(self.ring)]
            if following in seen or following in self.unreadable:
                break
            result.append(following)
            seen.add(following)
            current = following
        return result


def _link_of(iterator) -> int:
    """Link offset of the next entry delivered by a pending walk."""
    return next(iterator).vol.offset + LINK_OFFSET


def _traverse(
    context: contexts.Context,
    start: int = HEAD,
    forward: bool = True,
    sentinel: bool = True,
) -> List[int]:
    """Walk the list and return the link offset of every delivered entry.

    Enforces the traversal contract: the walk terminates within ``MAX_STEPS``
    entries, never delivers a link twice, and the iterator is exhausted
    afterwards (a read failure ends the walk instead of pausing it or raising).
    """
    head = context.modules[KERNEL_MODULE].object(
        "_LIST_ENTRY", offset=start, absolute=True
    )
    iterator = head.to_list(
        EPROCESS_TYPE, LINK_MEMBER, forward=forward, sentinel=sentinel
    )
    entries = list(itertools.islice(iterator, MAX_STEPS))
    assert len(entries) < MAX_STEPS, (
        f"traversal from {start:#x} did not terminate within {MAX_STEPS} entries"
    )
    links = [entry.vol.offset + LINK_OFFSET for entry in entries]
    assert len(links) == len(set(links)), f"duplicate list entries: {links}"
    with pytest.raises(StopIteration):
        next(iterator)
    return links


def _enumerate_processes(context: contexts.Context):
    """Bounded run of PsList's forward+backward enumeration."""
    processes = list(
        itertools.islice(PsList.list_processes(context, KERNEL_MODULE), MAX_STEPS)
    )
    assert len(processes) < MAX_STEPS, "process enumeration did not terminate"
    pids = [int(process.UniqueProcessId) for process in processes]
    offsets = [process.vol.offset for process in processes]
    assert len(pids) == len(set(pids)), f"duplicate PIDs delivered: {pids}"
    assert len(offsets) == len(set(offsets)), (
        f"duplicate processes delivered: {offsets}"
    )
    return processes


def _process_links(context: contexts.Context) -> List[int]:
    """Link offsets of the processes PsList enumerates, in delivery order."""
    return [
        process.vol.offset + LINK_OFFSET for process in _enumerate_processes(context)
    ]


def _process_pids(context: contexts.Context) -> List[int]:
    return [int(process.UniqueProcessId) for process in _enumerate_processes(context)]


def _merge(forward: Sequence[int], backward: Sequence[int]) -> List[int]:
    """PsList's deduplicating union of the forward and backward walks."""
    merged: List[int] = []
    for link in list(forward) + list(backward):
        if link not in merged:
            merged.append(link)
    return merged


def test_valid_ring_preserves_forward_and_backward_order(tmp_path):
    """A legitimate doubly-linked list keeps its order in both directions."""
    context = MemoryImage().build(tmp_path)
    simulator = ListSimulator()

    assert simulator.walk(forward=True) == [A, B, C]
    assert _traverse(context, forward=True) == [A, B, C]
    assert simulator.walk(forward=False) == [C, B, A]
    assert _traverse(context, forward=False) == [C, B, A]


@pytest.mark.parametrize("start", RING, ids=["sentinel", "first", "middle", "last"])
@pytest.mark.parametrize("forward", DIRECTIONS)
@pytest.mark.parametrize("sentinel", [True, False], ids=["sentinel", "non-sentinel"])
def test_any_starting_node_terminates_without_duplicates(
    tmp_path, start, forward, sentinel
):
    """Every starting node and direction terminates, each node exactly once."""
    context = MemoryImage().build(tmp_path)
    simulator = ListSimulator()

    expected = simulator.walk(start=start, forward=forward, sentinel=sentinel)
    assert _traverse(context, start, forward, sentinel) == expected


@pytest.mark.parametrize("pointer", OOB_POINTERS)
@pytest.mark.parametrize("fault", FAULT_LOCATIONS)
@pytest.mark.parametrize("forward", DIRECTIONS)
def test_out_of_bounds_pointer_stops_traversal(tmp_path, pointer, fault, forward):
    """An out-of-bounds link ends the walk at the corrupt node.

    Nodes reachable before the corrupt pointer are delivered; memory that
    merely follows the corrupt node is never scanned, so the planted decoy is
    not reported even though it lies in silent, readable memory.
    """
    direction = "Flink" if forward else "Blink"
    image = MemoryImage()
    image.set_pointer(fault, direction, pointer)
    image.add_decoy(DECOY_LINK)
    context = image.build(tmp_path)
    simulator = ListSimulator(broken_outgoing={fault})

    result = _traverse(context, forward=forward)

    assert result == simulator.walk(forward=forward)
    assert DECOY_LINK not in result
    # No state carried over: the same scan repeated reports the same nodes.
    assert _traverse(context, forward=forward) == result


@pytest.mark.parametrize("fault", [A, B, C], ids=["first", "middle", "last"])
@pytest.mark.parametrize("forward", DIRECTIONS)
def test_unreadable_node_stops_traversal(tmp_path, fault, forward):
    """A node whose own link is unmapped is skipped, ending the walk."""
    image = MemoryImage()
    image.drop_link(fault)
    image.add_decoy(DECOY_LINK)
    context = image.build(tmp_path)
    simulator = ListSimulator(unreadable={fault})

    result = _traverse(context, forward=forward)

    assert result == simulator.walk(forward=forward)
    assert fault not in result
    assert DECOY_LINK not in result


def test_partially_readable_node_is_not_delivered(tmp_path):
    """A link with only half its bytes mapped is rejected, not reported."""
    ring = (HEAD, A, PARTIAL_LINK, C)
    image = MemoryImage(ring=ring, pids={A: 4, C: 200})
    image.make_partial_link(PARTIAL_LINK)
    context = image.build(tmp_path)
    simulator = ListSimulator(ring, unreadable={PARTIAL_LINK})

    assert _traverse(context, forward=True) == [A]
    assert _traverse(context, forward=False) == [C]
    assert simulator.walk(forward=True) == [A]
    assert simulator.walk(forward=False) == [C]


def test_starting_on_unreadable_node_yields_nothing(tmp_path):
    """A walk started on an unmapped link returns no entries, not an error."""
    image = MemoryImage()
    image.drop_link(B)
    context = image.build(tmp_path)
    simulator = ListSimulator(unreadable={B})

    assert _traverse(context, start=B, forward=True) == []
    assert _traverse(context, start=B, forward=False) == []
    assert simulator.walk(start=B) == []
    # From the sentinel the rest of the ring is still reachable.
    assert _traverse(context, forward=True) == [A]
    assert _traverse(context, forward=False) == [C]


def test_cycle_without_sentinel_terminates(tmp_path):
    """A cycle that never reaches the sentinel stops after each node once."""
    image = MemoryImage()
    image.set_pointer(C, "Flink", A)
    image.set_pointer(A, "Blink", C)
    context = image.build(tmp_path)

    assert _traverse(context, forward=True) == [A, B, C]
    assert _traverse(context, forward=False) == [C, B, A]


def test_self_referential_node_terminates(tmp_path):
    """A node pointing at itself is delivered once and ends the walk."""
    image = MemoryImage()
    image.set_pointer(B, "Flink", B)
    context = image.build(tmp_path)

    assert _traverse(context, forward=True) == [A, B]
    assert _traverse(context, forward=False) == [C, B, A]


def test_repeated_traversals_do_not_share_state(tmp_path):
    """A repair between scans is visible: no state leaks from an earlier walk."""
    image = MemoryImage()
    context = image.build(tmp_path)

    assert _traverse(context) == [A, B, C]

    image.set_pointer(B, "Flink", 0xDEAD0000)
    assert _traverse(context) == [A, B]
    # The failed walk left nothing behind: repeating it gives the same result.
    assert _traverse(context) == [A, B]

    image.set_pointer(B, "Flink", C)
    assert _traverse(context) == [A, B, C]


def test_failed_walk_is_exhausted_not_paused(tmp_path):
    """A walk that stopped on bad memory is finished, not merely suspended.

    After the failure the iterator must keep raising ``StopIteration`` even if
    the corrupt pointer is repaired: the only way to see the repaired list is
    to start a new walk.
    """
    image = MemoryImage()
    image.set_pointer(B, "Flink", 0xDEAD0000)
    context = image.build(tmp_path)
    head = context.modules[KERNEL_MODULE].object(
        "_LIST_ENTRY", offset=HEAD, absolute=True
    )
    iterator = head.to_list(EPROCESS_TYPE, LINK_MEMBER)

    delivered = [_link_of(iterator), _link_of(iterator)]
    assert delivered == [A, B]
    with pytest.raises(StopIteration):
        next(iterator)

    # Repair the corrupt pointer while the old iterator is exhausted.
    image.set_pointer(B, "Flink", C)

    with pytest.raises(StopIteration):
        next(iterator)
    # A new walk over the repaired image reports the whole list again.
    assert _traverse(context) == [A, B, C]


def test_pslist_returns_valid_list_in_order(tmp_path):
    """PsList yields every process once, in list order."""
    context = MemoryImage().build(tmp_path)

    assert _process_links(context) == [A, B, C]
    assert _process_pids(context) == [PIDS[A], PIDS[B], PIDS[C]]


@pytest.mark.parametrize("fault", [A, B, C], ids=["first", "middle", "last"])
def test_pslist_merges_directions_without_duplicates(tmp_path, fault):
    """A broken forward link loses nothing: the backward walk fills the gap."""
    image = MemoryImage()
    image.set_pointer(fault, "Flink", 0xDEAD0000)
    context = image.build(tmp_path)
    simulator = ListSimulator(broken_outgoing={fault})

    expected = _merge(simulator.walk(forward=True), simulator.walk(forward=False))

    assert _process_links(context) == expected
    assert set(expected) == {A, B, C}
    assert sorted(_process_pids(context)) == sorted(PIDS.values())


def test_pslist_does_not_report_memory_after_fault(tmp_path):
    """Nodes behind a corrupt link are not mistaken for list members."""
    image = MemoryImage()
    image.set_pointer(B, "Flink", 0xDEAD0000)
    image.add_decoy(DECOY_LINK)
    context = image.build(tmp_path)

    pids = _process_pids(context)

    assert pids == [PIDS[A], PIDS[B], PIDS[C]]
    assert DECOY_PID not in pids


def test_pslist_repeated_scans_are_isolated(tmp_path):
    """Each enumeration starts fresh, including after a corrupted scan."""
    image = MemoryImage()
    context = image.build(tmp_path)

    first = _process_pids(context)
    assert first == [PIDS[A], PIDS[B], PIDS[C]]

    image.set_pointer(A, "Flink", 0xDEAD0000)
    damaged = _process_pids(context)
    assert damaged == [PIDS[A], PIDS[C], PIDS[B]]
    assert _process_pids(context) == damaged

    image.set_pointer(A, "Flink", B)
    assert _process_pids(context) == first


def test_pslist_unreadable_middle_node_only_reports_reachable(tmp_path):
    """A mid-list hole limits the scan to nodes still reachable either way."""
    image = MemoryImage()
    image.drop_link(B)
    image.add_decoy(DECOY_LINK)
    context = image.build(tmp_path)
    simulator = ListSimulator(unreadable={B})

    expected = _merge(simulator.walk(forward=True), simulator.walk(forward=False))

    assert expected == [A, C]
    assert _process_links(context) == expected
    assert _process_pids(context) == [PIDS[A], PIDS[C]]
    assert DECOY_PID not in _process_pids(context)


def test_pslist_unreadable_head_reports_nothing(tmp_path):
    """An unmapped sentinel ends both walks immediately."""
    image = MemoryImage()
    image.drop_link(HEAD)
    context = image.build(tmp_path)

    assert _process_links(context) == []
    assert _process_pids(context) == []

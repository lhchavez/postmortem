"""A class to analyze a Control Flow Graph."""

from __future__ import print_function

import collections
import logging

import capstone

_UNCONDITIONAL_JUMP_MNEMONICS = ['jmp', 'jmpq']
_HALT_MNEMONICS = ['hlt']

# A mapping of registers to its widest equivalent.
_REGISTER_EQUIVALENCES = {
    capstone.CS_ARCH_X86: {
        # RAX
        capstone.x86.X86_REG_AH: capstone.x86.X86_REG_RAX,
        capstone.x86.X86_REG_AL: capstone.x86.X86_REG_RAX,
        capstone.x86.X86_REG_AX: capstone.x86.X86_REG_RAX,
        capstone.x86.X86_REG_EAX: capstone.x86.X86_REG_RAX,
        capstone.x86.X86_REG_RAX: capstone.x86.X86_REG_RAX,

        # RBX
        capstone.x86.X86_REG_BH: capstone.x86.X86_REG_RBX,
        capstone.x86.X86_REG_BL: capstone.x86.X86_REG_RBX,
        capstone.x86.X86_REG_BX: capstone.x86.X86_REG_RBX,
        capstone.x86.X86_REG_EBX: capstone.x86.X86_REG_RBX,
        capstone.x86.X86_REG_RBX: capstone.x86.X86_REG_RBX,

        # RCX
        capstone.x86.X86_REG_CH: capstone.x86.X86_REG_RCX,
        capstone.x86.X86_REG_CL: capstone.x86.X86_REG_RCX,
        capstone.x86.X86_REG_CX: capstone.x86.X86_REG_RCX,
        capstone.x86.X86_REG_ECX: capstone.x86.X86_REG_RCX,
        capstone.x86.X86_REG_RCX: capstone.x86.X86_REG_RCX,

        # RDX
        capstone.x86.X86_REG_DH: capstone.x86.X86_REG_RDX,
        capstone.x86.X86_REG_DL: capstone.x86.X86_REG_RDX,
        capstone.x86.X86_REG_DX: capstone.x86.X86_REG_RDX,
        capstone.x86.X86_REG_EDX: capstone.x86.X86_REG_RDX,
        capstone.x86.X86_REG_RDX: capstone.x86.X86_REG_RDX,

        # RSI
        capstone.x86.X86_REG_SIL: capstone.x86.X86_REG_RSI,
        capstone.x86.X86_REG_SI: capstone.x86.X86_REG_RSI,
        capstone.x86.X86_REG_ESI: capstone.x86.X86_REG_RSI,
        capstone.x86.X86_REG_RSI: capstone.x86.X86_REG_RSI,

        # RDI
        capstone.x86.X86_REG_DIL: capstone.x86.X86_REG_RDI,
        capstone.x86.X86_REG_DI: capstone.x86.X86_REG_RDI,
        capstone.x86.X86_REG_EDI: capstone.x86.X86_REG_RDI,
        capstone.x86.X86_REG_RDI: capstone.x86.X86_REG_RDI,

        # RBP
        capstone.x86.X86_REG_BPL: capstone.x86.X86_REG_RBP,
        capstone.x86.X86_REG_BP: capstone.x86.X86_REG_RBP,
        capstone.x86.X86_REG_EBP: capstone.x86.X86_REG_RBP,
        capstone.x86.X86_REG_RBP: capstone.x86.X86_REG_RBP,

        # RSP
        capstone.x86.X86_REG_SPL: capstone.x86.X86_REG_RSP,
        capstone.x86.X86_REG_SP: capstone.x86.X86_REG_RSP,
        capstone.x86.X86_REG_ESP: capstone.x86.X86_REG_RSP,
        capstone.x86.X86_REG_RSP: capstone.x86.X86_REG_RSP,

        # R8
        capstone.x86.X86_REG_R8B: capstone.x86.X86_REG_R8,
        capstone.x86.X86_REG_R8W: capstone.x86.X86_REG_R8,
        capstone.x86.X86_REG_R8D: capstone.x86.X86_REG_R8,
        capstone.x86.X86_REG_R8: capstone.x86.X86_REG_R8,

        # R9
        capstone.x86.X86_REG_R9B: capstone.x86.X86_REG_R9,
        capstone.x86.X86_REG_R9W: capstone.x86.X86_REG_R9,
        capstone.x86.X86_REG_R9D: capstone.x86.X86_REG_R9,
        capstone.x86.X86_REG_R9: capstone.x86.X86_REG_R9,

        # R10
        capstone.x86.X86_REG_R10B: capstone.x86.X86_REG_R10,
        capstone.x86.X86_REG_R10W: capstone.x86.X86_REG_R10,
        capstone.x86.X86_REG_R10D: capstone.x86.X86_REG_R10,
        capstone.x86.X86_REG_R10: capstone.x86.X86_REG_R10,

        # R11
        capstone.x86.X86_REG_R11B: capstone.x86.X86_REG_R11,
        capstone.x86.X86_REG_R11W: capstone.x86.X86_REG_R11,
        capstone.x86.X86_REG_R11D: capstone.x86.X86_REG_R11,
        capstone.x86.X86_REG_R11: capstone.x86.X86_REG_R11,

        # R12
        capstone.x86.X86_REG_R12B: capstone.x86.X86_REG_R12,
        capstone.x86.X86_REG_R12W: capstone.x86.X86_REG_R12,
        capstone.x86.X86_REG_R12D: capstone.x86.X86_REG_R12,
        capstone.x86.X86_REG_R12: capstone.x86.X86_REG_R12,

        # R13
        capstone.x86.X86_REG_R13B: capstone.x86.X86_REG_R13,
        capstone.x86.X86_REG_R13W: capstone.x86.X86_REG_R13,
        capstone.x86.X86_REG_R13D: capstone.x86.X86_REG_R13,
        capstone.x86.X86_REG_R13: capstone.x86.X86_REG_R13,

        # R14
        capstone.x86.X86_REG_R14B: capstone.x86.X86_REG_R14,
        capstone.x86.X86_REG_R14W: capstone.x86.X86_REG_R14,
        capstone.x86.X86_REG_R14D: capstone.x86.X86_REG_R14,
        capstone.x86.X86_REG_R14: capstone.x86.X86_REG_R14,

        # R15
        capstone.x86.X86_REG_R15B: capstone.x86.X86_REG_R15,
        capstone.x86.X86_REG_R15W: capstone.x86.X86_REG_R15,
        capstone.x86.X86_REG_R15D: capstone.x86.X86_REG_R15,
        capstone.x86.X86_REG_R15: capstone.x86.X86_REG_R15,

        # RIP
        capstone.x86.X86_REG_EIP: capstone.x86.X86_REG_RIP,
        capstone.x86.X86_REG_RIP: capstone.x86.X86_REG_RIP,
    },
}


def _prune_unreachable(blocks, address_range):
    reachable = set()
    queue = ['%x' % address_range[0]]
    while queue:
        addr = queue.pop()
        if addr in reachable:
            continue
        reachable.add(addr)
        for edge in blocks[addr]['edges']:
            queue.append(edge['target'])

    for unreachable in sorted(set(blocks.keys()) - reachable):
        del blocks[unreachable]


def reverse_postorder(blocks):
    """Visit the block graph in reverse postorder.

    This is useful to perform data-flow analysis on the block graph.
    """

    reverse_edges = collections.defaultdict(set)
    order = []
    seen = set()

    def _visit(address):
        if address in seen:
            return
        seen.add(address)
        block = blocks[address]
        for edge in block['edges']:
            reverse_edges[edge['target']].add(address)
            _visit(edge['target'])
        order.append(address)

    # Start the visiting on the first address of the function.
    _visit(min(blocks.keys()))

    for address in order[::-1]:
        yield (address, blocks[address], reverse_edges[address])


class Disassembler:
    """A control flow graph from a disassembled code."""

    def __init__(self,
                 isa,
                 *,
                 syntax=capstone.CS_OPT_SYNTAX_ATT,
                 raw_instructions=False):
        if isa == 'x86':
            self._arch = capstone.CS_ARCH_X86
            self._mode = capstone.CS_MODE_32
        elif isa == 'x86_64':
            self._arch = capstone.CS_ARCH_X86
            self._mode = capstone.CS_MODE_64
        elif isa == 'arm':
            self._arch = capstone.CS_ARCH_ARM
            self._mode = capstone.CS_MODE_32
        elif isa == 'aarch64':
            self._arch = capstone.CS_ARCH_ARM64
            self._mode = capstone.CS_MODE_64
        else:
            raise Exception('Unknown ISA: %s' % isa)

        self._disassembler = capstone.Cs(self._arch, self._mode)
        self._disassembler.detail = True
        self._disassembler.syntax = syntax

        self._raw_instructions = raw_instructions

    def disassemble(self, code, address_range):
        """A JSON-friendly representation of this graph."""
        cuts, edges = self._calculate_edges(code, address_range)
        blocks = self._fill_basic_blocks(code, address_range, cuts, edges)
        _prune_unreachable(blocks, address_range)
        return blocks

    def normalize_register(self, register):
        """Return the widest register for this register, if known."""
        return _REGISTER_EQUIVALENCES[self._arch].get(register, None)

    def _get_jump_target(self, instruction):
        op = instruction.operands[0]
        if self._arch == capstone.CS_ARCH_X86:
            if op.type == capstone.x86.X86_OP_IMM:
                return op.imm
            if op.type == capstone.x86.X86_OP_MEM:
                if op.mem.base in (capstone.x86.X86_REG_RIP,
                                   capstone.x86.X86_REG_IP):
                    return instruction.address + op.mem.disp
        logging.debug('Unsupported jump addressing mode: %s %s',
                      instruction.mnemonic, instruction.op_str)
        return -1

    def _calculate_edges(self, code, address_range):
        cuts = set([address_range[0]])
        edges = collections.defaultdict(list)
        for i in self._disassembler.disasm(code, address_range[0]):
            if capstone.CS_GRP_JUMP in i.groups:
                cuts.add(i.address + i.size)
                cuts.add(i.operands[0].value.imm)
                if i.mnemonic in _UNCONDITIONAL_JUMP_MNEMONICS:
                    edges[i.address] = [(self._get_jump_target(i),
                                         'unconditional')]
                else:
                    edges[i.address] = [(i.address + i.size, 'fallthrough'),
                                        (i.operands[0].value.imm, 'jump')]
            elif capstone.CS_GRP_RET in i.groups or i.mnemonic in _HALT_MNEMONICS:
                cuts.add(i.address + i.size)
            else:
                edges[i.address] = [(i.address + i.size, 'unconditional')]
            # Some amount of padding might have been added to the code to
            # ensure that the last instruction is read fully.
            if i.address >= address_range[1]:
                break
        return cuts, edges

    def _fill_basic_blocks(self, code, address_range, cuts, edges):
        blocks = collections.defaultdict(lambda: {'edges': [], 'external_edges': [], 'instructions': []})

        current_block = None
        for i in self._disassembler.disasm(code, address_range[0]):
            if i.address in cuts:
                current_block = blocks['%x' % i.address]
            if i.address in edges:
                for dst, edgetype in edges[i.address]:
                    if dst not in cuts:
                        if not address_range[0] <= dst < address_range[1]:
                            current_block['external_edges'].append({
                                'target':
                                '%x' % dst
                            })
                        continue
                    current_block['edges'].append({
                        'type': edgetype,
                        'target': '%x' % dst
                    })
            if self._raw_instructions:
                instruction = i
            else:
                instruction = {
                    'address': '%x' % i.address,
                    'bytes': [x for x in i.bytes],
                    'mnemonic': i.mnemonic,
                    'op': i.op_str,
                }
            current_block['instructions'].append(instruction)
            # Some amount of padding was added to the code to ensure that the last
            # instruction is read fully.
            if i.address >= address_range[1]:
                break
        return blocks


# vi: tabstop=4 shiftwidth=4

# -*- coding: utf-8 -*-
# Generates a SourceMod-ready signature.
#@author nosoop (original author), VerdiusArcana
#@category _NEW_
# Modified version of nosoop's original function signature generator.
# This version outputs both the shortest unique signature (original behavior)
# and optional fixed-length signatures (24-byte and 32-byte) for those who want
# longer patterns for manual verification or future-proofing.
#
# Modifications: Adds dual-format output (Ghidra & Gamedata),
# optional 24-/32-byte signatures with uniqueness and wildcard limits.
#
# @category _NEW_

from __future__ import print_function

import collections
import ghidra.program.model.lang.OperandType as OperandType
import ghidra.program.model.address.AddressSet as AddressSet

MAKE_SIG_AT = collections.OrderedDict([
    ('fn', 'start of function'),
    ('cursor', 'instruction at cursor')
])

BytePattern = collections.namedtuple('BytePattern', ['is_wildcard', 'byte'])

def __bytepattern_ida_str(self):
    return '{:02X}'.format(self.byte) if not self.is_wildcard else '?'

def __bytepattern_sig_str(self):
    return r'\x{:02X}'.format(self.byte) if not self.is_wildcard else r'\x2A'

BytePattern.ida_str = __bytepattern_ida_str
BytePattern.sig_str = __bytepattern_sig_str

def shouldMaskOperand(ins, opIndex):
    optype = ins.getOperandType(opIndex)
    return optype & OperandType.DYNAMIC or optype & OperandType.ADDRESS

def getMaskedInstruction(ins):
    mask = [0] * ins.length
    proto = ins.getPrototype()
    for op in range(proto.getNumOperands()):
        if shouldMaskOperand(ins, op):
            mask = [ m | v & 0xFF for m, v in zip(mask, proto.getOperandValueMask(op).getBytes()) ]
    for m, b in zip(mask, ins.getBytes()):
        if m == 0xFF:
            yield BytePattern(is_wildcard = True, byte = None)
        else:
            yield BytePattern(byte = b & 0xFF, is_wildcard = False)

def cleanupWilds(byte_pattern):
    for byte in reversed(byte_pattern):
        if not byte.is_wildcard:
            break
        del byte_pattern[-1]

def find_signature_matches(byte_pattern, max_matches=128):
    pattern = ''.join('.' if b.is_wildcard else r'\x{:02x}'.format(b.byte) for b in byte_pattern)
    return findBytes(None, pattern, max_matches)

def build_byte_pattern_from_instructions(fn, max_bytes):
    cm = currentProgram.getCodeManager()
    ins = cm.getInstructionAt(fn.getEntryPoint())
    byte_pattern = []
    while ins and currentProgram.getFunctionManager().getFunctionContaining(ins.getAddress()) == fn:
        for entry in getMaskedInstruction(ins):
            byte_pattern.append(entry)
        if len(byte_pattern) >= max_bytes:
            break
        ins = ins.getNext()
    return byte_pattern

def print_dual_format(label, byte_pattern):
    ghidra_fmt = " ".join('?' if b.is_wildcard else '{:02X}'.format(b.byte) for b in byte_pattern)
    gamedata_fmt = "".join(b.sig_str() for b in byte_pattern)
    print(label)
    print("Ghidra:   " + ghidra_fmt)
    print("Gamedata: " + gamedata_fmt)

def print_optional_signature(byte_pattern, length, wildcard_limit, label):
    if len(byte_pattern) < length:
        print(label + "\nN/A (signature too short)")
        return
    slice_ = byte_pattern[:length]
    wilds = sum(1 for b in slice_ if b.is_wildcard)
    if wilds > wildcard_limit:
        print(label + "\nN/A (too many wildcards)")
        return
    matches = find_signature_matches(slice_)
    if len(matches) != 1:
        print(label + "\nN/A (not unique)")
        return
    print_dual_format(label, slice_)

def process(start_at = MAKE_SIG_AT['fn']):
    print("========================")
    fm = currentProgram.getFunctionManager()
    fn = fm.getFunctionContaining(currentAddress)
    cm = currentProgram.getCodeManager()

    if start_at == MAKE_SIG_AT['fn']:
        ins = cm.getInstructionAt(fn.getEntryPoint())
    elif start_at == MAKE_SIG_AT['cursor']:
        try:
            ins = cm.getInstructionContaining(currentAddress, False)
        except TypeError:
            ins = cm.getInstructionContaining(currentAddress)

    if not ins:
        printerr("Could not find instruction")
        return

    byte_pattern = []
    pattern = ""
    matches = []
    match_limit = 128

    while fm.getFunctionContaining(ins.getAddress()) == fn:
        for entry in getMaskedInstruction(ins):
            byte_pattern.append(entry)
            pattern += '.' if entry.is_wildcard else r'\x{:02x}'.format(entry.byte)
        expected_next = ins.getAddress().add(ins.length)
        ins = ins.getNext()
        if ins and ins.getAddress() != expected_next:
            for _ in range(ins.getAddress().subtract(expected_next)):
                byte_pattern.append(BytePattern(is_wildcard=True, byte=None))
                pattern += '.'
        if len(byte_pattern) < 1:
            continue
        if 0 < len(matches) < match_limit:
            match_set = AddressSet()
            for addr in matches:
                match_set.add(addr, addr.add(len(byte_pattern)))
            matches = findBytes(match_set, pattern, match_limit, 1)
        else:
            matches = findBytes(matches[0] if matches else None, pattern, match_limit)
        if len(matches) < 2:
            break

    cleanupWilds(byte_pattern)
    print("Signature for", fn.getName())
    print_dual_format("Shortest Unique:", byte_pattern)

    if len(byte_pattern) > 32:
        print("Optional 24-Byte Signature:\nN/A (signature too long)")
        print("Optional 32-Byte Signature:\nN/A (signature too long)")
    else:
        full_pattern = build_byte_pattern_from_instructions(fn, 32)
        print_optional_signature(full_pattern, 24, 8, "Optional 24-Byte Signature:")
        print_optional_signature(full_pattern, 32, 12, "Optional 32-Byte Signature:")

    print("========================")

if __name__ == "__main__":
    fm = currentProgram.getFunctionManager()
    fn = fm.getFunctionContaining(currentAddress)
    if not fn:
        printerr("Not in a function")
    else:
        start_at = askChoice("makesig", "Make sig at:", MAKE_SIG_AT.values(), MAKE_SIG_AT['fn'])
        process(start_at)

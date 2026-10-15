# toolbox/core/arg_stub.py
"""配置循环桩识别示例（arg 参数桩 + 调用方循环区间）。

示例形态：
- arg 参数桩：内部 `push 0; push 1; push eq-imm; push [ebp+8]; call 内联核心`，
  参数由调用者经 `[ebp+8]` 传入。
- 调用者循环：`push imm32(起始DWORD); counter清零; cmp counter, N;
  push 起始+counter; call arg桩`，候选范围为起始值到起始值加循环次数减一。

只读分析模块，不修改引擎。
"""
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM

from .pe import get_image_base, read_va
from .stub_scan import _disasm_around, _find_prologue_va, _scan_e8


def find_arg_stub_cores(data, sections, inline_core_targets):
    """找「per 来自调用者 [ebp+8] 参数」的 arg 参数桩函数起始地址集合。

    形态：内部 `push 0; push 1; push eq-imm; push [ebp+8]; call 内联核心`。
    """
    cores = set()
    for call_va, tgt in _scan_e8(data, sections, [], set(inline_core_targets)):
        insns = _disasm_around(data, sections, call_va)
        has_ebp8 = False
        imm_n = 0
        for ins in reversed(insns):
            if ins.address >= call_va:
                continue
            if ins.mnemonic == 'push':
                if ins.op_str == 'dword ptr [ebp + 8]':
                    has_ebp8 = True
                elif ins.operands[0].type == X86_OP_IMM:
                    imm_n += 1
                else:
                    continue
            elif ins.mnemonic in ('mov', 'sub', 'add', 'lea', 'movzx',
                                  'test', 'cmp', 'jmp', 'jne', 'je', 'nop'):
                continue
            else:
                break
        if has_ebp8 and imm_n >= 3:
            pro = _find_prologue_va(data, sections, call_va)
            if pro is not None and call_va - pro <= 0x40:
                cores.add(pro)
    return cores


def _callers_of(data, sections, target):
    calls = []
    for s in sections:
        if s.name == '.rsrc':
            continue
        buf = data[s.raw:s.raw + s.raw_size]
        base = get_image_base(sections) + s.va
        i = 0
        while i < len(buf) - 4:
            if buf[i] == 0xE8:
                rel = struct.unpack_from('<i', buf, i + 1)[0]
                tgt = (base + i + 5 + rel) & 0xFFFFFFFF
                if tgt == target:
                    calls.append(base + i)
                i += 5
            else:
                i += 1
    return calls


def arg_stub_range(data, sections, core):
    """推导 arg 参数桩 core 的覆盖特技号区间 [start, end]（含端点）。

    在 core 的每个调用者函数内找：
    - push imm32（起始 DWORD）；
    - cmp [ebp-Y], N（循环上限，如 cmp [ebp-0xC], 5）；
    - 循环体内 add [ebp-8]+[ebp-Y] 后 push 喂给 core。
    覆盖 = start ~ start+N-1。识别失败返回 None。
    """
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    for call in _callers_of(data, sections, core):
        pro = _find_prologue_va(data, sections, call)
        if pro is None or call - pro > 0x400:
            continue
        buf = read_va(data, sections, pro, call - pro + 8)
        if buf is None:
            continue
        insns = list(md.disasm(buf, pro))
        start = None
        max_n = None
        # 起始：push imm32（68 xx 00 00 00，4 字节立即数；6A xx 的 push 0 是 eff 标志）
        for ins in insns:
            if (ins.mnemonic == 'push' and ins.operands
                    and ins.operands[0].type == X86_OP_IMM
                    and len(ins.bytes) >= 5 and ins.bytes[0] == 0x68):
                v = ins.operands[0].imm & 0xFFFF
                if 0 <= v <= 0xFF:
                    start = v
                    break
        # 上限：cmp dword ptr [ebp-Y], N
        for ins in insns:
            os_ = ins.op_str
            if ins.mnemonic == 'cmp' and 'dword ptr [ebp -' in os_ and ', ' in os_:
                tail = os_.split(', ')[-1]
                try:
                    n = int(tail, 0)
                    if 1 <= n <= 0x100:
                        max_n = n
                except ValueError:
                    continue
        if start is not None and max_n is not None:
            return (start, start + max_n - 1)
    return None

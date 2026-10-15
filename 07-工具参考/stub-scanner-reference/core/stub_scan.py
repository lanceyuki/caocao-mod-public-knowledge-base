"""Read-only x86 stub candidate scanner with caller-supplied target profiles.

The recognition heuristics are examples derived from one engine sample. Supply
target-specific dispatch ranges and inline core addresses after inspecting the
file being analyzed; no engine addresses are bundled in this module.
"""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM, X86_OP_REG, X86_REG_EAX, X86_REG_ECX
from .pe import get_image_base, load_pe, read_va


def _scan_e8(data, sections, target_ranges, target_set):
    hits = []
    for s in sections:
        if s.name == '.rsrc':
            continue
        buf = data[s.raw:s.raw+s.raw_size]
        base = get_image_base(sections) + s.va
        i = 0
        limit = len(buf) - 4
        while i < limit:
            i = buf.find(b'\xE8', i, limit)
            if i < 0:
                break
            rel = struct.unpack_from('<i', buf, i+1)[0]
            tgt = (base + i + 5 + rel) & 0xFFFFFFFF
            if (target_ranges and any(lo <= tgt < hi for lo, hi, _ in target_ranges)) or (tgt in target_set):
                hits.append((base + i, tgt))
                i += 5
                continue
            # 假 E8 后仍逐字节找下一处，不能跳过紧随其后的真 call。
            i += 1
    return hits


def _collect_pushes(insns, call_va):
    seq = []
    seen_eax = False
    calc_skip = 0
    for ins in reversed(insns):
        if ins.address >= call_va:
            continue
        m = ins.mnemonic
        if m == 'push':
            op = ins.operands[0]
            if op.type == X86_OP_IMM:
                # 特技号是 0~255 无符号值；capstone 对 6A FE 返回 -2，需 & 0xFF 还原
                seq.append((ins.address, op.imm & 0xFF, 'imm'))
            elif op.type == X86_OP_REG and op.reg == X86_REG_EAX:
                if calc_skip > 0:
                    break
                # 4 个 imm push 已齐（标准/3参桩格式完整）时，更早的 push eax 是外部
                # 辅助代码（如 call 返回值压栈），不是运行时计算的特技号——停止收集
                if sum(1 for _, _, k in seq if k == 'imm') >= 4:
                    break
                seq.append((ins.address, None, 'eax'))
                seen_eax = True
            elif op.type == X86_OP_REG and op.reg == X86_REG_ECX:
                # push ecx：mov-al 桩形态（mov al,技能; mov cl,装备; push 0; push 1;
                # push ecx; push eax; call）的装备号来自寄存器，不打断收集
                seq.append((ins.address, None, 'ecx'))
                continue
            else:
                break
        elif m == 'add' and ins.op_str.startswith(('al,', 'eax,')):
            # 参数化桩基数：add al/eax, base（04 xx / 83 C0 xx）；
            # capstone 对小值渲染十进制（'eax, 6'）、大值渲染十六进制（'al, 0x8A'），
            # int(rest, 0) 两者都解析；& 0xFF 兼容 0xffffff80 负值渲染
            try:
                _addv = int(ins.op_str.split(', ', 1)[1].strip(), 0) & 0xFF
            except (ValueError, IndexError):
                _addv = None
            if _addv is not None:
                seq.append((ins.address, _addv, 'al_add'))
        elif m == 'mov' and ins.op_str.startswith('ecx'):
            # 跳过 thiscall 单位指针设置（mov ecx, [ebp+0xC] 等），继续向前收集 push
            continue
        elif seen_eax and m in ('mov','add','dec','inc','sub','xor','lea','shl','shr','imul','and','or','neg','cdq','movzx','movsx'):
            calc_skip += 1
            if calc_skip > 6:
                break
            continue
        else:
            break
    seq.reverse()
    return seq


def _find_wrapper_cores(data, sections, dispatch_ranges, inline_core_targets):
    """找包装函数：内部以 [ebp+XX] 参数形式（≥3 个）调用内联核心的函数。

    A wrapper candidate forwards several stack-frame arguments to one of the
    configured inline cores. The pattern is heuristic and needs target review.
    """
    wrappers = set()
    for call_va, tgt in _scan_e8(data, sections, [], inline_core_targets):
        insns = _disasm_around(data, sections, call_va)
        arg_pushes = 0
        for ins in reversed(insns):
            if ins.address >= call_va:
                continue
            if ins.mnemonic == 'push' and ins.op_str.startswith('dword ptr [ebp +'):
                arg_pushes += 1
                continue
            if ins.mnemonic == 'push':
                break
            if ins.mnemonic in ('mov', 'call', 'add', 'sub', 'lea', 'xor', 'test', 'cmp', 'jmp', 'jne', 'je', 'ja', 'jae', 'jb', 'jbe'):
                continue
            break
        if arg_pushes >= 3:
            pro = _find_prologue_va(data, sections, call_va)
            in_dispatch = (pro is not None and
                           any(lo <= pro < hi for lo, hi, _dummy in dispatch_ranges))
            if (pro is not None and call_va - pro <= 0x40
                    and pro not in inline_core_targets and not in_dispatch):
                wrappers.add(pro)
    return wrappers


def _moval_nums(data, sections, call_va):
    """Collect immediate values loaded into AL before a candidate call.

    mov-al 桩形态：mov al,技能号; mov cl,装备号; push 0; push 1; push ecx; push eax;
    call 内联核心——技能号在 mov al 立即数里而非 push。返回排序去重的号码列表或 None。

    判定规则（防误配）：
    - call 前 0x10 字节内必须有 push eax（该 call 是 eax 传个人号形态）；
    - mov al,imm8 与 call 之间不得有其它 call（避免把别的调用路径的 mov al 算进来）。
    """
    pro = _find_prologue_va(data, sections, call_va)
    if pro is None or call_va - pro > 0x800:
        return None
    buf = read_va(data, sections, pro, call_va - pro + 8)
    if buf is None:
        return None
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    insns = list(md.disasm(buf, pro))
    # 1) call 前 0x10 字节内必须有 push eax
    near = [i for i in insns if call_va - 0x10 <= i.address < call_va]
    if not any(i.mnemonic == 'push' and i.op_str == 'eax' for i in near):
        return None
    # 2) 找 call 前最近的 push eax（该桩的个人号压栈点）
    stub_push_eax = max((i for i in insns if i.address < call_va
                         and i.mnemonic == 'push' and i.op_str == 'eax'),
                        key=lambda i: i.address, default=None)
    if stub_push_eax is None:
        return None
    # 3) push eax 之前（同函数内）的 mov al,imm8 站点。
    # A branch may contain another call between the immediate load and push;
    # static scanning cannot prove which branch executes.
    nums = []
    for ins in insns:
        if ins.address >= stub_push_eax.address:
            break
        if ins.mnemonic == 'mov' and ins.op_str.startswith('al, 0x'):
            try:
                nums.append(int(ins.op_str.split('0x')[1], 16))
            except (ValueError, IndexError):
                continue
    return sorted(set(nums)) or None


def _parse(seq):
    al_add_idx = next((i for i,(_,_,k) in enumerate(seq) if k == 'al_add'), None)
    eax_idx = next((i for i,(_,_,k) in enumerate(seq) if k == 'eax'), None)
    if al_add_idx is not None:
        imms = [v for _,v,k in seq[:al_add_idx] if k == 'imm']
        eff = imms[-3] if len(imms) >= 3 else None
        stk = imms[-2] if len(imms) >= 3 else None
        eq = imms[-1] if len(imms) >= 3 else None
        addv = seq[al_add_idx][1]
        return '参数化桩', eff, stk, eq, None, f'al+0x{addv:X}'
    if eax_idx is not None:
        imms = [v for _,v,k in seq if k == 'imm']
        eff = imms[-3] if len(imms) >= 3 else None
        stk = imms[-2] if len(imms) >= 3 else None
        eq = imms[-1] if len(imms) >= 3 else None
        return '动态桩', eff, stk, eq, None, '?'
    imms = [v for _,v,k in seq if k == 'imm']
    if len(imms) == 4:
        return '标准桩', imms[0], imms[1], imms[2], imms[3], f'0x{imms[3]:X}'
    if len(imms) == 3:
        # 3-push 桩：push eff; push stk; push 特技号（无装备号 push，末位 imm 即个人号）
        return '3参桩', imms[0], imms[1], None, imms[2], f'0x{imms[2]:X}'
    if len(imms) >= 5:
        # For longer push sequences, retain the first fields as a candidate
        # interpretation and the final immediate as the candidate identifier.
        return '多推桩', imms[0], imms[1], imms[2], imms[-1], f'0x{imms[-1]:X}'
    return '异常', None, None, None, None, '?'


def _push_vas_for_parsed_stub(seq, typ):
    """Return candidate VAs for immediate pushes used in the parsed sequence.

    The locations help a reviewer return to disassembly. They do not establish
    that changing those bytes is safe or appropriate.
    """
    imms = [(va, value) for va, value, kind in seq if kind == 'imm']
    if typ in ('标准桩', '多推桩') and len(imms) >= 3:
        result = {'equip': imms[2][0]}
        if typ == '标准桩' and len(imms) >= 4:
            result['per'] = imms[3][0]
        elif typ == '多推桩' and len(imms) >= 5:
            result['per'] = imms[-1][0]
        return result
    if typ == '包装桩' and len(imms) >= 4:
        return {'equip': imms[2][0], 'per': imms[3][0]}
    if typ == '参数化桩' and len(imms) >= 3:
        return {'equip': imms[2][0]}
    return {}


def _find_prologue_va(data, sections, call_va, max_back=0x800):
    """字节级：call 前 max_back 字节内找最近的 push ebp/mov ebp,esp (55 8B EC / 55 89 E5)。

    The bounded byte search avoids relying on one linear disassembly pass.
    """
    start = call_va - max_back
    buf = read_va(data, sections, start, max_back)
    if buf is None:
        return None
    for i in range(len(buf) - 3, -1, -1):
        if buf[i] == 0x55 and (buf[i + 1] == 0x8B and buf[i + 2] == 0xEC or
                               buf[i + 1] == 0x89 and buf[i + 2] == 0xE5):
            return start + i
    return None


def _disasm_range(data, sections, va_start, va_end):
    buf = read_va(data, sections, va_start, va_end - va_start)
    if buf is None:
        return []
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True  # 读取 ins.operands 必需
    return list(md.disasm(buf, va_start))


def _disasm_around(data, sections, call_va, back=40):
    """优先从最近 prologue 反汇编（避免零填充/错位），无 prologue 则线性回溯。"""
    pro = _find_prologue_va(data, sections, call_va)
    if pro is not None and call_va - pro <= 0x800:
        return _disasm_range(data, sections, pro, call_va + 5)
    return _disasm_range(data, sections, call_va - back, call_va + 5)


def scan_stubs(engine_path, dispatch_ranges, inline_core_targets, dispatch_body=None):
    """Find likely stub callsites in ``engine_path`` using a supplied profile.

    ``dispatch_ranges`` contains ``(start_va, end_va, label)`` tuples;
    ``inline_core_targets`` contains target VAs. These values must be derived
    for the user's own file. ``dispatch_body`` is an optional ``(start, end)``
    interval whose internal calls should be omitted from the result.
    """
    dispatch_ranges = tuple(dispatch_ranges)
    inline_core_targets = set(inline_core_targets)
    data, sections = load_pe(engine_path)
    wrappers = _find_wrapper_cores(data, sections, dispatch_ranges, inline_core_targets)
    hits = _scan_e8(data, sections, dispatch_ranges, inline_core_targets | wrappers)
    found = []
    for call_va, tgt in sorted(hits):
        if dispatch_body is not None and dispatch_body[0] <= call_va < dispatch_body[1]:
            continue
        stub_start = _find_prologue_va(data, sections, call_va)
        insns = _disasm_around(data, sections, call_va)
        seq = _collect_pushes(insns, call_va)
        typ, eff, stk, eq, per, per_expr = _parse(seq) if seq else ('异常', None, None, None, None, '?')
        moval_nums = None
        if tgt in wrappers:
            imms = [v for _, v, k in seq if k == 'imm']
            if len(imms) >= 4:
                typ = '包装桩'
                eff, stk, eq, per = imms[0], imms[1], imms[2], imms[3]
                per_expr = f'0x{per:X}'
        elif not seq or typ in ('异常', '动态桩') or per is None:
            moval_nums = _moval_nums(data, sections, call_va)
            if moval_nums:
                typ = 'mov桩'
                per_expr = 'moval:' + ','.join('0x%X' % n for n in moval_nums)
        if not seq and not moval_nums:
            continue
        kind = next((lbl for lo, hi, lbl in dispatch_ranges if lo <= tgt < hi), 'inline target')
        push_vas = _push_vas_for_parsed_stub(seq, typ)
        found.append({'call': call_va, 'tgt': tgt, 'kind': kind, 'type': typ,
                      'eff': eff, 'stack': stk, 'equip': eq, 'per': per, 'per_expr': per_expr,
                      'moval_nums': moval_nums,
                      'start': stub_start,
                      'push_vas': push_vas})
    return found


def get_skill_name(data, sections, skill_id, name_table_va, entry_size=16, encoding='gbk'):
    """Read one fixed-width name when the caller supplies its table location."""
    if (skill_id is None or skill_id < 0 or skill_id > 0xFF
            or name_table_va is None or entry_size <= 0):
        return '?'
    va = name_table_va + skill_id * entry_size
    buf = read_va(data, sections, va, entry_size)
    if buf is None:
        return '?'
    try:
        name = buf.split(b'\x00')[0].decode(encoding, errors='replace')
    except Exception:
        name = '?'
    return name

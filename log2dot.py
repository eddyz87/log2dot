#!/usr/bin/python3

from dataclasses import dataclass
from typing import List
import argparse
import pydot
import math
import sys
import re
import io
import os

@dataclass
class Insn:
    addr: int
    succ: List[int]
    text: str
    freq: int = 0
    cline: str = None

@dataclass
class BB:
    idx: int
    addr: int
    insns: List[Insn]
    succ: List[int]
    max_freq = 0

@dataclass
class CLine:
    tgt_log_line: int
    text: str

def dup_stdout():
    return os.fdopen(os.dup(sys.stdout.fileno()), 'w')

def dup_stdin():
    return os.fdopen(os.dup(sys.stdin.fileno()))

def read_graph(fn):
    bb_starts = set([0])
    bb_ends = set()
    addr2insn = {}
    cline = None

    def mk_insn(addr, liveregs, insn):
        if m := re.match(r'goto pc(?P<delta>[+-][0-9]+)', insn):
            delta = int(m['delta'])
            succ1 = addr + delta + 1
            succ2 = None
            bb_starts.add(succ1)
            bb_ends.add(addr)
        elif m := re.match(r'.*goto pc(?P<delta>[+-][0-9]+)', insn):
            delta = int(m['delta'])
            succ1 = addr + 1
            succ2 = addr + delta + 1
            bb_starts.add(succ1)
            bb_starts.add(succ2)
            bb_ends.add(addr)
        elif m := re.match(r'exit', insn):
            succ1 = None
            succ2 = None
            bb_ends.add(addr)
        elif m := re.match(r'r[0-9] = 0x[0-9a-f]+', insn):
            succ1 = addr + 2
            succ2 = None
        else:
            succ1 = addr + 1
            succ2 = None
        succ = []
        if succ1 is not None:
            succ.append(succ1)
        if succ2 is not None:
            succ.append(succ2)
        if liveregs:
            liveregs = f' {liveregs} '
        else:
            liveregs = ''
        return Insn(addr, succ, f'{liveregs}{insn}')

    with open(fn) if fn is not None else dup_stdin() as f:
        for line_num, line in enumerate(f):
            if m := re.match(r'(?P<cline>; .* @ .*)', line):
                cline = CLine(line_num + 1, m['cline'])
            elif m := re.match(r'[ ]*'
                               r'(?P<addr>[0-9]+): '
                               r'(?P<liveregs>[0-9\.]+ )?'
                               r'\([0-9a-f]+\) (?P<insn>[^\n;]*)'
                               r'([ ]+;.*)?'
                               r'\n',
                               line):
                addr = int(m['addr'])
                if addr not in addr2insn:
                    addr2insn[addr] = mk_insn(addr, m['liveregs'], m['insn'])
                insn = addr2insn[addr]
                insn.freq += 1
                if cline and cline.tgt_log_line == line_num:
                    insn.cline = cline.text

    insns = list(addr2insn.values())
    insns.sort(key=lambda insn: insn.addr)
    for insn in insns:
        for s in insn.succ:
            if s in bb_starts:
                bb_ends.add(insn.addr)
                break
    addr2bb = {}
    bb = None
    def new_bb(addr):
        return bb
    for insn in insns:
        if insn.addr in bb_starts or bb is None:
            bb = BB(len(addr2bb), insn.addr, [], [])
            addr2bb[insn.addr] = bb
        bb.insns.append(insn)
        bb.max_freq = max(bb.max_freq, insn.freq)
        bb_end = insn.addr in bb_ends
        if not bb_end:
            for s in insn.succ:
                if s in addr2insn and addr2insn[s].freq != insn.freq:
                    bb_end = True
                    break
        if bb_end:
            for s in insn.succ:
                bb.succ.append(s)
            bb = None
    return addr2bb

def count_digits(n):
    n = abs(n)
    d = 0
    while n > 1000:
        n //= 1000
        d += 3
    while n > 0:
        n //= 10
        d += 1
    return d

def compute_backedges(addr2bb):
    EXPLORE = 1
    POP = 2
    visited = set()
    backedges = set()
    bbs = sorted(list(addr2bb.values()), key=lambda bb: bb.addr)
    for bb in bbs:
        stack = [(bb, EXPLORE)]
        spine = set()
        while stack:
            v, state = stack.pop()
            if state == EXPLORE:
                if v.addr in visited:
                    continue
                visited.add(v.addr)
                spine.add(v.addr)
                stack.append((v, POP))
                for s in reversed(v.succ):
                    if s in spine:
                        backedges.add((v.addr, s))
                        continue
                    if s in addr2bb: # dead code has no bb's
                        stack.append((addr2bb[s], EXPLORE))
            elif state == POP:
                spine.remove(v.addr)
    return backedges

def graph2dot(addr2bb):
    g = pydot.Dot("G", graph_type="digraph")
    g.set_node_defaults(shape="box", fontname="monospace",
                        colorscheme="ylorbr8", style='filled')
    max_color = 4
    max_freq = 0
    for bb in addr2bb.values():
        max_freq = max(max_freq, bb.max_freq)
    max_freq += 1
    max_freq = int(math.log2(max_freq))
    color_step = max_freq // max_color
    if color_step == 0:
        color_step = 1
    #print(f'max_freq={max_freq}, color_step={color_step}')
    for bb in addr2bb.values():
        with io.StringIO() as out:
            addr_digits = 0
            insn_chars = 0
            for insn in bb.insns:
                addr_digits = max(addr_digits, count_digits(insn.addr))
                insn_chars = max(insn_chars, len(insn.text))
            insn_padding = insn_chars + 8
            for insn in bb.insns:
                if insn.cline:
                    out.write(f"{insn.cline}\\l")
                out.write(f"{insn.addr:{addr_digits}}: {insn.text:{insn_padding}} {insn.freq}\\l")
            label = out.getvalue()
        color = math.log2(bb.max_freq)
        color = int(color // color_step)
        #print(f'bb.max_freq={bb.max_freq}, color={color}')
        n = pydot.Node(bb.addr, label=label.replace('\\n', ''), fillcolor=color + 1)
        g.add_node(n)
    backedges = compute_backedges(addr2bb)
    for bb in addr2bb.values():
        for i, s in enumerate(bb.succ):
            e = pydot.Edge(bb.addr, s)
            if i == 1:
                e.get_attributes()['color'] = 'blue'
            if (bb.addr, s) in backedges:
                e.get_attributes()['penwidth'] = '5'
            g.add_edge(e)
    return g

def log2dot(log_file, dot_file):
    addr2bb = read_graph(log_file)
    g = graph2dot(addr2bb)
    with open(dot_file, 'w') if dot_file is not None else dup_stdout() as out:
        out.write(g.to_string())

def parse_args(args=None):
    parser = argparse.ArgumentParser(
        prog='log2dot',
        description='Converts level 2 BPF verifier log to annotated CFG and outputs it in DOT format.')
    parser.add_argument(
        'log_file',
        nargs='?',
        help='Path to verifier log, produced with LOG_LEVEL2, e.g. using `veristat -v -l2 ...`. '
             'If omitted, input is read from stdin.')
    parser.add_argument(
        '-o', '--output',
        metavar='dot_file',
        dest='dot_file',
        help='Output file path, if omitted output is printed to stdout.')
    #parser.add_argument('--split-at-freq-boundary')
    return parser.parse_args(args)

if __name__ == '__main__':
    args = parse_args()
    log2dot(args.log_file, args.dot_file)

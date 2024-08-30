import struct
from dataclasses import dataclass
from enum import Enum
from typing_extensions import List, Tuple
from lief import DEX


def parse_FMT10X(buffer: bytearray, dex_object: DEX.File, offset):
    return ()


def parse_FMT10T(buffer: bytearray, dex_object: DEX.File, offset):
    (val,) = struct.unpack_from("b", buffer, 1)
    return ("%04x" % (val + offset),)


def parse_FMT10u(buffer: bytearray, dex_object: DEX.File, offset):
    (val,) = struct.unpack_from("b", buffer, 1)
    return ("%04x" % (val + offset),)


def parse_FMT11N(buffer: bytearray, dex_object: DEX.File, offset):
    return (
        "v%d" % ((buffer[1]) & 0xF),
        "%d" % (((buffer[1]) >> 4) & 0xF),
    )


def parse_FMT11X(buffer: bytearray, dex_object: DEX.File, offset):
    return ("v%d" % (buffer[1]),)


def parse_FMT12X(buffer: bytearray, dex_object: DEX.File, offset):
    return (
        "v%d" % ((buffer[1]) & 0x0F),
        "v%d" % (((buffer[1]) >> 4) & 0xF),
    )


def parse_FMT20T(buffer: bytearray, dex_object: DEX.File, offset):
    (v,) = struct.unpack_from("h", buffer, 2)
    return ("%04x" % (v + offset),)


def parse_FMT21C(buffer: bytearray, dex_object: DEX.File, offset):
    op = buffer[0]

    (v,) = struct.unpack_from("H", buffer, 2)
    arg1 = "@%d" % v
    if op == 0x1A:
        arg1 = '"%s"' % dex_object.strings[v]
    elif op in [0x1C, 0x1F, 0x22]:
        # arg1 = "type@%s"%dex_object.gettypename(v)
        # arg1 = "field@%s  //%s"%(dex_object.getfieldname(v),dex_object.getfieldfullname(v))
        # arg1 = dex_object.types[v].value.pretty_name if v in dex_object.types else v
        arg1 = "%s" % (dex_object.types[v])
    return (
        "v%d" % (buffer[1]),
        arg1,
    )


def parse_FMT21H(buffer: bytearray, dex_object: DEX.File, offset):
    (v,) = struct.unpack_from("H", buffer, 2)
    if (buffer[1]) == 0x19:
        arg1 = "@%d000000000000" % v
    else:
        arg1 = "@%d0000" % v
    return (
        "v%d" % (buffer[1]),
        arg1,
    )


def parse_FMT21S(buffer: bytearray, dex_object: DEX.File, offset):
    (v,) = struct.unpack_from("H", buffer, 2)
    arg1 = "%d" % v
    return (
        "v%d" % (buffer[1]),
        arg1,
    )


def parse_FMT21T(buffer: bytearray, dex_object: DEX.File, offset):
    (v,) = struct.unpack_from("h", buffer, 2)
    arg1 = "%04x" % (v + offset)
    return (
        "v%d" % (buffer[1]),
        arg1,
    )


def parse_FMT22B(buffer: bytearray, dex_object: DEX.File, offset):
    (
        cc,
        bb,
    ) = struct.unpack_from("Bb", buffer, 2)
    return (
        "v%d" % (buffer[1]),
        "v%d" % bb,
        "%d" % cc,
    )


def parse_FMT22C(buffer: bytearray, dex_object: DEX.File, offset):
    (cccc,) = struct.unpack_from("H", buffer, 2)
    if (buffer[0]) == 0x20 or (buffer[0]) == 0x23:
        # prefix="type@%s"%(dex_object.gettypename(cccc))
        prefix = "%s" % (dex_object.types[cccc])
    else:
        # prefix="field@%s  //%s"%(dex_object.getfieldname(cccc),dex_object.getfieldfullname(cccc))
        prefix = "%s" % (dex_object.fields[cccc])

    bb = (buffer[1]) >> 4
    return (
        "v%d" % ((buffer[1]) & 0xF),
        "v%d" % (((buffer[1]) >> 4) & 0xF),
        "%s" % prefix,
    )


def parse_FMT22S(buffer: bytearray, dex_object: DEX.File, offset):
    bb = (buffer[1]) >> 4
    (cccc,) = struct.unpack_from("h", buffer, 2)
    return (
        "v%d" % ((buffer[1]) & 0xF),
        "v%d" % (((buffer[1]) >> 4) & 0xF),
        "%d" % cccc,
    )


def parse_FMT22T(buffer: bytearray, dex_object: DEX.File, offset):
    bb = (buffer[1]) >> 4
    (cccc,) = struct.unpack_from("h", buffer, 2)

    return (
        "v%d" % ((buffer[1]) & 0xF),
        "v%d" % (((buffer[1]) >> 4) & 0xF),
        "%04x" % int(cccc + offset),
    )


def parse_FMT22X(buffer: bytearray, dex_object: DEX.File, offset):
    (v,) = struct.unpack_from("h", buffer, 2)
    arg1 = "v%d" % v
    return (
        "v%d" % (buffer[1]),
        arg1,
    )


def parse_FMT23X(buffer: bytearray, dex_object: DEX.File, offset):
    (
        cc,
        bb,
    ) = struct.unpack_from("Bb", buffer, 2)
    return (
        "v%d" % (buffer[1]),
        "v%d" % bb,
        "v%d" % cc,
    )


def parse_FMT30T(buffer: bytearray, dex_object: DEX.File, offset):
    (aaaaaaaa,) = struct.unpack_from("i", buffer, 2)
    return ("+%x" % (aaaaaaaa + offset),)


def parse_FMT31C(buffer: bytearray, dex_object: DEX.File, offset):
    (bbbbbbbb,) = struct.unpack_from("I", buffer, 2)
    return (
        "v%d" % (buffer[1]),
        "+%d" % bbbbbbbb,
    )


def parse_FMT31I(buffer: bytearray, dex_object: DEX.File, offset):
    (bbbbbbbb,) = struct.unpack_from("I", buffer, 2)
    return (
        "v%d" % (buffer[1]),
        "%d" % bbbbbbbb,
    )


def parse_FMT31T(buffer: bytearray, dex_object: DEX.File, offset):
    (bbbbbbbb,) = struct.unpack_from("i", buffer, 2)
    return (
        "v%d" % (buffer[1]),
        "string@%d" % bbbbbbbb,
    )


def parse_FMT32X(buffer: bytearray, dex_object: DEX.File, offset):
    (
        aaaa,
        bbbb,
    ) = struct.unpack_from("hh", buffer, 2)
    return (
        "v%d" % aaaa,
        "v%d" % bbbb,
    )


def parse_FMT35C(buffer: bytearray, dex_object: DEX.File, offset: int):
    A = (buffer[1]) >> 4
    G = (buffer[1]) & 0xF
    D = (buffer[4]) >> 4
    C = (buffer[4]) & 0xF
    F = (buffer[5]) >> 4
    E = (buffer[5]) & 0xF
    (bbbb,) = struct.unpack_from("H", buffer, 2)
    if (buffer[0]) == 0x24:
        prefix = "type@%s" % (dex_object.strings[bbbb])
    else:
        # prefix="meth@%s  //%s"%(dex_object.getmethodname(bbbb),dex_object.getmethodfullname(bbbb,True))
        prefix = "%s" % (dex_object.methods[bbbb])
        pass
    if A == 5:
        return (
            "v%d" % C,
            "v%d" % D,
            "v%d" % E,
            "v%d" % F,
            "v%d" % G,
            "%s" % (prefix),
        )
    elif A == 4:
        return (
            "v%d" % C,
            "v%d" % D,
            "v%d" % E,
            "v%d" % F,
            "%s" % (prefix),
        )
    elif A == 3:
        return (
            "v%d" % C,
            "v%d" % D,
            "v%d" % E,
            "%s" % (prefix),
        )
    elif A == 2:
        return (
            "v%d" % C,
            "v%d" % D,
            "%s" % (prefix),
        )
    elif A == 1:
        return (
            "v%d" % C,
            "%s" % (prefix),
        )
    elif A == 0:
        return ("%s" % (prefix),)
    else:
        return "error ......."
    return (
        "v%d" % C,
        "v%d" % D,
        "v%d" % E,
        "v%d" % F,
        "v%d" % G,
        "%s" % (prefix),
    )


def parse_FMT3RC(buffer: bytearray, dex_object: DEX.File, offset):
    return ()


def parse_FMT51L(buffer: bytearray, dex_object: DEX.File, offset):
    if len(buffer) < 10:
        return (1, "")
    bb = struct.unpack_from("q", buffer, 2)
    return (
        INSTRUCTIONS[buffer[0]][1],
        "v%d" % (buffer[1]),
        "%d" % bb,
    )


class Template(Enum):
    FMT10T = 0, "fmt10t", 1, parse_FMT10T
    FMT10X = 1, "fmt10x", 1, parse_FMT10X
    FMT11N = 2, "fmt11n", 1, parse_FMT11N
    FMT11X = 3, "fmt11x", 1, parse_FMT11X
    FMT12X = 4, "fmt12x", 1, parse_FMT12X
    FMT20T = 5, "fmt20t", 2, parse_FMT20T
    FMT21C = 6, "fmt21c", 2, parse_FMT21C
    FMT21H = 7, "fmt21h", 2, parse_FMT21H
    FMT21S = 8, "fmt21s", 2, parse_FMT21S
    FMT21T = 9, "fmt21t", 2, parse_FMT21T
    FMT22B = 10, "fmt22b", 2, parse_FMT22B
    FMT22C = 11, "fmt22c", 2, parse_FMT22C
    FMT22S = 12, "fmt22s", 2, parse_FMT22S
    FMT22T = 13, "fmt22t", 2, parse_FMT22T
    FMT22X = 14, "fmt22x", 2, parse_FMT22X
    FMT23X = 15, "fmt23x", 2, parse_FMT23X
    FMT30T = 16, "fmt30t", 3, parse_FMT30T
    FMT31C = 17, "fmt31c", 3, parse_FMT31C
    FMT31I = 18, "fmt31i", 3, parse_FMT31I
    FMT31T = 19, "fmt31t", 3, parse_FMT31T
    FMT32X = 20, "fmt32x", 3, parse_FMT32X
    FMT35C = 21, "fmt35c", 3, parse_FMT35C
    FMT3RC = 22, "fmt3rc", 3, parse_FMT3RC
    FMT51L = 23, "fmt51l", 5, parse_FMT51L

    def __init__(self, id: int, label: str, size: int, parse: callable):
        self.id = id
        self.label = label
        self.size = size
        self.parse = parse


@dataclass
class Instruction(object):
    op: int
    label: str
    template: Template

    @property
    def size(self):
        return self.template.size

    def __getitem__(self, index):
        if index == 0:
            return self.template.id
        if index == 1:
            return self.label
        if index == 2:
            return self.template.size
        if index == 0:
            return self.id


INSTRUCTIONS = {
    0: Instruction(0x00, "nop", Template.FMT10X),
    1: Instruction(0x01, "move", Template.FMT12X),
    2: Instruction(0x02, "move/from16", Template.FMT22X),
    3: Instruction(0x03, "move/16", Template.FMT32X),
    4: Instruction(0x04, "move-wide", Template.FMT12X),
    5: Instruction(0x05, "move-wide/from16", Template.FMT22X),
    6: Instruction(0x06, "move-wide/16", Template.FMT32X),
    7: Instruction(0x07, "move-object", Template.FMT12X),
    8: Instruction(0x08, "move-object/from16", Template.FMT22X),
    9: Instruction(0x09, "move-object/16", Template.FMT32X),
    10: Instruction(0x0A, "move-result", Template.FMT11X),
    11: Instruction(0x0B, "move-result-wide", Template.FMT11X),
    12: Instruction(0x0C, "move-result-object", Template.FMT11X),
    13: Instruction(0x0D, "move-exception", Template.FMT11X),
    14: Instruction(0x0E, "return-void", Template.FMT10X),
    15: Instruction(0x0F, "return", Template.FMT11X),
    16: Instruction(0x10, "return-wide", Template.FMT11X),
    17: Instruction(0x11, "return-object", Template.FMT11X),
    18: Instruction(0x12, "const/4", Template.FMT11N),
    19: Instruction(0x13, "const/16", Template.FMT21S),
    20: Instruction(0x14, "const", Template.FMT31I),
    21: Instruction(0x15, "const/high16", Template.FMT21H),
    22: Instruction(0x16, "const-wide/16", Template.FMT21S),
    23: Instruction(0x17, "const-wide/32", Template.FMT31I),
    24: Instruction(0x18, "const-wide", Template.FMT51L),
    25: Instruction(0x19, "const-wide/high16", Template.FMT21H),
    26: Instruction(0x1A, "const-string", Template.FMT21C),
    27: Instruction(0x1B, "const-string/jumbo", Template.FMT31C),
    28: Instruction(0x1C, "const-class", Template.FMT21C),
    29: Instruction(0x1D, "monitor-enter", Template.FMT11X),
    30: Instruction(0x1E, "monitor-exit", Template.FMT11X),
    31: Instruction(0x1F, "check-cast", Template.FMT21C),
    32: Instruction(0x20, "instance-of", Template.FMT22C),
    33: Instruction(0x21, "array-length", Template.FMT12X),
    34: Instruction(0x22, "new-instance", Template.FMT21C),
    35: Instruction(0x23, "new-array", Template.FMT22C),
    36: Instruction(0x24, "filled-new-array", Template.FMT35C),
    37: Instruction(0x25, "filled-new-array/range", Template.FMT3RC),
    38: Instruction(0x26, "fill-array-data", Template.FMT31T),
    39: Instruction(0x27, "throw", Template.FMT11X),
    40: Instruction(0x28, "goto", Template.FMT10T),
    41: Instruction(0x29, "goto/16", Template.FMT20T),
    42: Instruction(0x2A, "goto/32", Template.FMT30T),
    43: Instruction(0x2B, "packed-switch", Template.FMT31T),
    44: Instruction(0x2C, "sparse-switch", Template.FMT31T),
    45: Instruction(0x2D, "cmpl-float", Template.FMT23X),
    46: Instruction(0x2E, "cmpg-float", Template.FMT23X),
    47: Instruction(0x2F, "cmpl-double", Template.FMT23X),
    48: Instruction(0x30, "cmpg-double", Template.FMT23X),
    49: Instruction(0x31, "cmp-long", Template.FMT23X),
    50: Instruction(0x32, "if-eq", Template.FMT22T),
    51: Instruction(0x33, "if-ne", Template.FMT22T),
    52: Instruction(0x34, "if-lt", Template.FMT22T),
    53: Instruction(0x35, "if-ge", Template.FMT22T),
    54: Instruction(0x36, "if-gt", Template.FMT22T),
    55: Instruction(0x37, "if-le", Template.FMT22T),
    56: Instruction(0x38, "if-eqz", Template.FMT21T),
    57: Instruction(0x39, "if-nez", Template.FMT21T),
    58: Instruction(0x3A, "if-ltz", Template.FMT21T),
    59: Instruction(0x3B, "if-gez", Template.FMT21T),
    60: Instruction(0x3C, "if-gtz", Template.FMT21T),
    61: Instruction(0x3D, "if-lez", Template.FMT21T),
    62: Instruction(0x3E, "unused", Template.FMT10X),
    63: Instruction(0x3F, "unused", Template.FMT10X),
    64: Instruction(0x40, "unused", Template.FMT10X),
    65: Instruction(0x41, "unused", Template.FMT10X),
    66: Instruction(0x42, "unused", Template.FMT10X),
    67: Instruction(0x43, "unused", Template.FMT10X),
    68: Instruction(0x44, "aget", Template.FMT23X),
    69: Instruction(0x45, "aget-wide", Template.FMT23X),
    70: Instruction(0x46, "aget-object", Template.FMT23X),
    71: Instruction(0x47, "aget-boolean", Template.FMT23X),
    72: Instruction(0x48, "aget-byte", Template.FMT23X),
    73: Instruction(0x49, "aget-char", Template.FMT23X),
    74: Instruction(0x4A, "aget-short", Template.FMT23X),
    75: Instruction(0x4B, "aput", Template.FMT23X),
    76: Instruction(0x4C, "aput-wide", Template.FMT23X),
    77: Instruction(0x4D, "aput-object", Template.FMT23X),
    78: Instruction(0x4E, "aput-boolean", Template.FMT23X),
    79: Instruction(0x4F, "aput-byte", Template.FMT23X),
    80: Instruction(0x50, "aput-shar", Template.FMT23X),
    81: Instruction(0x51, "aput-short", Template.FMT23X),
    82: Instruction(0x52, "iget", Template.FMT22C),
    83: Instruction(0x53, "iget-wide", Template.FMT22C),
    84: Instruction(0x54, "iget-object", Template.FMT22C),
    85: Instruction(0x55, "iget-boolean", Template.FMT22C),
    86: Instruction(0x56, "iget-byte", Template.FMT22C),
    87: Instruction(0x57, "iget-char", Template.FMT22C),
    88: Instruction(0x58, "iget-short", Template.FMT22C),
    89: Instruction(0x59, "iput", Template.FMT22C),
    90: Instruction(0x5A, "iput-wide", Template.FMT22C),
    91: Instruction(0x5B, "iput-object", Template.FMT22C),
    92: Instruction(0x5C, "iput-boolean", Template.FMT22C),
    93: Instruction(0x5D, "iput-byte", Template.FMT22C),
    94: Instruction(0x5E, "iput-char", Template.FMT22C),
    95: Instruction(0x5F, "iput-short", Template.FMT22C),
    96: Instruction(0x60, "sget", Template.FMT21C),
    97: Instruction(0x61, "sget-wide", Template.FMT21C),
    98: Instruction(0x62, "sget-object", Template.FMT21C),
    99: Instruction(0x63, "sget-boolean", Template.FMT21C),
    100: Instruction(0x64, "sget-byte", Template.FMT21C),
    101: Instruction(0x65, "sget-char", Template.FMT21C),
    102: Instruction(0x66, "sget-short", Template.FMT21C),
    103: Instruction(0x67, "sput", Template.FMT21C),
    104: Instruction(0x68, "sput-wide", Template.FMT21C),
    105: Instruction(0x69, "sput-object", Template.FMT21C),
    106: Instruction(0x6A, "sput-boolean", Template.FMT21C),
    107: Instruction(0x6B, "sput-byte", Template.FMT21C),
    108: Instruction(0x6C, "sput-char", Template.FMT21C),
    109: Instruction(0x6D, "sput-short", Template.FMT21C),
    110: Instruction(0x6E, "invoke-virtual", Template.FMT35C),
    111: Instruction(0x6F, "invoke-super", Template.FMT35C),
    112: Instruction(0x70, "invoke-direct", Template.FMT35C),
    113: Instruction(0x71, "invoke-static", Template.FMT35C),
    114: Instruction(0x72, "invoke-insterface", Template.FMT35C),
    115: Instruction(0x73, "unused", Template.FMT10X),
    116: Instruction(0x74, "invoke-virtual/range", Template.FMT3RC),
    117: Instruction(0x75, "invoke-super/range", Template.FMT3RC),
    118: Instruction(0x76, "invoke-direct/range", Template.FMT3RC),
    119: Instruction(0x77, "invoke-static/range", Template.FMT3RC),
    120: Instruction(0x78, "invoke-interface/range", Template.FMT3RC),
    121: Instruction(0x79, "unused", Template.FMT10X),
    122: Instruction(0x7A, "unused", Template.FMT10X),
    123: Instruction(0x7B, "neg-int", Template.FMT12X),
    124: Instruction(0x7C, "not-int", Template.FMT12X),
    125: Instruction(0x7D, "neg-long", Template.FMT12X),
    126: Instruction(0x7E, "not-long", Template.FMT12X),
    127: Instruction(0x7F, "neg-float", Template.FMT12X),
    128: Instruction(0x80, "neg-double", Template.FMT12X),
    129: Instruction(0x81, "int-to-long", Template.FMT12X),
    130: Instruction(0x82, "int-to-float", Template.FMT12X),
    131: Instruction(0x83, "int-to-double", Template.FMT12X),
    132: Instruction(0x84, "long-to-int", Template.FMT12X),
    133: Instruction(0x85, "long-to-float", Template.FMT12X),
    134: Instruction(0x86, "long-to-double", Template.FMT12X),
    135: Instruction(0x87, "float-to-int", Template.FMT12X),
    136: Instruction(0x88, "float-to-long", Template.FMT12X),
    137: Instruction(0x89, "float-to-double", Template.FMT12X),
    138: Instruction(0x8A, "double-to-int", Template.FMT12X),
    139: Instruction(0x8B, "double-to-long", Template.FMT12X),
    140: Instruction(0x8C, "double-to-float", Template.FMT12X),
    141: Instruction(0x8D, "int-to-byte", Template.FMT12X),
    142: Instruction(0x8E, "int-to-char", Template.FMT12X),
    143: Instruction(0x8F, "int-to-short", Template.FMT12X),
    144: Instruction(0x90, "add-int", Template.FMT23X),
    145: Instruction(0x91, "sub-int", Template.FMT23X),
    146: Instruction(0x92, "mul-int", Template.FMT23X),
    147: Instruction(0x93, "div-int", Template.FMT23X),
    148: Instruction(0x94, "rem-int", Template.FMT23X),
    149: Instruction(0x95, "and-int", Template.FMT23X),
    150: Instruction(0x96, "or-int", Template.FMT23X),
    151: Instruction(0x97, "xor-int", Template.FMT23X),
    152: Instruction(0x98, "shl-int", Template.FMT23X),
    153: Instruction(0x99, "shr-int", Template.FMT23X),
    154: Instruction(0x9A, "ushr-int", Template.FMT23X),
    155: Instruction(0x9B, "add-long", Template.FMT23X),
    156: Instruction(0x9C, "sub-long", Template.FMT23X),
    157: Instruction(0x9D, "mul-long", Template.FMT23X),
    158: Instruction(0x9E, "div-long", Template.FMT23X),
    159: Instruction(0x9F, "rem-long", Template.FMT23X),
    160: Instruction(0xA0, "and-long", Template.FMT23X),
    161: Instruction(0xA1, "or-long", Template.FMT23X),
    162: Instruction(0xA2, "xor-long", Template.FMT23X),
    163: Instruction(0xA3, "shl-long", Template.FMT23X),
    164: Instruction(0xA4, "shr-long", Template.FMT23X),
    165: Instruction(0xA5, "ushr-long", Template.FMT23X),
    166: Instruction(0xA6, "add-float", Template.FMT23X),
    167: Instruction(0xA7, "sub-float", Template.FMT23X),
    168: Instruction(0xA8, "mul-float", Template.FMT23X),
    169: Instruction(0xA9, "div-float", Template.FMT23X),
    170: Instruction(0xAA, "rem-float", Template.FMT23X),
    171: Instruction(0xAB, "add-double", Template.FMT23X),
    172: Instruction(0xAC, "sub-double", Template.FMT23X),
    173: Instruction(0xAD, "mul-double", Template.FMT23X),
    174: Instruction(0xAE, "div-double", Template.FMT23X),
    175: Instruction(0xAF, "rem-double", Template.FMT23X),
    176: Instruction(0xB0, "add-int/2addr", Template.FMT12X),
    177: Instruction(0xB1, "sub-int/2addr", Template.FMT12X),
    178: Instruction(0xB2, "mul-int/2addr", Template.FMT12X),
    179: Instruction(0xB3, "div-int/2addr", Template.FMT12X),
    180: Instruction(0xB4, "rem-int/2addr", Template.FMT12X),
    181: Instruction(0xB5, "and-int/2addr", Template.FMT12X),
    182: Instruction(0xB6, "or-int/2addr", Template.FMT12X),
    183: Instruction(0xB7, "xor-int/2addr", Template.FMT12X),
    184: Instruction(0xB8, "shl-int/2addr", Template.FMT12X),
    185: Instruction(0xB9, "shr-int/2addr", Template.FMT12X),
    186: Instruction(0xBA, "ushr-int/2addr", Template.FMT12X),
    187: Instruction(0xBB, "add-long/2addr", Template.FMT12X),
    188: Instruction(0xBC, "sub-long/2addr", Template.FMT12X),
    189: Instruction(0xBD, "mul-long/2addr", Template.FMT12X),
    190: Instruction(0xBE, "div-long/2addr", Template.FMT12X),
    191: Instruction(0xBF, "rem-long/2addr", Template.FMT12X),
    192: Instruction(0xC0, "and-long/2addr", Template.FMT12X),
    193: Instruction(0xC1, "or-long/2addr", Template.FMT12X),
    194: Instruction(0xC2, "xor-long/2addr", Template.FMT12X),
    195: Instruction(0xC3, "shl-long/2addr", Template.FMT12X),
    196: Instruction(0xC4, "shr-long/2addr", Template.FMT12X),
    197: Instruction(0xC5, "ushr-long/2addr", Template.FMT12X),
    198: Instruction(0xC6, "add-float/2addr", Template.FMT12X),
    199: Instruction(0xC7, "sub-float/2addr", Template.FMT12X),
    200: Instruction(0xC8, "mul-float/2addr", Template.FMT12X),
    201: Instruction(0xC9, "div-float/2addr", Template.FMT12X),
    202: Instruction(0xCA, "rem-float/2addr", Template.FMT12X),
    203: Instruction(0xCB, "add-double/2addr", Template.FMT12X),
    204: Instruction(0xCC, "sub-double/2addr", Template.FMT12X),
    205: Instruction(0xCD, "mul-double/2addr", Template.FMT12X),
    206: Instruction(0xCE, "div-double/2addr", Template.FMT12X),
    207: Instruction(0xCF, "rem-double/2addr", Template.FMT12X),
    208: Instruction(0xD0, "add-int/lit16", Template.FMT22S),
    209: Instruction(0xD1, "rsub-int", Template.FMT22S),
    210: Instruction(0xD2, "mul-int/lit16", Template.FMT22S),
    211: Instruction(0xD3, "div-int/lit16", Template.FMT22S),
    212: Instruction(0xD4, "rem-int/lit16", Template.FMT22S),
    213: Instruction(0xD5, "and-int/lit16", Template.FMT22S),
    214: Instruction(0xD6, "or-int/lit16", Template.FMT22S),
    215: Instruction(0xD7, "xor-int/lit16", Template.FMT22S),
    216: Instruction(0xD8, "add-int/lit8", Template.FMT22B),
    217: Instruction(0xD9, "rsub-int/lit8", Template.FMT22B),
    218: Instruction(0xDA, "mul-int/lit8", Template.FMT22B),
    219: Instruction(0xDB, "div-int/lit8", Template.FMT22B),
    220: Instruction(0xDC, "rem-int/lit8", Template.FMT22B),
    221: Instruction(0xDD, "and-int/lit8", Template.FMT22B),
    222: Instruction(0xDE, "or-int/lit8", Template.FMT22B),
    223: Instruction(0xDF, "xor-int/lit8", Template.FMT22B),
    224: Instruction(0xE0, "shl-int/lit8", Template.FMT22B),
    225: Instruction(0xE1, "shr-int/lit8", Template.FMT22B),
    226: Instruction(0xE2, "ushr-int/lit8", Template.FMT22B),
    227: Instruction(0xE3, "unused", Template.FMT10X),
    228: Instruction(0xE4, "unused", Template.FMT10X),
    229: Instruction(0xE5, "unused", Template.FMT10X),
    230: Instruction(0xE6, "unused", Template.FMT10X),
    231: Instruction(0xE7, "unused", Template.FMT10X),
    232: Instruction(0xE8, "unused", Template.FMT10X),
    233: Instruction(0xE9, "unused", Template.FMT10X),
    234: Instruction(0xEA, "unused", Template.FMT10X),
    235: Instruction(0xEB, "unused", Template.FMT10X),
    236: Instruction(0xEC, "unused", Template.FMT10X),
    237: Instruction(0xED, "unused", Template.FMT10X),
    238: Instruction(0xEE, "unused", Template.FMT10X),
    239: Instruction(0xEF, "unused", Template.FMT10X),
    240: Instruction(0xF0, "unused", Template.FMT10X),
    241: Instruction(0xF1, "unused", Template.FMT10X),
    242: Instruction(0xF2, "unused", Template.FMT10X),
    243: Instruction(0xF3, "unused", Template.FMT10X),
    244: Instruction(0xF4, "unused", Template.FMT10X),
    245: Instruction(0xF5, "unused", Template.FMT10X),
    246: Instruction(0xF6, "unused", Template.FMT10X),
    247: Instruction(0xF7, "unused", Template.FMT10X),
    248: Instruction(0xF8, "unused", Template.FMT10X),
    249: Instruction(0xF9, "unused", Template.FMT10X),
    250: Instruction(0xFA, "unused", Template.FMT10X),
    251: Instruction(0xFB, "unused", Template.FMT10X),
    252: Instruction(0xFC, "unused", Template.FMT10X),
    253: Instruction(0xFD, "unused", Template.FMT10X),
    254: Instruction(0xFE, "unused", Template.FMT10X),
    255: Instruction(0xFF, "unused", Template.FMT10X),
}


def parse_instructions(
    method: DEX.Method, dex: DEX.File
) -> List[tuple[Instruction, Tuple]]:
    buffer = bytearray(method.bytecode)
    offset = method.code_offset
    start = 0
    out = []

    while start < len(buffer):
        op_digit = buffer[start]
        if op_digit == 0:
            type = buffer[start + 1]
            if type == 1:
                (size,) = struct.unpack_from("H", buffer, 2 + start)
                start += (size * 2 + 4) * 2
                continue
            elif type == 2:
                (size,) = struct.unpack_from("H", buffer, 2 + start)
                start += (size * 4 + 2) * 2
                continue
            elif type == 3:
                (width,) = struct.unpack_from("H", buffer, 2 + start)
                (size,) = struct.unpack_from("I", buffer, 4 + start)
                start += 8 + ((size * width + 1) // 2) * 2
                continue

        inst: Instruction = INSTRUCTIONS[op_digit]
        parsed = inst.template.parse(buffer[start:], dex, offset)
        text = ""
        m = 0
        for x in buffer[start : start + 2 * inst.size]:
            text += "%02x" % (x)
            m += 1
            if m % 2 == 0:
                text += " "

        # print(
        #     "%08x: %-36s |%04x: %s %s"
        #     % (
        #         offset + start,
        #         text,
        #         start // 2,
        #         inst.label,
        #         parsed,
        #     ),
        # )

        out.append((inst, parsed))

        start += 2 * inst.size
    return out

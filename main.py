from enum import IntEnum
from typing import NamedTuple


class Opcode(IntEnum):
    OP_PUSHDATA = -1
    OP_0 = 0x00
    OP_1 = 0x51
    OP_VERIFY = 0x69
    OP_RETURN = 0x6A
    OP_DROP = 0x75
    OP_DUP = 0x76
    OP_SWAP = 0x7C
    OP_EQUAL = 0x87
    OP_EQUALVERIFY = 0x88
    OP_ADD = 0x93
    OP_SUB = 0x94
    OP_HASH160 = 0xA9
    OP_SHA256 = 0xAA
    OP_CHECKSIG = 0xAC
    OP_CHECKSIGVERIFY = 0xAD


class Token(NamedTuple):
    opcode: Opcode
    data: bytes | None = None  # only for OP_PUSHDATA


def parse(raw_script: bytes) -> list[Token]:
    tokens: list[Token] = []
    pc = 0
    length = len(raw_script)
    while pc < length:
        byte = raw_script[pc]
        pc += 1

        if 0x01 <= byte <= 0x4B:
            data_len = byte
            tokens.append(Token(Opcode.OP_PUSHDATA, raw_script[pc : pc + data_len]))
            pc += data_len

        elif byte == 0x4C:
            data_len = raw_script[pc]
            pc += 1
            tokens.append(Token(Opcode.OP_PUSHDATA, raw_script[pc : pc + data_len]))
            pc += data_len

        elif byte == 0x4D:
            data_len = int.from_bytes(raw_script[pc : pc + 2], byteorder="little")
            pc += 2
            tokens.append(Token(Opcode.OP_PUSHDATA, raw_script[pc : pc + data_len]))
            pc += data_len

        else:
            try:
                opcode = Opcode(byte)
                tokens.append(Token(opcode))
            except ValueError:
                raise ValueError(
                    f"Unknown opcode byte: 0x{byte:02X} at offset {pc - 1}"
                )

    return tokens

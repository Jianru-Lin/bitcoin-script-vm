from enum import IntEnum
from typing import NamedTuple


class BytesReader:
    _raw: bytes
    _pc: int
    _length: int

    def __init__(self, raw: bytes):
        self._raw = raw
        self._pc = 0
        self._length = len(raw)

    @property
    def pc(self) -> int:
        return self._pc

    def is_eof(self) -> bool:
        return self._pc >= self._length

    def read_byte(self) -> int:
        if self._pc >= self._length:
            raise ValueError(
                f"Unexpected end of stream: cannot read 1 byte at offset {self._pc}"
            )
        val = self._raw[self._pc]
        self._pc += 1
        return val

    def read_bytes(self, n: int) -> bytes:
        if self._pc + n > self._length:
            raise ValueError(
                f"Unexpected end of stream: required {n} bytes, only {self._length - self._pc} available at offset {self._pc}"
            )
        data = self._raw[self._pc : self._pc + n]
        self._pc += n
        return data

    def read_uint16_le(self) -> int:
        return int.from_bytes(self.read_bytes(2), byteorder="little")

    def read_uint32_le(self) -> int:
        return int.from_bytes(self.read_bytes(4), byteorder="little")


class BytesWriter:
    _buf: bytearray

    def __init__(self) -> None:
        self._buf = bytearray()

    def write_byte(self, val: int) -> None:
        if not (0 <= val <= 0xFF):
            raise ValueError(f"Byte value out of range (0~255): {val}")
        self._buf.append(val)

    def write_bytes(self, data: bytes) -> None:
        self._buf.extend(data)

    def write_uint16_le(self, val: int) -> None:
        if not (0 <= val <= 0xFFFF):
            raise ValueError(f"Uint16 out of range (0~65535): {val}")
        self._buf.extend(val.to_bytes(2, byteorder="little"))

    def write_uint32_le(self, val: int) -> None:
        if not (0 <= val <= 0xFFFFFFFF):
            raise ValueError(f"Uint32 out of range (0~4294967295): {val}")
        self._buf.extend(val.to_bytes(4, byteorder="little"))

    def to_bytes(self) -> bytes:
        return bytes(self._buf)


# Check here https://github.com/bitcoin/bitcoin/blob/master/src/script/script.h
class Opcode(IntEnum):
    # Constants
    OP_PUSHDATA_DIRECT = -1  # 0x01 ~ 0x4B
    OP_PUSHDATA1 = 0x4C
    OP_PUSHDATA2 = 0x4D
    OP_PUSHDATA4 = 0x4E
    OP_1NEGATE = 0x4F
    OP_0 = 0x00  # OP_FALSE
    OP_1 = 0x51  # OP_TRUE
    OP_2 = 0x52
    OP_3 = 0x53
    OP_4 = 0x54
    OP_5 = 0x55
    OP_6 = 0x56
    OP_7 = 0x57
    OP_8 = 0x58
    OP_9 = 0x59
    OP_10 = 0x5A
    OP_11 = 0x5B
    OP_12 = 0x5C
    OP_13 = 0x5D
    OP_14 = 0x5E
    OP_15 = 0x5F
    OP_16 = 0x60
    # Flow control
    OP_NOP = 0x61
    OP_IF = 0x63
    OP_NOTIF = 0x64
    OP_ELSE = 0x67
    OP_ENDIF = 0x68
    OP_VERIFY = 0x69
    OP_RETURN = 0x6A
    # Stack
    OP_TOALTSTACK = 0x6B
    OP_FROMALTSTACK = 0x6C
    OP_IFDUP = 0x73
    OP_DEPTH = 0x74
    OP_DROP = 0x75
    OP_DUP = 0x76
    OP_NIP = 0x77
    OP_OVER = 0x78
    OP_PICK = 0x79
    OP_ROLL = 0x7A
    OP_ROT = 0x7B
    OP_SWAP = 0x7C
    OP_TUCK = 0x7D
    OP_2DROP = 0x6D
    OP_2DUP = 0x6E
    OP_3DUP = 0x6F
    OP_2OVER = 0x70
    OP_2ROT = 0x71
    OP_2SWAP = 0x72
    # Splice
    OP_CAT = 0x7E
    OP_SUBSTR = 0x7F
    OP_LEFT = 0x80
    OP_RIGHT = 0x81
    OP_SIZE = 0x82
    # Bitwise logic
    OP_INVERT = 0x83
    OP_AND = 0x84
    OP_OR = 0x85
    OP_XOR = 0x86
    OP_EQUAL = 0x87
    OP_EQUALVERIFY = 0x88
    # Arithmetic
    OP_1ADD = 0x8B
    OP_1SUB = 0x8C
    OP_2MUL = 0x8D
    OP_2DIV = 0x8E
    OP_NEGATE = 0x8F
    OP_ABS = 0x90
    OP_NOT = 0x91
    OP_0NOTEQUAL = 0x92
    OP_ADD = 0x93
    OP_SUB = 0x94
    OP_MUL = 0x95
    OP_DIV = 0x96
    OP_MOD = 0x97
    OP_LSHIFT = 0x98
    OP_RSHIFT = 0x99
    OP_BOOLAND = 0x9A
    OP_BOOLOR = 0x9B
    OP_NUMEQUAL = 0x9C
    OP_NUMEQUALVERIFY = 0x9D
    OP_NUMNOTEQUAL = 0x9E
    OP_LESSTHAN = 0x9F
    OP_GREATERTHAN = 0xA0
    OP_LESSTHANOREQUAL = 0xA1
    OP_GREATERTHANOREQUAL = 0xA2
    OP_MIN = 0xA3
    OP_MAX = 0xA4
    OP_WITHIN = 0xA5
    # Crypto
    OP_RIPEMD160 = 0xA6
    OP_SHA1 = 0xA7
    OP_SHA256 = 0xA8
    OP_HASH160 = 0xA9
    OP_HASH256 = 0xAA
    OP_CODESEPARATOR = 0xAB
    OP_CHECKSIG = 0xAC
    OP_CHECKSIGVERIFY = 0xAD
    OP_CHECKMULTISIG = 0xAE
    OP_CHECKMULTISIGVERIFY = 0xAF
    OP_CHECKSIGADD = 0xBA
    # Locktime
    OP_CHECKLOCKTIMEVERIFY = 0xB1  # OP_NOP2
    OP_CHECKSEQUENCEVERIFY = 0xB2  # OP_NOP3
    # Reserved words
    OP_RESERVED = 0x50
    OP_VER = 0x62
    OP_VERIF = 0x65
    OP_VERNOTIF = 0x66
    OP_RESERVED1 = 0x89
    OP_RESERVED2 = 0x8A
    OP_NOP1 = 0xB0
    OP_NOP4 = 0xB3
    OP_NOP5 = 0xB4
    OP_NOP6 = 0xB5
    OP_NOP7 = 0xB6
    OP_NOP8 = 0xB7
    OP_NOP9 = 0xB8
    OP_NOP10 = 0xB9
    OP_INVALIDOPCODE = 0xFF


class ScriptToken(NamedTuple):
    opcode: Opcode
    data: bytes | None = None  # only for OP_PUSHDATA


class ScriptParser:
    _reader: BytesReader

    def __init__(self, raw_script: bytes) -> None:
        self._reader = BytesReader(raw_script)

    @property
    def reader(self) -> BytesReader:
        return self._reader

    def is_eof(self) -> bool:
        return self._reader.is_eof()

    def next_token(self) -> ScriptToken | None:
        reader = self._reader

        if reader.is_eof():
            return None

        offset = reader.pc
        byte = reader.read_byte()

        if 0x01 <= byte <= 0x4B:
            data = reader.read_bytes(byte)
            return ScriptToken(Opcode.OP_PUSHDATA_DIRECT, data)

        elif byte == Opcode.OP_PUSHDATA1:
            data_len = reader.read_byte()
            data = reader.read_bytes(data_len)
            return ScriptToken(Opcode.OP_PUSHDATA1, data)

        elif byte == Opcode.OP_PUSHDATA2:
            data_len = reader.read_uint16_le()
            data = reader.read_bytes(data_len)
            return ScriptToken(Opcode.OP_PUSHDATA2, data)

        elif byte == Opcode.OP_PUSHDATA4:
            data_len = reader.read_uint32_le()
            data = reader.read_bytes(data_len)
            return ScriptToken(Opcode.OP_PUSHDATA4, data)

        else:
            try:
                opcode = Opcode(byte)
                return ScriptToken(opcode)
            except ValueError:
                raise ValueError(
                    f"Unknown opcode byte: 0x{byte:02X} at offset {offset}"
                )

    def __iter__(self):
        while (token := self.next_token()) is not None:
            yield token

    @staticmethod
    def parse(raw_script: bytes) -> list[ScriptToken]:
        parser = ScriptParser(raw_script)
        return list(parser)


class ScriptCompiler:
    @staticmethod
    def compile(tokens: list[ScriptToken]) -> bytes:
        writer = BytesWriter()

        for token in tokens:
            match token.opcode:
                case Opcode.OP_PUSHDATA_DIRECT:
                    assert token.data is not None
                    data_len = len(token.data)
                    if not (1 <= data_len <= 75):
                        raise ValueError(
                            f"OP_PUSHDATA_DIRECT payload must be 1-75 bytes, got {data_len}"
                        )
                    writer.write_byte(data_len)
                    writer.write_bytes(token.data)

                case Opcode.OP_PUSHDATA1:
                    assert token.data is not None
                    data_len = len(token.data)
                    if data_len > 0xFF:
                        raise ValueError(
                            f"OP_PUSHDATA1 payload exceeds 255 bytes: {data_len}"
                        )
                    writer.write_byte(Opcode.OP_PUSHDATA1.value)
                    writer.write_byte(data_len)
                    writer.write_bytes(token.data)

                case Opcode.OP_PUSHDATA2:
                    assert token.data is not None
                    data_len = len(token.data)
                    if data_len > 0xFFFF:
                        raise ValueError(
                            f"OP_PUSHDATA2 payload exceeds 65535 bytes: {data_len}"
                        )
                    writer.write_byte(Opcode.OP_PUSHDATA2.value)
                    writer.write_uint16_le(data_len)
                    writer.write_bytes(token.data)

                case Opcode.OP_PUSHDATA4:
                    assert token.data is not None
                    data_len = len(token.data)
                    if data_len > 0xFFFFFFFF:
                        raise ValueError(
                            f"OP_PUSHDATA4 payload exceeds 4294967295 bytes: {data_len}"
                        )
                    writer.write_byte(Opcode.OP_PUSHDATA4.value)
                    writer.write_uint32_le(data_len)
                    writer.write_bytes(token.data)

                case regular_opcode:
                    writer.write_byte(regular_opcode.value)

        return writer.to_bytes()


class ScriptNumDecoder:
    @staticmethod
    def decode(data: bytes, require_minimal: bool, max_size: int) -> int:
        if len(data) > max_size:
            raise ValueError(f"ScriptNum overflow: exceeds {max_size} bytes")

        if len(data) == 0:
            return 0

        if require_minimal and not ScriptNumDecoder.is_minimal(data):
            raise ValueError("Non-minimallly encoded ScriptNum")

        is_negative = bool(data[-1] & 0b1000_0000)

        data_array = bytearray(data)
        data_array[-1] &= 0b0111_1111  # clear sign

        result = 0
        for i, byte in enumerate(data_array):
            result |= byte << (8 * i)

        return -result if is_negative else result

    @staticmethod
    def is_minimal(data: bytes) -> bool:
        if len(data) == 0:
            return True
        elif len(data) == 1:
            return (data[-1] & 0b0111_1111) != 0
        else:
            return not ((data[-1] & 0b0111_1111) == 0 and (data[-2] & 0b1000_0000) == 0)


class ScriptNumEncoder:
    @staticmethod
    def encode(val: int) -> bytes:
        if val == 0:
            return b""

        neg = val < 0
        abs_val = abs(val)
        result = bytearray()

        while abs_val > 0:
            result.append(abs_val & 0b1111_1111)
            abs_val >>= 8

        if result[-1] & 0b1000_0000:
            result.append(0b1000_0000 if neg else 0b0000_0000)
        elif neg:
            result[-1] |= 0b1000_0000

        return bytes(result)

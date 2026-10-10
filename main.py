import hashlib
import random
import socket
import sys
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from typing import ClassVar, NamedTuple, Protocol, Self, TypedDict, override

from btclib.ecc import dsa, ssa


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
        value = self._raw[self._pc]
        self._pc += 1
        return value

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

    def write_byte(self, value: int) -> None:
        if not (0 <= value <= 0xFF):
            raise ValueError(f"Byte value out of range (0~255): {value}")
        self._buf.append(value)

    def write_bytes(self, data: bytes) -> None:
        self._buf.extend(data)

    def write_uint16_le(self, value: int) -> None:
        if not (0 <= value <= 0xFFFF):
            raise ValueError(f"Uint16 out of range (0~65535): {value}")
        self._buf.extend(value.to_bytes(2, byteorder="little"))

    def write_uint32_le(self, value: int) -> None:
        if not (0 <= value <= 0xFFFFFFFF):
            raise ValueError(f"Uint32 out of range (0~4294967295): {value}")
        self._buf.extend(value.to_bytes(4, byteorder="little"))

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


# Check here https://github.com/bitcoin/bitcoin/blob/master/src/script/script_error.h
class ScriptError(IntEnum):
    SCRIPT_ERR_OK = 0
    SCRIPT_ERR_UNKNOWN_ERROR = 1
    SCRIPT_ERR_EVAL_FALSE = 2
    SCRIPT_ERR_OP_RETURN = 3
    SCRIPT_ERR_SCRIPTNUM = 4
    SCRIPT_ERR_SCRIPT_SIZE = 5
    SCRIPT_ERR_PUSH_SIZE = 6
    SCRIPT_ERR_OP_COUNT = 7
    SCRIPT_ERR_STACK_SIZE = 8
    SCRIPT_ERR_SIG_COUNT = 9
    SCRIPT_ERR_PUBKEY_COUNT = 10
    SCRIPT_ERR_VERIFY = 11
    SCRIPT_ERR_EQUALVERIFY = 12
    SCRIPT_ERR_CHECKMULTISIGVERIFY = 13
    SCRIPT_ERR_CHECKSIGVERIFY = 14
    SCRIPT_ERR_NUMEQUALVERIFY = 15
    SCRIPT_ERR_BAD_OPCODE = 16
    SCRIPT_ERR_DISABLED_OPCODE = 17
    SCRIPT_ERR_INVALID_STACK_OPERATION = 18
    SCRIPT_ERR_INVALID_ALTSTACK_OPERATION = 19
    SCRIPT_ERR_UNBALANCED_CONDITIONAL = 20
    SCRIPT_ERR_NEGATIVE_LOCKTIME = 21
    SCRIPT_ERR_UNSATISFIED_LOCKTIME = 22
    SCRIPT_ERR_SIG_HASHTYPE = 23
    SCRIPT_ERR_SIG_DER = 24
    SCRIPT_ERR_MINIMALDATA = 25
    SCRIPT_ERR_SIG_PUSHONLY = 26
    SCRIPT_ERR_SIG_HIGH_S = 27
    SCRIPT_ERR_SIG_NULLDUMMY = 28
    SCRIPT_ERR_PUBKEYTYPE = 29
    SCRIPT_ERR_CLEANSTACK = 30
    SCRIPT_ERR_MINIMALIF = 31
    SCRIPT_ERR_SIG_NULLFAIL = 32
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS = 33
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 34
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = 35
    SCRIPT_ERR_DISCOURAGE_OP_SUCCESS = 36
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE = 37
    SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH = 38
    SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY = 39
    SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH = 40
    SCRIPT_ERR_WITNESS_MALLEATED = 41
    SCRIPT_ERR_WITNESS_MALLEATED_P2SH = 42
    SCRIPT_ERR_WITNESS_UNEXPECTED = 43
    SCRIPT_ERR_WITNESS_PUBKEYTYPE = 44
    SCRIPT_ERR_SCHNORR_SIG_SIZE = 45
    SCRIPT_ERR_SCHNORR_SIG_HASHTYPE = 46
    SCRIPT_ERR_SCHNORR_SIG = 47
    SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE = 48
    SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT = 49
    SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG = 50
    SCRIPT_ERR_TAPSCRIPT_MINIMALIF = 51
    SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY = 52
    SCRIPT_ERR_OP_CODESEPARATOR = 53
    SCRIPT_ERR_SIG_FINDANDDELETE = 54
    SCRIPT_ERR_ERROR_COUNT = 55


class ScriptToken(NamedTuple):
    offset: int
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
            return ScriptToken(offset, Opcode.OP_PUSHDATA_DIRECT, data)

        elif byte == Opcode.OP_PUSHDATA1:
            data_len = reader.read_byte()
            data = reader.read_bytes(data_len)
            return ScriptToken(offset, Opcode.OP_PUSHDATA1, data)

        elif byte == Opcode.OP_PUSHDATA2:
            data_len = reader.read_uint16_le()
            data = reader.read_bytes(data_len)
            return ScriptToken(offset, Opcode.OP_PUSHDATA2, data)

        elif byte == Opcode.OP_PUSHDATA4:
            data_len = reader.read_uint32_le()
            data = reader.read_bytes(data_len)
            return ScriptToken(offset, Opcode.OP_PUSHDATA4, data)

        else:
            try:
                opcode = Opcode(byte)
                return ScriptToken(offset, opcode)
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
    def encode(value: int) -> bytes:
        if value == 0:
            return b""

        neg = value < 0
        abs_value = abs(value)
        result = bytearray()

        while abs_value > 0:
            result.append(abs_value & 0b1111_1111)
            abs_value >>= 8

        if result[-1] & 0b1000_0000:
            result.append(0b1000_0000 if neg else 0b0000_0000)
        elif neg:
            result[-1] |= 0b1000_0000

        return bytes(result)


class ScriptStack:
    _stack: list[bytes]

    def __init__(self, initial: list[bytes] | None = None) -> None:
        self._stack = list(initial) if initial else []

    def __len__(self) -> int:
        return len(self._stack)

    def __bool__(self) -> bool:
        return bool(self._stack)

    def __iter__(self) -> Iterator[bytes]:
        return iter(self._stack)

    @override
    def __repr__(self) -> str:
        return f"ScriptStack({self._stack!r})"

    def push(self, data: bytes | bytearray) -> None:
        self._stack.append(bytes(data))

    def pop(self) -> bytes:
        if not self._stack:
            raise ValueError("Stack underflow: cannot pop from empty stack")
        return self._stack.pop()

    def pop_n(self, n: int) -> list[bytes]:
        if n < 0:
            raise ValueError(f"Cannot pop negative count: {n}")
        if n == 0:
            return []
        if n > len(self._stack):
            raise ValueError(
                f"Stack underflow: required {n} items, but only {len(self._stack)} available"
            )
        items = self._stack[-n:]
        del self._stack[-n:]
        return items

    def peek(self, depth: int = 0) -> bytes:
        # 0 -> len - 1
        # 1 -> len - 2
        # 2 -> len - 3
        # n -> len - (n + 1)
        if depth < 0 or depth >= len(self._stack):
            raise ValueError(f"Stack index out of bounds: depth {depth}")
        index = len(self._stack) - depth - 1
        return self._stack[index]

    def remove_at(self, depth: int) -> bytes:
        if depth < 0 or depth >= len(self._stack):
            raise ValueError(f"Stack roll index out of bounds: depth {depth}")
        index = len(self._stack) - depth - 1
        return self._stack.pop(index)

    def insert_at(self, depth: int, data: bytes) -> None:
        # insert at empty stack is ok. depth can be len(self._stack)
        if depth < 0 or depth > len(self._stack):
            raise ValueError(f"Stack insert index out of bounds: depth {depth}")
        index = len(self._stack) - depth
        return self._stack.insert(index, data)

    def clone(self) -> Self:
        return self.__class__(self._stack)

    def peek_bool(self, depth: int = 0) -> bool:
        raw = self.peek(depth)
        for i, b in enumerate(raw):
            if b != 0:
                return not (i == len(raw) - 1 and b == 0b1000_0000)
        return False

    def pop_bool(self) -> bool:
        raw = self.pop()
        for i, b in enumerate(raw):
            if b != 0:
                return not (i == len(raw) - 1 and b == 0b1000_0000)
        return False

    def push_bool(self, value: bool) -> None:
        self.push(b"\x01" if value else b"")

    def peek_num(self, require_minimal: bool, max_size: int, depth: int = 0) -> int:
        return ScriptNumDecoder.decode(
            self.peek(depth), require_minimal=require_minimal, max_size=max_size
        )

    def pop_num(self, require_minimal: bool, max_size: int) -> int:
        return ScriptNumDecoder.decode(
            self.pop(), require_minimal=require_minimal, max_size=max_size
        )

    def push_num(self, value: int) -> None:
        self.push(ScriptNumEncoder.encode(value))


class ScriptCrypto:
    @staticmethod
    def sha1(data: bytes) -> bytes:
        return hashlib.sha1(data).digest()

    @staticmethod
    def sha256(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    @staticmethod
    def hash256(data: bytes) -> bytes:
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    @staticmethod
    def ripemd160(data: bytes) -> bytes:
        return hashlib.new("ripemd160", data).digest()

    @staticmethod
    def hash160(data: bytes) -> bytes:
        return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()

    @staticmethod
    def verify_ecdsa(msg_hash: bytes, pubkey_bytes: bytes, sig_der: bytes) -> bool:
        if not sig_der or not pubkey_bytes:
            return False
        try:
            return bool(dsa.verify(msg_hash, pubkey_bytes, sig_der))
        except Exception:  # noqa: BLE001
            return False

    @staticmethod
    def verify_schnorr(msg_hash: bytes, pubkey_bytes: bytes, sig_bytes: bytes) -> bool:
        if len(sig_bytes) != 64 or len(pubkey_bytes) != 32:
            return False
        try:
            return bool(ssa.verify(msg_hash, pubkey_bytes, sig_bytes))
        except Exception:  # noqa: BLE001
            return False


class ScriptExecutionError(Exception):
    error: ScriptError

    def __init__(self, error: ScriptError, message: str = ""):
        super().__init__(message or error.name)
        self.error = error


# Check here https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.h
class ScriptFlags(IntFlag):
    SCRIPT_VERIFY_NONE = 0
    SCRIPT_VERIFY_P2SH = 1 << 0
    SCRIPT_VERIFY_STRICTENC = 1 << 1
    SCRIPT_VERIFY_DERSIG = 1 << 2
    SCRIPT_VERIFY_LOW_S = 1 << 3
    SCRIPT_VERIFY_NULLDUMMY = 1 << 4
    SCRIPT_VERIFY_SIGPUSHONLY = 1 << 5
    SCRIPT_VERIFY_MINIMALDATA = 1 << 6
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = 1 << 7
    SCRIPT_VERIFY_CLEANSTACK = 1 << 8
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = 1 << 9
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = 1 << 10
    SCRIPT_VERIFY_WITNESS = 1 << 11
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 1 << 12
    SCRIPT_VERIFY_MINIMALIF = 1 << 13
    SCRIPT_VERIFY_NULLFAIL = 1 << 14
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = 1 << 15
    SCRIPT_VERIFY_CONST_SCRIPTCODE = 1 << 16
    SCRIPT_VERIFY_TAPROOT = 1 << 17
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = 1 << 18
    SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS = 1 << 19
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE = 1 << 20


class ScriptFlagsParser:
    _STRING_TO_FLAG: ClassVar[dict[str, ScriptFlags]] = {
        "": ScriptFlags.SCRIPT_VERIFY_NONE,
        "NONE": ScriptFlags.SCRIPT_VERIFY_NONE,
        "P2SH": ScriptFlags.SCRIPT_VERIFY_P2SH,
        "STRICTENC": ScriptFlags.SCRIPT_VERIFY_STRICTENC,
        "DERSIG": ScriptFlags.SCRIPT_VERIFY_DERSIG,
        "LOW_S": ScriptFlags.SCRIPT_VERIFY_LOW_S,
        "NULLDUMMY": ScriptFlags.SCRIPT_VERIFY_NULLDUMMY,
        "SIGPUSHONLY": ScriptFlags.SCRIPT_VERIFY_SIGPUSHONLY,
        "MINIMALDATA": ScriptFlags.SCRIPT_VERIFY_MINIMALDATA,
        "DISCOURAGE_UPGRADABLE_NOPS": ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
        "CLEANSTACK": ScriptFlags.SCRIPT_VERIFY_CLEANSTACK,
        "CHECKLOCKTIMEVERIFY": ScriptFlags.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
        "CHECKSEQUENCEVERIFY": ScriptFlags.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
        "WITNESS": ScriptFlags.SCRIPT_VERIFY_WITNESS,
        "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM": ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
        "MINIMALIF": ScriptFlags.SCRIPT_VERIFY_MINIMALIF,
        "NULLFAIL": ScriptFlags.SCRIPT_VERIFY_NULLFAIL,
        "WITNESS_PUBKEYTYPE": ScriptFlags.SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,
        "CONST_SCRIPTCODE": ScriptFlags.SCRIPT_VERIFY_CONST_SCRIPTCODE,
        "TAPROOT": ScriptFlags.SCRIPT_VERIFY_TAPROOT,
        "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION": ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
        "DISCOURAGE_OP_SUCCESS": ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
        "DISCOURAGE_UPGRADABLE_PUBKEYTYPE": ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
    }

    @classmethod
    def parse(cls, flags_str: str) -> ScriptFlags:
        flags = ScriptFlags.SCRIPT_VERIFY_NONE
        for item in flags_str.split(","):
            name = item.strip()
            if not name:
                continue
            if name not in cls._STRING_TO_FLAG:
                raise ValueError(f"Unknown script verification flag: {name}")
            flags |= cls._STRING_TO_FLAG[name]

        return flags

    @classmethod
    def to_string(cls, flags: ScriptFlags) -> str:
        if flags == ScriptFlags.SCRIPT_VERIFY_NONE:
            return "NONE"

        names = [
            name
            for name, flag_val in cls._STRING_TO_FLAG.items()
            if flag_val != ScriptFlags.SCRIPT_VERIFY_NONE and bool(flags & flag_val)
        ]
        return ",".join(names)


@dataclass(frozen=True)
class ScriptLimits:
    max_script_size: int = 10_000
    max_script_element_size: int = 520
    max_stack_size: int = 1_000
    max_ops_per_script: int = 201
    max_pubkeys_per_multisig: int = 20
    max_script_num_length: int = 4
    max_cltv_csv_num_length: int = 5
    max_tapscript_num_length: int = 8
    validation_weight_offset: int = 50
    validation_weight_per_sigop: int = 50

    @classmethod
    def mainnet(cls) -> Self:
        return cls()

    @classmethod
    def testnet(cls) -> Self:
        return cls()

    @classmethod
    def regtest(cls) -> Self:
        return cls()

    @classmethod
    def unlimited(cls) -> Self:
        max_int = sys.maxsize
        return cls(
            max_script_size=max_int,
            max_script_element_size=max_int,
            max_stack_size=max_int,
            max_ops_per_script=max_int,
            max_pubkeys_per_multisig=max_int,
            max_script_num_length=max_int,
            max_cltv_csv_num_length=max_int,
            max_tapscript_num_length=max_int,
            validation_weight_offset=max_int,
            validation_weight_per_sigop=0,  # no cost
        )


class ScriptSignatureVersion(IntEnum):
    BASE = 0
    WITNESS_V0 = 1
    TAPROOT = 2
    TAPSCRIPT = 3


class SignatureChecker(Protocol):
    def check_sig(self, sig: bytes, pubkey: bytes, ctx: "ScriptContext") -> bool: ...


class DummySignatureChecker:
    def check_sig(self, sig: bytes, pubkey: bytes, ctx: "ScriptContext") -> bool:
        return len(sig) != 0


@dataclass(frozen=True)
class TransactionContext:
    LOCKTIME_THRESHOLD: int = 500_000_000
    SEQUENCE_FINAL: int = 0xFFFF_FFFF

    SEQUENCE_LOCKTIME_DISABLE_FLAG: int = 1 << 31  # 0x80000000
    SEQUENCE_LOCKTIME_TYPE_FLAG: int = 1 << 22  # 0x00400000
    SEQUENCE_LOCKTIME_MASK: int = 0x0000_FFFF  # 0x0000FFFF

    tx_version: int = 2
    tx_locktime: int = 0
    input_sequence: int = 0xFFFF_FFFF

    def check_lock_time(self, lock_time: int) -> bool:
        # BIP65
        is_script_time = lock_time >= self.LOCKTIME_THRESHOLD
        is_tx_time = self.tx_locktime >= self.LOCKTIME_THRESHOLD
        if is_script_time != is_tx_time:
            return False

        if self.input_sequence == self.SEQUENCE_FINAL:
            return False

        return lock_time <= self.tx_locktime

    def check_sequence(self, sequence: int) -> bool:
        # BIP68 BIP112
        if self.tx_version < 2:
            return False

        if sequence & self.SEQUENCE_LOCKTIME_DISABLE_FLAG:
            return False

        if self.input_sequence & self.SEQUENCE_LOCKTIME_DISABLE_FLAG:
            return False

        is_script_time_locked = bool(sequence & self.SEQUENCE_LOCKTIME_TYPE_FLAG)
        is_input_time_locked = bool(
            self.input_sequence & self.SEQUENCE_LOCKTIME_TYPE_FLAG
        )
        if is_script_time_locked != is_input_time_locked:
            return False

        script_val = sequence & self.SEQUENCE_LOCKTIME_MASK
        input_val = self.input_sequence & self.SEQUENCE_LOCKTIME_MASK

        return script_val <= input_val


class ScriptContext:
    @dataclass(frozen=True)
    class Ready:
        pass

    @dataclass(frozen=True)
    class Running:
        pass

    @dataclass(frozen=True)
    class Terminated:
        error: ScriptError = ScriptError.SCRIPT_ERR_OK

    type State = Ready | Running | Terminated

    flags: ScriptFlags
    limits: ScriptLimits
    sig_version: ScriptSignatureVersion

    stack: ScriptStack
    altstack: ScriptStack
    branch_stack: list[bool]
    state: State
    current_token: ScriptToken | None
    codesep_pos: int

    tx_ctx: TransactionContext
    sig_checker: SignatureChecker

    def __init__(
        self,
        flags: ScriptFlags,
        limits: ScriptLimits,
        sig_version: ScriptSignatureVersion,
        tx_ctx: TransactionContext,
        sig_checker: SignatureChecker,
    ) -> None:
        self.flags = flags
        self.limits = limits
        self.sig_version = sig_version
        self.stack = ScriptStack()
        self.altstack = ScriptStack()
        self.branch_stack = []
        self.state = self.Ready()
        self.current_token = None
        self.codesep_pos = 0xFFFFFFFF  # BIP342
        self.tx_ctx = tx_ctx
        self.sig_checker = sig_checker

    def require_stack_min_size(self, min_size: int) -> None:
        if len(self.stack) < min_size:
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION)

    def require_altstack_min_size(self, min_size: int) -> None:
        if len(self.altstack) < min_size:
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_INVALID_ALTSTACK_OPERATION
            )

    def is_branch_active(self) -> bool:
        return all(
            self.branch_stack
        )  # [] => True, [True] => True, [True, ..., True] => True

    def is_parent_branch_active(self) -> bool:
        if len(self.branch_stack) <= 1:
            return True
        else:
            return all(self.branch_stack[:-1])

    def has_flag(self, flag: ScriptFlags) -> bool:
        return bool(self.flags & flag)


@dataclass(frozen=True)
class BaseOp(ABC):
    opcode: Opcode
    disabled: bool = False
    is_branch_control: bool = False

    @abstractmethod
    def execute(self, ctx: ScriptContext) -> None:
        pass


@dataclass(frozen=True)
class OP_PUSHDATA_DIRECT(BaseOp):
    opcode: Opcode = Opcode.OP_PUSHDATA_DIRECT

    @override
    def execute(self, ctx: ScriptContext) -> None:
        assert ctx.current_token is not None and ctx.current_token.data is not None
        data = ctx.current_token.data
        ctx.stack.push(data)


@dataclass(frozen=True)
class OP_PUSHDATA1(BaseOp):
    opcode: Opcode = Opcode.OP_PUSHDATA1

    @override
    def execute(self, ctx: ScriptContext) -> None:
        assert ctx.current_token is not None and ctx.current_token.data is not None
        data = ctx.current_token.data
        ctx.stack.push(data)


@dataclass(frozen=True)
class OP_PUSHDATA2(BaseOp):
    opcode: Opcode = Opcode.OP_PUSHDATA2

    @override
    def execute(self, ctx: ScriptContext) -> None:
        assert ctx.current_token is not None and ctx.current_token.data is not None
        data = ctx.current_token.data
        ctx.stack.push(data)


@dataclass(frozen=True)
class OP_PUSHDATA4(BaseOp):
    opcode: Opcode = Opcode.OP_PUSHDATA4

    @override
    def execute(self, ctx: ScriptContext) -> None:
        assert ctx.current_token is not None and ctx.current_token.data is not None
        data = ctx.current_token.data
        ctx.stack.push(data)


@dataclass(frozen=True)
class OP_1NEGATE(BaseOp):
    opcode: Opcode = Opcode.OP_1NEGATE

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(-1)


@dataclass(frozen=True)
class OP_0(BaseOp):  # OP_FALSE
    opcode: Opcode = Opcode.OP_0

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(0)


@dataclass(frozen=True)
class OP_1(BaseOp):  # OP_TRUE
    opcode: Opcode = Opcode.OP_1

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(1)


@dataclass(frozen=True)
class OP_2(BaseOp):
    opcode: Opcode = Opcode.OP_2

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(2)


@dataclass(frozen=True)
class OP_3(BaseOp):
    opcode: Opcode = Opcode.OP_3

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(3)


@dataclass(frozen=True)
class OP_4(BaseOp):
    opcode: Opcode = Opcode.OP_4

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(4)


@dataclass(frozen=True)
class OP_5(BaseOp):
    opcode: Opcode = Opcode.OP_5

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(5)


@dataclass(frozen=True)
class OP_6(BaseOp):
    opcode: Opcode = Opcode.OP_6

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(6)


@dataclass(frozen=True)
class OP_7(BaseOp):
    opcode: Opcode = Opcode.OP_7

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(7)


@dataclass(frozen=True)
class OP_8(BaseOp):
    opcode: Opcode = Opcode.OP_8

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(8)


@dataclass(frozen=True)
class OP_9(BaseOp):
    opcode: Opcode = Opcode.OP_9

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(9)


@dataclass(frozen=True)
class OP_10(BaseOp):
    opcode: Opcode = Opcode.OP_10

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(10)


@dataclass(frozen=True)
class OP_11(BaseOp):
    opcode: Opcode = Opcode.OP_11

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(11)


@dataclass(frozen=True)
class OP_12(BaseOp):
    opcode: Opcode = Opcode.OP_12

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(12)


@dataclass(frozen=True)
class OP_13(BaseOp):
    opcode: Opcode = Opcode.OP_13

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(13)


@dataclass(frozen=True)
class OP_14(BaseOp):
    opcode: Opcode = Opcode.OP_14

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(14)


@dataclass(frozen=True)
class OP_15(BaseOp):
    opcode: Opcode = Opcode.OP_15

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(15)


@dataclass(frozen=True)
class OP_16(BaseOp):
    opcode: Opcode = Opcode.OP_16

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(16)


@dataclass(frozen=True)
class OP_NOP(BaseOp):
    opcode: Opcode = Opcode.OP_NOP

    @override
    def execute(self, ctx: ScriptContext) -> None:
        pass


@dataclass(frozen=True)
class OP_IF(BaseOp):
    opcode: Opcode = Opcode.OP_IF
    is_branch_control: bool = True

    @override
    def execute(self, ctx: ScriptContext) -> None:
        if ctx.is_branch_active():
            ctx.require_stack_min_size(1)
            condition = ctx.stack.pop_bool()
            ctx.branch_stack.append(condition)
        else:
            ctx.branch_stack.append(False)


@dataclass(frozen=True)
class OP_NOTIF(BaseOp):
    opcode: Opcode = Opcode.OP_NOTIF
    is_branch_control: bool = True

    @override
    def execute(self, ctx: ScriptContext) -> None:
        if ctx.is_branch_active():
            ctx.require_stack_min_size(1)
            condition = not ctx.stack.pop_bool()
            ctx.branch_stack.append(condition)
        else:
            ctx.branch_stack.append(False)


@dataclass(frozen=True)
class OP_ELSE(BaseOp):
    opcode: Opcode = Opcode.OP_ELSE
    is_branch_control: bool = True

    @override
    def execute(self, ctx: ScriptContext) -> None:
        if not ctx.branch_stack:
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL,
                "OP_ELSE without matching OP_IF",
            )

        if ctx.is_parent_branch_active():
            ctx.branch_stack[-1] = not ctx.branch_stack[-1]
        else:
            ctx.branch_stack[-1] = False


@dataclass(frozen=True)
class OP_ENDIF(BaseOp):
    opcode: Opcode = Opcode.OP_ENDIF
    is_branch_control: bool = True

    @override
    def execute(self, ctx: ScriptContext) -> None:
        if not ctx.branch_stack:
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL,
                "OP_ENDIF without matching OP_IF",
            )
        _ = ctx.branch_stack.pop()


@dataclass(frozen=True)
class OP_VERIFY(BaseOp):
    opcode: Opcode = Opcode.OP_VERIFY

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        value = ctx.stack.pop_bool()
        if not value:
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_VERIFY,
                "OP_VERIFY failed: top stack item evaluated to false",
            )


@dataclass(frozen=True)
class OP_RETURN(BaseOp):
    opcode: Opcode = Opcode.OP_RETURN

    @override
    def execute(self, ctx: ScriptContext) -> None:
        raise ScriptExecutionError(
            ScriptError.SCRIPT_ERR_OP_RETURN,
            "Encountered OP_RETURN",
        )


@dataclass(frozen=True)
class OP_TOALTSTACK(BaseOp):
    opcode: Opcode = Opcode.OP_TOALTSTACK

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        ctx.altstack.push(ctx.stack.pop())


@dataclass(frozen=True)
class OP_FROMALTSTACK(BaseOp):
    opcode: Opcode = Opcode.OP_FROMALTSTACK

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_altstack_min_size(1)
        ctx.stack.push(ctx.altstack.pop())


@dataclass(frozen=True)
class OP_IFDUP(BaseOp):
    opcode: Opcode = Opcode.OP_IFDUP

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        if ctx.stack.peek_bool():
            ctx.stack.push(ctx.stack.peek())


@dataclass(frozen=True)
class OP_DEPTH(BaseOp):
    opcode: Opcode = Opcode.OP_DEPTH

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(len(ctx.stack))


@dataclass(frozen=True)
class OP_DROP(BaseOp):
    opcode: Opcode = Opcode.OP_DROP

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        _ = ctx.stack.pop()


@dataclass(frozen=True)
class OP_DUP(BaseOp):
    opcode: Opcode = Opcode.OP_DUP

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        ctx.stack.push(ctx.stack.peek())


@dataclass(frozen=True)
class OP_NIP(BaseOp):
    opcode: Opcode = Opcode.OP_NIP

    @override
    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b] => [..., b]
        ctx.require_stack_min_size(2)
        _ = ctx.stack.remove_at(1)


@dataclass(frozen=True)
class OP_OVER(BaseOp):
    opcode: Opcode = Opcode.OP_OVER

    @override
    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b] => [..., a, b, a]
        ctx.require_stack_min_size(2)
        ctx.stack.push(ctx.stack.peek(1))


@dataclass(frozen=True)
class OP_PICK(BaseOp):
    opcode: Opcode = Opcode.OP_PICK
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        # [..., item(depth=n), ...] => [..., item(depth=n), ..., item]
        ctx.require_stack_min_size(1)
        n = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        if n < 0 or n >= len(ctx.stack):
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION)
        ctx.stack.push(ctx.stack.peek(n))


@dataclass(frozen=True)
class OP_ROLL(BaseOp):
    opcode: Opcode = Opcode.OP_ROLL
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        # [..., item(depth=n), ...] => [..., (removed), ..., item]
        ctx.require_stack_min_size(1)
        n = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        if n < 0 or n >= len(ctx.stack):
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION)
        ctx.stack.push(ctx.stack.remove_at(n))


@dataclass(frozen=True)
class OP_ROT(BaseOp):
    opcode: Opcode = Opcode.OP_ROT

    @override
    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b, c] => [..., b, c, a]
        ctx.require_stack_min_size(3)
        ctx.stack.push(ctx.stack.remove_at(2))


@dataclass(frozen=True)
class OP_SWAP(BaseOp):
    opcode: Opcode = Opcode.OP_SWAP

    @override
    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b] => [..., b, a]
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop()
        a = ctx.stack.pop()
        ctx.stack.push(b)
        ctx.stack.push(a)


@dataclass(frozen=True)
class OP_TUCK(BaseOp):
    opcode: Opcode = Opcode.OP_TUCK

    @override
    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b] => [..., b, a, b]
        ctx.require_stack_min_size(2)
        top = ctx.stack.peek(0)
        ctx.stack.insert_at(2, top)


@dataclass(frozen=True)
class OP_2DROP(BaseOp):
    opcode: Opcode = Opcode.OP_2DROP

    @override
    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b] => [...]
        ctx.require_stack_min_size(2)
        _ = ctx.stack.pop()
        _ = ctx.stack.pop()


@dataclass(frozen=True)
class OP_2DUP(BaseOp):
    opcode: Opcode = Opcode.OP_2DUP

    @override
    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b] => [..., a, b, a, b]
        ctx.require_stack_min_size(2)
        a = ctx.stack.peek(1)
        b = ctx.stack.peek(0)
        ctx.stack.push(a)
        ctx.stack.push(b)


@dataclass(frozen=True)
class OP_3DUP(BaseOp):
    opcode: Opcode = Opcode.OP_3DUP

    @override
    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b, c] => [..., a, b, c, a, b, c]
        ctx.require_stack_min_size(3)
        a = ctx.stack.peek(2)
        b = ctx.stack.peek(1)
        c = ctx.stack.peek(0)
        ctx.stack.push(a)
        ctx.stack.push(b)
        ctx.stack.push(c)


@dataclass(frozen=True)
class OP_2OVER(BaseOp):
    opcode: Opcode = Opcode.OP_2OVER

    @override
    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b, c, d] => [..., a, b, c, d, a, b]
        ctx.require_stack_min_size(4)
        a = ctx.stack.peek(3)
        b = ctx.stack.peek(2)
        ctx.stack.push(a)
        ctx.stack.push(b)


@dataclass(frozen=True)
class OP_2ROT(BaseOp):
    opcode: Opcode = Opcode.OP_2ROT

    @override
    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b, c, d, e, f] => [..., c, d, e, f, a, b]
        ctx.require_stack_min_size(6)
        a = ctx.stack.remove_at(5)
        b = ctx.stack.remove_at(4)
        ctx.stack.push(a)
        ctx.stack.push(b)


@dataclass(frozen=True)
class OP_2SWAP(BaseOp):
    opcode: Opcode = Opcode.OP_2SWAP

    @override
    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b, c, d] => [..., c, d, a, b]
        ctx.require_stack_min_size(4)
        a = ctx.stack.remove_at(3)
        b = ctx.stack.remove_at(2)
        ctx.stack.push(a)
        ctx.stack.push(b)


@dataclass(frozen=True)
class OP_CAT(BaseOp):
    opcode: Opcode = Opcode.OP_CAT

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop()
        a = ctx.stack.pop()
        ctx.stack.push(a + b)


@dataclass(frozen=True)
class OP_SUBSTR(BaseOp):
    opcode: Opcode = Opcode.OP_SUBSTR
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(3)
        size = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        begin = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        if begin < 0 or size < 0:
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR)
        data = ctx.stack.pop()
        ctx.stack.push(data[begin : begin + size])


@dataclass(frozen=True)
class OP_LEFT(BaseOp):
    opcode: Opcode = Opcode.OP_LEFT
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        size = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        if size < 0:
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR)
        data = ctx.stack.pop()
        ctx.stack.push(data[:size])


@dataclass(frozen=True)
class OP_RIGHT(BaseOp):
    opcode: Opcode = Opcode.OP_RIGHT
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        size = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        if size < 0:
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR)
        data = ctx.stack.pop()
        ctx.stack.push(data[-size:] if size else b"")


@dataclass(frozen=True)
class OP_SIZE(BaseOp):
    opcode: Opcode = Opcode.OP_SIZE

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        ctx.stack.push_num(len(ctx.stack.peek()))


@dataclass(frozen=True)
class OP_INVERT(BaseOp):
    opcode: Opcode = Opcode.OP_INVERT

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        data = ctx.stack.pop()
        ctx.stack.push(bytes(~b & 0xFF for b in data))


@dataclass(frozen=True)
class OP_AND(BaseOp):
    opcode: Opcode = Opcode.OP_AND

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop()
        a = ctx.stack.pop()
        if len(a) != len(b):
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                "Bitwise operands must have equal lengths",
            )
        ctx.stack.push(bytes(x & y for x, y in zip(a, b)))


@dataclass(frozen=True)
class OP_OR(BaseOp):
    opcode: Opcode = Opcode.OP_OR

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop()
        a = ctx.stack.pop()
        if len(a) != len(b):
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                "Bitwise operands must have equal lengths",
            )
        ctx.stack.push(bytes(x | y for x, y in zip(a, b)))


@dataclass(frozen=True)
class OP_XOR(BaseOp):
    opcode: Opcode = Opcode.OP_XOR

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop()
        a = ctx.stack.pop()
        if len(a) != len(b):
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                "Bitwise operands must have equal lengths",
            )
        ctx.stack.push(bytes(x ^ y for x, y in zip(a, b)))


@dataclass(frozen=True)
class OP_EQUAL(BaseOp):
    opcode: Opcode = Opcode.OP_EQUAL

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop()
        a = ctx.stack.pop()
        ctx.stack.push_bool(a == b)


@dataclass(frozen=True)
class OP_EQUALVERIFY(BaseOp):
    opcode: Opcode = Opcode.OP_EQUALVERIFY

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop()
        a = ctx.stack.pop()
        if a != b:
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_EQUALVERIFY)


@dataclass(frozen=True)
class OP_1ADD(BaseOp):
    opcode: Opcode = Opcode.OP_1ADD
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_num(a + 1)


@dataclass(frozen=True)
class OP_1SUB(BaseOp):
    opcode: Opcode = Opcode.OP_1SUB
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_num(a - 1)


@dataclass(frozen=True)
class OP_2MUL(BaseOp):
    opcode: Opcode = Opcode.OP_2MUL
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_num(a * 2)


@dataclass(frozen=True)
class OP_2DIV(BaseOp):
    opcode: Opcode = Opcode.OP_2DIV
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_num(int(a / 2))


@dataclass(frozen=True)
class OP_NEGATE(BaseOp):
    opcode: Opcode = Opcode.OP_NEGATE
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_num(-a)


@dataclass(frozen=True)
class OP_ABS(BaseOp):
    opcode: Opcode = Opcode.OP_ABS
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_num(abs(a))


@dataclass(frozen=True)
class OP_NOT(BaseOp):
    opcode: Opcode = Opcode.OP_NOT
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_bool(a == 0)


@dataclass(frozen=True)
class OP_0NOTEQUAL(BaseOp):
    opcode: Opcode = Opcode.OP_0NOTEQUAL
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_bool(a != 0)


@dataclass(frozen=True)
class OP_ADD(BaseOp):
    opcode: Opcode = Opcode.OP_ADD
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_num(a + b)


@dataclass(frozen=True)
class OP_SUB(BaseOp):
    opcode: Opcode = Opcode.OP_SUB
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_num(a - b)


@dataclass(frozen=True)
class OP_MUL(BaseOp):
    opcode: Opcode = Opcode.OP_MUL
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_num(a * b)


@dataclass(frozen=True)
class OP_DIV(BaseOp):
    opcode: Opcode = Opcode.OP_DIV
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        if b == 0:
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Division by zero"
            )
        ctx.stack.push_num(int(a / b))


@dataclass(frozen=True)
class OP_MOD(BaseOp):
    opcode: Opcode = Opcode.OP_MOD
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        if b == 0:
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Modulo by zero"
            )
        rem = a - int(a / b) * b
        ctx.stack.push_num(rem)


@dataclass(frozen=True)
class OP_LSHIFT(BaseOp):
    opcode: Opcode = Opcode.OP_LSHIFT
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        shift = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        value = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        if shift < 0:
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                "Shift amount must not be negative",
            )
        ctx.stack.push_num(value << shift)


@dataclass(frozen=True)
class OP_RSHIFT(BaseOp):
    opcode: Opcode = Opcode.OP_RSHIFT
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        shift = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        value = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        if shift < 0:
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                "Shift amount must not be negative",
            )
        sign = -1 if value < 0 else 1
        result = (abs(value) >> shift) * sign
        ctx.stack.push_num(result)


@dataclass(frozen=True)
class OP_BOOLAND(BaseOp):
    opcode: Opcode = Opcode.OP_BOOLAND
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_bool(a != 0 and b != 0)


@dataclass(frozen=True)
class OP_BOOLOR(BaseOp):
    opcode: Opcode = Opcode.OP_BOOLOR
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_bool(a != 0 or b != 0)


@dataclass(frozen=True)
class OP_NUMEQUAL(BaseOp):
    opcode: Opcode = Opcode.OP_NUMEQUAL
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_bool(a == b)


@dataclass(frozen=True)
class OP_NUMEQUALVERIFY(BaseOp):
    opcode: Opcode = Opcode.OP_NUMEQUALVERIFY
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        if a != b:
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_NUMEQUALVERIFY)


@dataclass(frozen=True)
class OP_NUMNOTEQUAL(BaseOp):
    opcode: Opcode = Opcode.OP_NUMNOTEQUAL
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_bool(a != b)


@dataclass(frozen=True)
class OP_LESSTHAN(BaseOp):
    opcode: Opcode = Opcode.OP_LESSTHAN
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_bool(a < b)


@dataclass(frozen=True)
class OP_GREATERTHAN(BaseOp):
    opcode: Opcode = Opcode.OP_GREATERTHAN
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_bool(a > b)


@dataclass(frozen=True)
class OP_LESSTHANOREQUAL(BaseOp):
    opcode: Opcode = Opcode.OP_LESSTHANOREQUAL
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_bool(a <= b)


@dataclass(frozen=True)
class OP_GREATERTHANOREQUAL(BaseOp):
    opcode: Opcode = Opcode.OP_GREATERTHANOREQUAL
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_bool(a >= b)


@dataclass(frozen=True)
class OP_MIN(BaseOp):
    opcode: Opcode = Opcode.OP_MIN
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_num(min(a, b))


@dataclass(frozen=True)
class OP_MAX(BaseOp):
    opcode: Opcode = Opcode.OP_MAX
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        a = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_num(max(a, b))


@dataclass(frozen=True)
class OP_WITHIN(BaseOp):
    opcode: Opcode = Opcode.OP_WITHIN
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(3)
        max_value = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        min_value = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        x = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        ctx.stack.push_bool(min_value <= x < max_value)


@dataclass(frozen=True)
class OP_RIPEMD160(BaseOp):
    opcode: Opcode = Opcode.OP_RIPEMD160

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        ctx.stack.push(ScriptCrypto.ripemd160(ctx.stack.pop()))


@dataclass(frozen=True)
class OP_SHA1(BaseOp):
    opcode: Opcode = Opcode.OP_SHA1

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        ctx.stack.push(ScriptCrypto.sha1(ctx.stack.pop()))


@dataclass(frozen=True)
class OP_SHA256(BaseOp):
    opcode: Opcode = Opcode.OP_SHA256

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        ctx.stack.push(ScriptCrypto.sha256(ctx.stack.pop()))


@dataclass(frozen=True)
class OP_HASH160(BaseOp):
    opcode: Opcode = Opcode.OP_HASH160

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        ctx.stack.push(ScriptCrypto.hash160(ctx.stack.pop()))


@dataclass(frozen=True)
class OP_HASH256(BaseOp):
    opcode: Opcode = Opcode.OP_HASH256

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        ctx.stack.push(ScriptCrypto.hash256(ctx.stack.pop()))


@dataclass(frozen=True)
class OP_CODESEPARATOR(BaseOp):
    opcode: Opcode = Opcode.OP_CODESEPARATOR

    @override
    def execute(self, ctx: ScriptContext) -> None:
        assert ctx.current_token is not None
        ctx.codesep_pos = ctx.current_token.offset


@dataclass(frozen=True)
class OP_CHECKSIG(BaseOp):
    opcode: Opcode = Opcode.OP_CHECKSIG

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        pubkey = ctx.stack.pop()
        sig = ctx.stack.pop()

        if len(sig) == 0:
            ctx.stack.push_bool(False)
            return

        success = ctx.sig_checker.check_sig(sig=sig, pubkey=pubkey, ctx=ctx)

        if not success:  # BIP146
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_SIG_NULLFAIL,
                "Signature must be zero-length if verification fails",
            )

        ctx.stack.push_bool(True)


@dataclass(frozen=True)
class OP_CHECKSIGVERIFY(BaseOp):
    opcode: Opcode = Opcode.OP_CHECKSIGVERIFY

    @override
    def execute(self, ctx: ScriptContext) -> None:
        OP_CHECKSIG().execute(ctx)
        OP_VERIFY().execute(ctx)


@dataclass(frozen=True)
class OP_CHECKMULTISIG(BaseOp):
    opcode: Opcode = Opcode.OP_CHECKMULTISIG
    require_minimal: bool = False
    max_size: int = 1024  # 4 (BIP62)
    bug_off_by_one: bool = False

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        pubkeys_len = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        if pubkeys_len < 0 or pubkeys_len > ctx.limits.max_pubkeys_per_multisig:
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_PUBKEY_COUNT)
        ctx.require_stack_min_size(pubkeys_len)
        pubkeys = ctx.stack.pop_n(pubkeys_len)

        ctx.require_stack_min_size(1)
        signatures_len = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        if signatures_len < 0 or signatures_len > pubkeys_len:
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_SIG_COUNT)
        ctx.require_stack_min_size(signatures_len)
        signatures = ctx.stack.pop_n(signatures_len)

        if self.bug_off_by_one:
            ctx.require_stack_min_size(1)
            dummy = ctx.stack.pop()
            if len(dummy) != 0:  # BIP147
                raise ScriptExecutionError(ScriptError.SCRIPT_ERR_SIG_NULLDUMMY)

        sig_idx = 0
        pk_idx = 0
        success = True

        while sig_idx < signatures_len:
            if (pubkeys_len - pk_idx) < (signatures_len - sig_idx):
                success = False
                break

            sig = signatures[sig_idx]
            pubkey = pubkeys[pk_idx]

            if len(sig) > 0 and ctx.sig_checker.check_sig(sig, pubkey, ctx):
                sig_idx += 1

            pk_idx += 1

        if sig_idx < signatures_len:
            success = False

        if not success:
            for sig in signatures:
                if len(sig) != 0:
                    raise ScriptExecutionError(
                        ScriptError.SCRIPT_ERR_SIG_NULLFAIL,
                        "Signatures must be zero-length if verification fails",
                    )
            ctx.stack.push_bool(False)
        else:
            ctx.stack.push_bool(True)


@dataclass(frozen=True)
class OP_CHECKMULTISIGVERIFY(BaseOp):
    opcode: Opcode = Opcode.OP_CHECKMULTISIGVERIFY
    require_minimal: bool = False
    max_size: int = 1024
    bug_off_by_one: bool = False

    @override
    def execute(self, ctx: ScriptContext) -> None:
        OP_CHECKMULTISIG(
            require_minimal=self.require_minimal,
            max_size=self.max_size,
            bug_off_by_one=self.bug_off_by_one,
        ).execute(ctx)
        OP_VERIFY().execute(ctx)


@dataclass(frozen=True)
class OP_CHECKSIGADD(BaseOp):
    opcode: Opcode = Opcode.OP_CHECKSIGADD
    require_minimal: bool = False
    max_size: int = 1024

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(3)
        pubkey = ctx.stack.pop()
        n = ctx.stack.pop_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )
        sig = ctx.stack.pop()

        if len(pubkey) == 0:
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY,
                "OP_CHECKSIGADD encountered an empty public key",
            )

        if len(sig) == 0:
            ctx.stack.push_num(n)
        else:
            success = ctx.sig_checker.check_sig(sig=sig, pubkey=pubkey, ctx=ctx)
            if not success:
                raise ScriptExecutionError(
                    ScriptError.SCRIPT_ERR_SIG_NULLFAIL,
                    "OP_CHECKSIGADD: non-empty signature failed verification",
                )
            ctx.stack.push_num(n + 1)


@dataclass(frozen=True)
class OP_CHECKLOCKTIMEVERIFY(BaseOp):  # OP_NOP2
    opcode: Opcode = Opcode.OP_CHECKLOCKTIMEVERIFY
    require_minimal: bool = False
    max_size: int = 1024  # 5 (BIP65)

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        lock_time = ctx.stack.peek_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )

        if lock_time < 0:
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_NEGATIVE_LOCKTIME)

        if not ctx.tx_ctx.check_lock_time(lock_time):
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME,
                "Locktime condition not satisfied by current transaction",
            )


@dataclass(frozen=True)
class OP_CHECKSEQUENCEVERIFY(BaseOp):  # OP_NOP3
    opcode: Opcode = Opcode.OP_CHECKSEQUENCEVERIFY
    require_minimal: bool = False
    max_size: int = 1024  # 5 (BIP112)

    @override
    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)

        sequence = ctx.stack.peek_num(
            require_minimal=self.require_minimal, max_size=self.max_size
        )

        if sequence < 0:
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_NEGATIVE_LOCKTIME)

        if not ctx.tx_ctx.check_sequence(sequence):
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME,
                "Sequence locktime condition not satisfied by current transaction",
            )


@dataclass(frozen=True)
class OP_RESERVED(BaseOp):
    opcode: Opcode = Opcode.OP_RESERVED

    @override
    def execute(self, ctx: ScriptContext) -> None:
        raise ScriptExecutionError(
            ScriptError.SCRIPT_ERR_BAD_OPCODE,
            "Encountered reserved/illegal opcode: OP_RESERVED",
        )


@dataclass(frozen=True)
class OP_VER(BaseOp):
    opcode: Opcode = Opcode.OP_VER

    @override
    def execute(self, ctx: ScriptContext) -> None:
        raise ScriptExecutionError(
            ScriptError.SCRIPT_ERR_BAD_OPCODE,
            "Encountered reserved/illegal opcode: OP_VER",
        )


@dataclass(frozen=True)
class OP_VERIF(BaseOp):
    opcode: Opcode = Opcode.OP_VERIF

    @override
    def execute(self, ctx: ScriptContext) -> None:
        raise ScriptExecutionError(
            ScriptError.SCRIPT_ERR_BAD_OPCODE,
            "Encountered reserved/illegal opcode: OP_VERIF",
        )


@dataclass(frozen=True)
class OP_VERNOTIF(BaseOp):
    opcode: Opcode = Opcode.OP_VERNOTIF

    @override
    def execute(self, ctx: ScriptContext) -> None:
        raise ScriptExecutionError(
            ScriptError.SCRIPT_ERR_BAD_OPCODE,
            "Encountered reserved/illegal opcode: OP_VERNOTIF",
        )


@dataclass(frozen=True)
class OP_RESERVED1(BaseOp):
    opcode: Opcode = Opcode.OP_RESERVED1

    @override
    def execute(self, ctx: ScriptContext) -> None:
        raise ScriptExecutionError(
            ScriptError.SCRIPT_ERR_BAD_OPCODE,
            "Encountered reserved/illegal opcode: OP_RESERVED1",
        )


@dataclass(frozen=True)
class OP_RESERVED2(BaseOp):
    opcode: Opcode = Opcode.OP_RESERVED2

    @override
    def execute(self, ctx: ScriptContext) -> None:
        raise ScriptExecutionError(
            ScriptError.SCRIPT_ERR_BAD_OPCODE,
            "Encountered reserved/illegal opcode: OP_RESERVED2",
        )


@dataclass(frozen=True)
class OP_NOP1(BaseOp):
    opcode: Opcode = Opcode.OP_NOP1

    @override
    def execute(self, ctx: ScriptContext) -> None:
        pass


@dataclass(frozen=True)
class OP_NOP4(BaseOp):
    opcode: Opcode = Opcode.OP_NOP4

    @override
    def execute(self, ctx: ScriptContext) -> None:
        pass


@dataclass(frozen=True)
class OP_NOP5(BaseOp):
    opcode: Opcode = Opcode.OP_NOP5

    @override
    def execute(self, ctx: ScriptContext) -> None:
        pass


@dataclass(frozen=True)
class OP_NOP6(BaseOp):
    opcode: Opcode = Opcode.OP_NOP6

    @override
    def execute(self, ctx: ScriptContext) -> None:
        pass


@dataclass(frozen=True)
class OP_NOP7(BaseOp):
    opcode: Opcode = Opcode.OP_NOP7

    @override
    def execute(self, ctx: ScriptContext) -> None:
        pass


@dataclass(frozen=True)
class OP_NOP8(BaseOp):
    opcode: Opcode = Opcode.OP_NOP8

    @override
    def execute(self, ctx: ScriptContext) -> None:
        pass


@dataclass(frozen=True)
class OP_NOP9(BaseOp):
    opcode: Opcode = Opcode.OP_NOP9

    @override
    def execute(self, ctx: ScriptContext) -> None:
        pass


@dataclass(frozen=True)
class OP_NOP10(BaseOp):
    opcode: Opcode = Opcode.OP_NOP10

    @override
    def execute(self, ctx: ScriptContext) -> None:
        pass


@dataclass(frozen=True)
class OP_INVALIDOPCODE(BaseOp):
    opcode: Opcode = Opcode.OP_INVALIDOPCODE

    @override
    def execute(self, ctx: ScriptContext) -> None:
        raise ScriptExecutionError(
            ScriptError.SCRIPT_ERR_BAD_OPCODE,
            "Encountered OP_INVALIDOPCODE (0xFF)",
        )


class InstructionSet:
    _ops: dict[Opcode, BaseOp]

    def __init__(self) -> None:
        self._ops = {}

    def register(self, op: BaseOp) -> None:
        self._ops[op.opcode] = op

    def get(self, opcode: Opcode) -> BaseOp | None:
        return self._ops.get(opcode)

    @classmethod
    def ideal(cls) -> Self:
        self = cls()
        self.register(OP_PUSHDATA_DIRECT())
        self.register(OP_PUSHDATA1())
        self.register(OP_PUSHDATA2())
        self.register(OP_PUSHDATA4())
        self.register(OP_1NEGATE())
        self.register(OP_0())
        self.register(OP_1())
        self.register(OP_2())
        self.register(OP_3())
        self.register(OP_4())
        self.register(OP_5())
        self.register(OP_6())
        self.register(OP_7())
        self.register(OP_8())
        self.register(OP_9())
        self.register(OP_10())
        self.register(OP_11())
        self.register(OP_12())
        self.register(OP_13())
        self.register(OP_14())
        self.register(OP_15())
        self.register(OP_16())
        self.register(OP_NOP())
        self.register(OP_IF())
        self.register(OP_NOTIF())
        self.register(OP_ELSE())
        self.register(OP_ENDIF())
        self.register(OP_VERIFY())
        self.register(OP_RETURN())
        self.register(OP_TOALTSTACK())
        self.register(OP_FROMALTSTACK())
        self.register(OP_IFDUP())
        self.register(OP_DEPTH())
        self.register(OP_DROP())
        self.register(OP_DUP())
        self.register(OP_NIP())
        self.register(OP_OVER())
        self.register(OP_PICK())
        self.register(OP_ROLL())
        self.register(OP_ROT())
        self.register(OP_SWAP())
        self.register(OP_TUCK())
        self.register(OP_2DROP())
        self.register(OP_2DUP())
        self.register(OP_3DUP())
        self.register(OP_2OVER())
        self.register(OP_2ROT())
        self.register(OP_2SWAP())
        self.register(OP_CAT())
        self.register(OP_SUBSTR())
        self.register(OP_LEFT())
        self.register(OP_RIGHT())
        self.register(OP_SIZE())
        self.register(OP_INVERT())
        self.register(OP_AND())
        self.register(OP_OR())
        self.register(OP_XOR())
        self.register(OP_EQUAL())
        self.register(OP_EQUALVERIFY())
        self.register(OP_1ADD())
        self.register(OP_1SUB())
        self.register(OP_2MUL())
        self.register(OP_2DIV())
        self.register(OP_NEGATE())
        self.register(OP_ABS())
        self.register(OP_NOT())
        self.register(OP_0NOTEQUAL())
        self.register(OP_ADD())
        self.register(OP_SUB())
        self.register(OP_MUL())
        self.register(OP_DIV())
        self.register(OP_MOD())
        self.register(OP_LSHIFT())
        self.register(OP_RSHIFT())
        self.register(OP_BOOLAND())
        self.register(OP_BOOLOR())
        self.register(OP_NUMEQUAL())
        self.register(OP_NUMEQUALVERIFY())
        self.register(OP_NUMNOTEQUAL())
        self.register(OP_LESSTHAN())
        self.register(OP_GREATERTHAN())
        self.register(OP_LESSTHANOREQUAL())
        self.register(OP_GREATERTHANOREQUAL())
        self.register(OP_MIN())
        self.register(OP_MAX())
        self.register(OP_WITHIN())
        self.register(OP_RIPEMD160())
        self.register(OP_SHA1())
        self.register(OP_SHA256())
        self.register(OP_HASH160())
        self.register(OP_HASH256())
        self.register(OP_CODESEPARATOR())
        self.register(OP_CHECKSIG())
        self.register(OP_CHECKSIGVERIFY())
        self.register(OP_CHECKMULTISIG())
        self.register(OP_CHECKMULTISIGVERIFY())
        self.register(OP_CHECKSIGADD())
        self.register(OP_CHECKLOCKTIMEVERIFY())
        self.register(OP_CHECKSEQUENCEVERIFY())
        self.register(OP_RESERVED())
        self.register(OP_VER())
        self.register(OP_VERIF())
        self.register(OP_VERNOTIF())
        self.register(OP_RESERVED1())
        self.register(OP_RESERVED2())
        self.register(OP_NOP1())
        self.register(OP_NOP4())
        self.register(OP_NOP5())
        self.register(OP_NOP6())
        self.register(OP_NOP7())
        self.register(OP_NOP8())
        self.register(OP_NOP9())
        self.register(OP_NOP10())
        self.register(OP_INVALIDOPCODE())
        return self

    @classmethod
    def standard_latest(cls) -> Self:
        self = cls()
        self.register(OP_PUSHDATA_DIRECT())
        self.register(OP_PUSHDATA1())
        self.register(OP_PUSHDATA2())
        self.register(OP_PUSHDATA4())
        self.register(OP_1NEGATE())
        self.register(OP_0())
        self.register(OP_1())
        self.register(OP_2())
        self.register(OP_3())
        self.register(OP_4())
        self.register(OP_5())
        self.register(OP_6())
        self.register(OP_7())
        self.register(OP_8())
        self.register(OP_9())
        self.register(OP_10())
        self.register(OP_11())
        self.register(OP_12())
        self.register(OP_13())
        self.register(OP_14())
        self.register(OP_15())
        self.register(OP_16())
        self.register(OP_NOP())
        self.register(OP_IF())
        self.register(OP_NOTIF())
        self.register(OP_ELSE())
        self.register(OP_ENDIF())
        self.register(OP_VERIFY())
        self.register(OP_RETURN())
        self.register(OP_TOALTSTACK())
        self.register(OP_FROMALTSTACK())
        self.register(OP_IFDUP())
        self.register(OP_DEPTH())
        self.register(OP_DROP())
        self.register(OP_DUP())
        self.register(OP_NIP())
        self.register(OP_OVER())
        self.register(OP_PICK(require_minimal=True, max_size=4))
        self.register(OP_ROLL(require_minimal=True, max_size=4))
        self.register(OP_ROT())
        self.register(OP_SWAP())
        self.register(OP_TUCK())
        self.register(OP_2DROP())
        self.register(OP_2DUP())
        self.register(OP_3DUP())
        self.register(OP_2OVER())
        self.register(OP_2ROT())
        self.register(OP_2SWAP())
        self.register(OP_CAT(disabled=True))
        self.register(OP_SUBSTR(disabled=True, require_minimal=True, max_size=4))
        self.register(OP_LEFT(disabled=True, require_minimal=True, max_size=4))
        self.register(OP_RIGHT(disabled=True, require_minimal=True, max_size=4))
        self.register(OP_SIZE())
        self.register(OP_INVERT(disabled=True))
        self.register(OP_AND(disabled=True))
        self.register(OP_OR(disabled=True))
        self.register(OP_XOR(disabled=True))
        self.register(OP_EQUAL())
        self.register(OP_EQUALVERIFY())
        self.register(OP_1ADD(require_minimal=True, max_size=4))
        self.register(OP_1SUB(require_minimal=True, max_size=4))
        self.register(OP_2MUL(require_minimal=True, max_size=4))
        self.register(OP_2DIV(require_minimal=True, max_size=4))
        self.register(OP_NEGATE(require_minimal=True, max_size=4))
        self.register(OP_ABS(require_minimal=True, max_size=4))
        self.register(OP_NOT(require_minimal=True, max_size=4))
        self.register(OP_0NOTEQUAL(require_minimal=True, max_size=4))
        self.register(OP_ADD(require_minimal=True, max_size=4))
        self.register(OP_SUB(require_minimal=True, max_size=4))
        self.register(OP_MUL(require_minimal=True, max_size=4))
        self.register(OP_DIV(require_minimal=True, max_size=4))
        self.register(OP_MOD(require_minimal=True, max_size=4))
        self.register(OP_LSHIFT(require_minimal=True, max_size=4))
        self.register(OP_RSHIFT(require_minimal=True, max_size=4))
        self.register(OP_BOOLAND(require_minimal=True, max_size=4))
        self.register(OP_BOOLOR(require_minimal=True, max_size=4))
        self.register(OP_NUMEQUAL(require_minimal=True, max_size=4))
        self.register(OP_NUMEQUALVERIFY(require_minimal=True, max_size=4))
        self.register(OP_NUMNOTEQUAL(require_minimal=True, max_size=4))
        self.register(OP_LESSTHAN(require_minimal=True, max_size=4))
        self.register(OP_GREATERTHAN(require_minimal=True, max_size=4))
        self.register(OP_LESSTHANOREQUAL(require_minimal=True, max_size=4))
        self.register(OP_GREATERTHANOREQUAL(require_minimal=True, max_size=4))
        self.register(OP_MIN(require_minimal=True, max_size=4))
        self.register(OP_MAX(require_minimal=True, max_size=4))
        self.register(OP_WITHIN(require_minimal=True, max_size=4))
        self.register(OP_RIPEMD160())
        self.register(OP_SHA1())
        self.register(OP_SHA256())
        self.register(OP_HASH160())
        self.register(OP_HASH256())
        self.register(OP_CODESEPARATOR())
        self.register(OP_CHECKSIG())
        self.register(OP_CHECKSIGVERIFY())
        self.register(
            OP_CHECKMULTISIG(bug_off_by_one=True, require_minimal=True, max_size=4)
        )
        self.register(
            OP_CHECKMULTISIGVERIFY(
                bug_off_by_one=True, require_minimal=True, max_size=4
            )
        )
        self.register(OP_CHECKSIGADD(require_minimal=True, max_size=4))
        self.register(OP_CHECKLOCKTIMEVERIFY(require_minimal=True, max_size=5))
        self.register(OP_CHECKSEQUENCEVERIFY(require_minimal=True, max_size=5))
        self.register(OP_RESERVED())
        self.register(OP_VER())
        self.register(OP_VERIF())
        self.register(OP_VERNOTIF())
        self.register(OP_RESERVED1())
        self.register(OP_RESERVED2())
        self.register(OP_NOP1())
        self.register(OP_NOP4())
        self.register(OP_NOP5())
        self.register(OP_NOP6())
        self.register(OP_NOP7())
        self.register(OP_NOP8())
        self.register(OP_NOP9())
        self.register(OP_NOP10())
        self.register(OP_INVALIDOPCODE())
        return self


class ScriptInterpreter:
    ctx: ScriptContext
    instruction_set: InstructionSet

    def __init__(
        self,
        limits: ScriptLimits,
        sig_version: ScriptSignatureVersion,
        flags: ScriptFlags,
        tx_ctx: TransactionContext,
    ) -> None:
        self.ctx = ScriptContext(
            limits=limits,
            sig_version=sig_version,
            flags=flags,
            tx_ctx=tx_ctx,
            sig_checker=DummySignatureChecker(),
        )
        self.instruction_set = InstructionSet.ideal()

    def execute(self, script_bytes: bytes) -> ScriptContext.Terminated:
        self.ctx.state = ScriptContext.Running()
        parser = ScriptParser(script_bytes)
        for token in parser:
            self._step(token)
            if isinstance(self.ctx.state, ScriptContext.Terminated):
                return self.ctx.state

        if self.ctx.branch_stack:
            self.ctx.state = ScriptContext.Terminated(
                error=ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL
            )
        else:
            self.ctx.state = ScriptContext.Terminated(error=ScriptError.SCRIPT_ERR_OK)
        return self.ctx.state

    def _step(self, token: ScriptToken) -> None:
        try:
            opcode = token.opcode
            self.ctx.current_token = token

            op = self.instruction_set.get(opcode)
            if op is None:
                raise ScriptExecutionError(
                    ScriptError.SCRIPT_ERR_BAD_OPCODE,
                    f"Unhandled opcode: {opcode.name}",
                )

            if not self.ctx.is_branch_active() and not op.is_branch_control:
                return

            if op.disabled:
                raise ScriptExecutionError(
                    ScriptError.SCRIPT_ERR_DISABLED_OPCODE,
                    f"Opcode {opcode.name} is disabled",
                )

            op.execute(self.ctx)

        except ScriptExecutionError as e:
            self.ctx.state = ScriptContext.Terminated(error=e.error)
        finally:
            self.ctx.current_token = None


class Prevout(TypedDict):
    amount: int
    lock_script: bytes


class TransactionValidator:
    @staticmethod
    def validate_2009_satoshi(
        *, lock_script: bytes, unlock_script: bytes, tx: bytes, input_index: int
    ) -> ScriptError:
        raise NotImplementedError("TODO")

    @staticmethod
    def validate_2012_p2sh_bip16(
        *,
        lock_script: bytes,
        unlock_script: bytes,
        tx: bytes,
        input_index: int,
    ) -> ScriptError:
        raise NotImplementedError("TODO")

    @staticmethod
    def validate_2017_segwit_bip141_bip143(
        *,
        lock_script: bytes,
        unlock_script: bytes,
        witness: list[bytes],
        tx: bytes,
        input_index: int,
        amount: int,
    ) -> ScriptError:
        raise NotImplementedError("TODO")

    @staticmethod
    def validate_2021_taproot_bip340_bip341_bip342(
        *,
        unlock_script: bytes,
        witness: list[bytes],
        tx: bytes,
        input_index: int,
        prevouts: list[Prevout],
    ) -> ScriptError:
        raise NotImplementedError("TODO")


class BlockValidator:
    # TODO
    pass


@dataclass(frozen=True)
class Peer:
    host: str
    port: int


class DNS:
    @staticmethod
    def resolve(host: str) -> list[str]:
        # UNKNOWN LIMIT: the OS may cache the query result
        try:
            infos = socket.getaddrinfo(
                host, 0, family=socket.AF_INET, type=socket.SOCK_STREAM
            )
        except socket.gaierror:
            return []
        unique_ips = {ip for item in infos if isinstance((ip := item[4][0]), str)}
        return list(unique_ips)


# Check here https://github.com/bitcoin/bitcoin/blob/master/src/protocol.h
class ServiceFlags(IntFlag):
    NODE_NONE = 0
    NODE_NETWORK = 1 << 0
    NODE_BLOOM = 1 << 2
    NODE_WITNESS = 1 << 3
    NODE_COMPACT_FILTERS = 1 << 6
    NODE_NETWORK_LIMITED = 1 << 10
    NODE_P2P_V2 = 1 << 11

    def to_dns_prefix(self) -> str:
        if self.value == 0:
            return ""
        return f"x{self.value:x}"


@dataclass(frozen=True)
class DnsSeed:
    host: str

    def query(self, service_flags: ServiceFlags, default_port: int) -> list[Peer]:
        dns_prefix = service_flags.to_dns_prefix()
        target_host = f"{dns_prefix}.{self.host}" if dns_prefix else self.host
        print(target_host)
        peers = DNS.resolve(target_host)
        return [Peer(host, default_port) for host in peers]


@dataclass(frozen=True)
class Network(ABC):
    @dataclass(frozen=True)
    class Config:
        name: str
        magic: bytes
        default_port: int
        genesis_hash: bytes
        dns_seeds: list[str]

    config: Config

    def dns_seed_list(self) -> list[DnsSeed]:
        return [DnsSeed(host) for host in self.config.dns_seeds]

    def peer_discovery(
        self, service_flags: ServiceFlags = ServiceFlags.NODE_NONE
    ) -> list[Peer]:
        peers: list[Peer] = []
        for seed in self.dns_seed_list():
            peers.extend(
                seed.query(
                    default_port=self.config.default_port, service_flags=service_flags
                )
            )
        unique_peers = list(set(peers))
        random.shuffle(unique_peers)
        return unique_peers


# Check here https://github.com/bitcoin/bitcoin/blob/bfdcd9797cd1a1345bdaf7ee7ef48f94028262da/src/kernel/chainparams.cpp
class Mainnet(Network):
    def __init__(self) -> None:
        super().__init__(
            Network.Config(
                name="mainnet",
                magic=b"\xf9\xbe\xb4\xd9",
                default_port=8333,
                genesis_hash=bytes.fromhex(
                    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
                )[::-1],
                dns_seeds=[
                    "dnsseed.bluematt.me",
                    "seed.bitcoin.jonasschnelli.ch",
                    "seed.btc.petertodd.net",
                    "seed.bitcoin.sprovoost.nl",
                    "dnsseed.emzy.de",
                    "seed.bitcoin.wiz.biz",
                    "seed.mainnet.achownodes.xyz",
                ],
            )
        )


# Check here https://github.com/bitcoin/bitcoin/blob/bfdcd9797cd1a1345bdaf7ee7ef48f94028262da/src/kernel/chainparams.cpp
class Testnet4(Network):
    def __init__(self) -> None:
        super().__init__(
            Network.Config(
                name="testnet4",
                magic=b"\x1c\x16\x3f\x28",
                default_port=48333,
                genesis_hash=bytes.fromhex(
                    "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"
                )[::-1],
                dns_seeds=[
                    "seed.testnet4.bitcoin.sprovoost.nl",
                    "seed.testnet4.wiz.biz",
                ],
            )
        )


class RegTest(Network):
    def __init__(self) -> None:
        super().__init__(
            Network.Config(
                name="regtest",
                magic=b"\xfa\xbf\xb5\xda",
                default_port=18444,
                genesis_hash=bytes.fromhex(
                    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
                )[::-1],
                dns_seeds=[],
            )
        )

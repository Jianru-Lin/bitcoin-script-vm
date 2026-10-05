import hashlib
import random
import socket
from abc import ABC
from collections.abc import Iterator
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from typing import NamedTuple, Self, TypedDict, override

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

    stack: ScriptStack
    altstack: ScriptStack
    branch_stack: list[bool]
    state: State
    current_token: ScriptToken | None = None

    def __init__(self, stack: ScriptStack | None = None) -> None:
        self.stack = stack if stack is not None else ScriptStack()
        self.altstack = ScriptStack()
        self.branch_stack = []
        self.state = self.Ready()

    def require_stack_min_size(self, min_size: int) -> None:
        if len(self.stack) < min_size:
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION)

    def require_altstack_min_size(self, min_size: int) -> None:
        if len(self.altstack) < min_size:
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_INVALID_ALTSTACK_OPERATION
            )

    def branch_flag(self) -> bool:
        return all(
            self.branch_stack
        )  # [] => True, [True] => True, [True, ..., True] => True


@dataclass(frozen=True)
class OP_PUSHDATA_DIRECT:
    opcode: Opcode = Opcode.OP_PUSHDATA_DIRECT

    def execute(self, ctx: ScriptContext) -> None:
        assert ctx.current_token is not None and ctx.current_token.data is not None
        data = ctx.current_token.data
        ctx.stack.push(data)


@dataclass(frozen=True)
class OP_PUSHDATA1:
    opcode: Opcode = Opcode.OP_PUSHDATA1

    def execute(self, ctx: ScriptContext) -> None:
        assert ctx.current_token is not None and ctx.current_token.data is not None
        data = ctx.current_token.data
        ctx.stack.push(data)


@dataclass(frozen=True)
class OP_PUSHDATA2:
    opcode: Opcode = Opcode.OP_PUSHDATA2

    def execute(self, ctx: ScriptContext) -> None:
        assert ctx.current_token is not None and ctx.current_token.data is not None
        data = ctx.current_token.data
        ctx.stack.push(data)


@dataclass(frozen=True)
class OP_PUSHDATA4:
    opcode: Opcode = Opcode.OP_PUSHDATA4

    def execute(self, ctx: ScriptContext) -> None:
        assert ctx.current_token is not None and ctx.current_token.data is not None
        data = ctx.current_token.data
        ctx.stack.push(data)


@dataclass(frozen=True)
class OP_1NEGATE:
    opcode: Opcode = Opcode.OP_1NEGATE

    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(-1)


@dataclass(frozen=True)
class OP_0:  # OP_FALSE
    opcode: Opcode = Opcode.OP_0

    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(0)


@dataclass(frozen=True)
class OP_1:  # OP_TRUE
    opcode: Opcode = Opcode.OP_1

    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(1)


@dataclass(frozen=True)
class OP_2:
    opcode: Opcode = Opcode.OP_2

    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(2)


@dataclass(frozen=True)
class OP_3:
    opcode: Opcode = Opcode.OP_3

    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(3)


@dataclass(frozen=True)
class OP_4:
    opcode: Opcode = Opcode.OP_4

    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(4)


@dataclass(frozen=True)
class OP_5:
    opcode: Opcode = Opcode.OP_5

    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(5)


@dataclass(frozen=True)
class OP_6:
    opcode: Opcode = Opcode.OP_6

    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(6)


@dataclass(frozen=True)
class OP_7:
    opcode: Opcode = Opcode.OP_7

    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(7)


@dataclass(frozen=True)
class OP_8:
    opcode: Opcode = Opcode.OP_8

    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(8)


@dataclass(frozen=True)
class OP_9:
    opcode: Opcode = Opcode.OP_9

    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(9)


@dataclass(frozen=True)
class OP_10:
    opcode: Opcode = Opcode.OP_10

    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(10)


@dataclass(frozen=True)
class OP_11:
    opcode: Opcode = Opcode.OP_11

    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(11)


@dataclass(frozen=True)
class OP_12:
    opcode: Opcode = Opcode.OP_12

    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(12)


@dataclass(frozen=True)
class OP_13:
    opcode: Opcode = Opcode.OP_13

    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(13)


@dataclass(frozen=True)
class OP_14:
    opcode: Opcode = Opcode.OP_14

    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(14)


@dataclass(frozen=True)
class OP_15:
    opcode: Opcode = Opcode.OP_15

    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(15)


@dataclass(frozen=True)
class OP_16:
    opcode: Opcode = Opcode.OP_16

    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(16)


@dataclass(frozen=True)
class OP_NOP:
    opcode: Opcode = Opcode.OP_NOP

    def execute(self, ctx: ScriptContext) -> None:
        pass


@dataclass(frozen=True)
class OP_IF:
    opcode: Opcode = Opcode.OP_IF

    def execute(self, ctx: ScriptContext) -> None:
        if ctx.branch_flag():
            ctx.require_stack_min_size(1)
            condition = ctx.stack.pop_bool()
            ctx.branch_stack.append(condition)
        else:
            ctx.branch_stack.append(False)


@dataclass(frozen=True)
class OP_NOTIF:
    opcode: Opcode = Opcode.OP_NOTIF

    def execute(self, ctx: ScriptContext) -> None:
        if ctx.branch_flag():
            ctx.require_stack_min_size(1)
            condition = not ctx.stack.pop_bool()
            ctx.branch_stack.append(condition)
        else:
            ctx.branch_stack.append(False)


@dataclass(frozen=True)
class OP_ELSE:
    opcode: Opcode = Opcode.OP_ELSE

    def execute(self, ctx: ScriptContext) -> None:
        if not ctx.branch_stack:
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL,
                "OP_ELSE without matching OP_IF",
            )
        raise NotImplementedError("TODO")


@dataclass(frozen=True)
class OP_ENDIF:
    opcode: Opcode = Opcode.OP_ENDIF

    def execute(self, ctx: ScriptContext) -> None:
        if not ctx.branch_stack:
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL,
                "OP_ENDIF without matching OP_IF",
            )
        _ = ctx.branch_stack.pop()


@dataclass(frozen=True)
class OP_VERIFY:
    opcode: Opcode = Opcode.OP_VERIFY

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        value = ctx.stack.pop_bool()
        if not value:
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_VERIFY,
                "OP_VERIFY failed: top stack item evaluated to false",
            )


@dataclass(frozen=True)
class OP_RETURN:
    opcode: Opcode = Opcode.OP_RETURN

    def execute(self, ctx: ScriptContext) -> None:
        # TODO consider IF branche
        raise ScriptExecutionError(
            ScriptError.SCRIPT_ERR_OP_RETURN,
            "Encountered OP_RETURN",
        )


@dataclass(frozen=True)
class OP_TOALTSTACK:
    opcode: Opcode = Opcode.OP_TOALTSTACK

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        ctx.altstack.push(ctx.stack.pop())


@dataclass(frozen=True)
class OP_FROMALTSTACK:
    opcode: Opcode = Opcode.OP_FROMALTSTACK

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_altstack_min_size(1)
        ctx.stack.push(ctx.altstack.pop())


@dataclass(frozen=True)
class OP_IFDUP:
    opcode: Opcode = Opcode.OP_IFDUP

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        if ctx.stack.peek_bool():
            ctx.stack.push(ctx.stack.peek())


@dataclass(frozen=True)
class OP_DEPTH:
    opcode: Opcode = Opcode.OP_DEPTH

    def execute(self, ctx: ScriptContext) -> None:
        ctx.stack.push_num(len(ctx.stack))


@dataclass(frozen=True)
class OP_DROP:
    opcode: Opcode = Opcode.OP_DROP

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        _ = ctx.stack.pop()


@dataclass(frozen=True)
class OP_DUP:
    opcode: Opcode = Opcode.OP_DUP

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        ctx.stack.push(ctx.stack.peek())


@dataclass(frozen=True)
class OP_NIP:
    opcode: Opcode = Opcode.OP_NIP

    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b] => [..., b]
        ctx.require_stack_min_size(2)
        _ = ctx.stack.remove_at(1)


@dataclass(frozen=True)
class OP_OVER:
    opcode: Opcode = Opcode.OP_OVER

    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b] => [..., a, b, a]
        ctx.require_stack_min_size(2)
        ctx.stack.push(ctx.stack.peek(1))


@dataclass(frozen=True)
class OP_PICK:
    opcode: Opcode = Opcode.OP_PICK

    def execute(self, ctx: ScriptContext) -> None:
        # [..., item(depth=n), ...] => [..., item(depth=n), ..., item]
        ctx.require_stack_min_size(1)
        n = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        if n < 0 or n >= len(ctx.stack):
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION)
        ctx.stack.push(ctx.stack.peek(n))


@dataclass(frozen=True)
class OP_ROLL:
    opcode: Opcode = Opcode.OP_ROLL

    def execute(self, ctx: ScriptContext) -> None:
        # [..., item(depth=n), ...] => [..., (removed), ..., item]
        ctx.require_stack_min_size(1)
        n = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        if n < 0 or n >= len(ctx.stack):
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION)
        ctx.stack.push(ctx.stack.remove_at(n))


@dataclass(frozen=True)
class OP_ROT:
    opcode: Opcode = Opcode.OP_ROT

    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b, c] => [..., b, c, a]
        ctx.require_stack_min_size(3)
        ctx.stack.push(ctx.stack.remove_at(2))


@dataclass(frozen=True)
class OP_SWAP:
    opcode: Opcode = Opcode.OP_SWAP

    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b] => [..., b, a]
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop()
        a = ctx.stack.pop()
        ctx.stack.push(b)
        ctx.stack.push(a)


@dataclass(frozen=True)
class OP_TUCK:
    opcode: Opcode = Opcode.OP_TUCK

    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b] => [..., b, a, b]
        ctx.require_stack_min_size(2)
        top = ctx.stack.peek(0)
        ctx.stack.insert_at(2, top)


@dataclass(frozen=True)
class OP_2DROP:
    opcode: Opcode = Opcode.OP_2DROP

    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b] => [...]
        ctx.require_stack_min_size(2)
        _ = ctx.stack.pop()
        _ = ctx.stack.pop()


@dataclass(frozen=True)
class OP_2DUP:
    opcode: Opcode = Opcode.OP_2DUP

    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b] => [..., a, b, a, b]
        ctx.require_stack_min_size(2)
        a = ctx.stack.peek(1)
        b = ctx.stack.peek(0)
        ctx.stack.push(a)
        ctx.stack.push(b)


@dataclass(frozen=True)
class OP_3DUP:
    opcode: Opcode = Opcode.OP_3DUP

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
class OP_2OVER:
    opcode: Opcode = Opcode.OP_2OVER

    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b, c, d] => [..., a, b, c, d, a, b]
        ctx.require_stack_min_size(4)
        a = ctx.stack.peek(3)
        b = ctx.stack.peek(2)
        ctx.stack.push(a)
        ctx.stack.push(b)


@dataclass(frozen=True)
class OP_2ROT:
    opcode: Opcode = Opcode.OP_2ROT

    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b, c, d, e, f] => [..., c, d, e, f, a, b]
        ctx.require_stack_min_size(6)
        a = ctx.stack.remove_at(5)
        b = ctx.stack.remove_at(4)
        ctx.stack.push(a)
        ctx.stack.push(b)


@dataclass(frozen=True)
class OP_2SWAP:
    opcode: Opcode = Opcode.OP_2SWAP

    def execute(self, ctx: ScriptContext) -> None:
        # [..., a, b, c, d] => [..., c, d, a, b]
        ctx.require_stack_min_size(4)
        a = ctx.stack.remove_at(3)
        b = ctx.stack.remove_at(2)
        ctx.stack.push(a)
        ctx.stack.push(b)


@dataclass(frozen=True)
class OP_CAT:
    opcode: Opcode = Opcode.OP_CAT

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop()
        a = ctx.stack.pop()
        ctx.stack.push(a + b)


@dataclass(frozen=True)
class OP_SUBSTR:
    opcode: Opcode = Opcode.OP_SUBSTR

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(3)
        size = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        begin = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        if begin < 0 or size < 0:
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR)
        data = ctx.stack.pop()
        ctx.stack.push(data[begin : begin + size])


@dataclass(frozen=True)
class OP_LEFT:
    opcode: Opcode = Opcode.OP_LEFT

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        size = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        if size < 0:
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR)
        data = ctx.stack.pop()
        ctx.stack.push(data[:size])


@dataclass(frozen=True)
class OP_RIGHT:
    opcode: Opcode = Opcode.OP_RIGHT

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        size = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        if size < 0:
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR)
        data = ctx.stack.pop()
        ctx.stack.push(data[-size:] if size else b"")


@dataclass(frozen=True)
class OP_SIZE:
    opcode: Opcode = Opcode.OP_SIZE

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        ctx.stack.push_num(len(ctx.stack.peek()))


@dataclass(frozen=True)
class OP_INVERT:
    opcode: Opcode = Opcode.OP_INVERT

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        data = ctx.stack.pop()
        ctx.stack.push(bytes(~b & 0xFF for b in data))


@dataclass(frozen=True)
class OP_AND:
    opcode: Opcode = Opcode.OP_AND

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
class OP_OR:
    opcode: Opcode = Opcode.OP_OR

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
class OP_XOR:
    opcode: Opcode = Opcode.OP_XOR

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
class OP_EQUAL:
    opcode: Opcode = Opcode.OP_EQUAL

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop()
        a = ctx.stack.pop()
        ctx.stack.push_bool(a == b)


@dataclass(frozen=True)
class OP_EQUALVERIFY:
    opcode: Opcode = Opcode.OP_EQUALVERIFY

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop()
        a = ctx.stack.pop()
        if a != b:
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_EQUALVERIFY)


@dataclass(frozen=True)
class OP_1ADD:
    opcode: Opcode = Opcode.OP_1ADD

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_num(a + 1)


@dataclass(frozen=True)
class OP_1SUB:
    opcode: Opcode = Opcode.OP_1SUB

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_num(a - 1)


@dataclass(frozen=True)
class OP_2MUL:
    opcode: Opcode = Opcode.OP_2MUL

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_num(a * 2)


@dataclass(frozen=True)
class OP_2DIV:
    opcode: Opcode = Opcode.OP_2DIV

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_num(int(a / 2))


@dataclass(frozen=True)
class OP_NEGATE:
    opcode: Opcode = Opcode.OP_NEGATE

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_num(-a)


@dataclass(frozen=True)
class OP_ABS:
    opcode: Opcode = Opcode.OP_ABS

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_num(abs(a))


@dataclass(frozen=True)
class OP_NOT:
    opcode: Opcode = Opcode.OP_NOT

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_bool(a == 0)


@dataclass(frozen=True)
class OP_0NOTEQUAL:
    opcode: Opcode = Opcode.OP_0NOTEQUAL

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_bool(a != 0)


@dataclass(frozen=True)
class OP_ADD:
    opcode: Opcode = Opcode.OP_ADD

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_num(a + b)


@dataclass(frozen=True)
class OP_SUB:
    opcode: Opcode = Opcode.OP_SUB

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_num(a - b)


@dataclass(frozen=True)
class OP_MUL:
    opcode: Opcode = Opcode.OP_MUL

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_num(a * b)


@dataclass(frozen=True)
class OP_DIV:
    opcode: Opcode = Opcode.OP_DIV

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        if b == 0:
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Division by zero"
            )
        ctx.stack.push_num(int(a / b))


@dataclass(frozen=True)
class OP_MOD:
    opcode: Opcode = Opcode.OP_MOD

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        if b == 0:
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Modulo by zero"
            )
        rem = a - int(a / b) * b
        ctx.stack.push_num(rem)


@dataclass(frozen=True)
class OP_LSHIFT:
    opcode: Opcode = Opcode.OP_LSHIFT

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        shift = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        value = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        if shift < 0:
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                "Shift amount must not be negative",
            )
        ctx.stack.push_num(value << shift)


@dataclass(frozen=True)
class OP_RSHIFT:
    opcode: Opcode = Opcode.OP_RSHIFT

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        shift = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        value = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        if shift < 0:
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                "Shift amount must not be negative",
            )
        sign = -1 if value < 0 else 1
        result = (abs(value) >> shift) * sign
        ctx.stack.push_num(result)


@dataclass(frozen=True)
class OP_BOOLAND:
    opcode: Opcode = Opcode.OP_BOOLAND

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_bool(a != 0 and b != 0)


@dataclass(frozen=True)
class OP_BOOLOR:
    opcode: Opcode = Opcode.OP_BOOLOR

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_bool(a != 0 or b != 0)


@dataclass(frozen=True)
class OP_NUMEQUAL:
    opcode: Opcode = Opcode.OP_NUMEQUAL

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_bool(a == b)


@dataclass(frozen=True)
class OP_NUMEQUALVERIFY:
    opcode: Opcode = Opcode.OP_NUMEQUALVERIFY

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        if a != b:
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_NUMEQUALVERIFY)


@dataclass(frozen=True)
class OP_NUMNOTEQUAL:
    opcode: Opcode = Opcode.OP_NUMNOTEQUAL

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_bool(a != b)


@dataclass(frozen=True)
class OP_LESSTHAN:
    opcode: Opcode = Opcode.OP_LESSTHAN

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_bool(a < b)


@dataclass(frozen=True)
class OP_GREATERTHAN:
    opcode: Opcode = Opcode.OP_GREATERTHAN

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_bool(a > b)


@dataclass(frozen=True)
class OP_LESSTHANOREQUAL:
    opcode: Opcode = Opcode.OP_LESSTHANOREQUAL

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_bool(a <= b)


@dataclass(frozen=True)
class OP_GREATERTHANOREQUAL:
    opcode: Opcode = Opcode.OP_GREATERTHANOREQUAL

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_bool(a >= b)


@dataclass(frozen=True)
class OP_MIN:
    opcode: Opcode = Opcode.OP_MIN

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_num(min(a, b))


@dataclass(frozen=True)
class OP_MAX:
    opcode: Opcode = Opcode.OP_MAX

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(2)
        b = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        a = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_num(max(a, b))


@dataclass(frozen=True)
class OP_WITHIN:
    opcode: Opcode = Opcode.OP_WITHIN

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(3)
        max_value = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        min_value = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        x = ctx.stack.pop_num(require_minimal=False, max_size=1024)
        ctx.stack.push_bool(min_value <= x < max_value)


@dataclass(frozen=True)
class OP_RIPEMD160:
    opcode: Opcode = Opcode.OP_RIPEMD160

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        ctx.stack.push(ScriptCrypto.ripemd160(ctx.stack.pop()))


@dataclass(frozen=True)
class OP_SHA1:
    opcode: Opcode = Opcode.OP_SHA1

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        ctx.stack.push(ScriptCrypto.sha1(ctx.stack.pop()))


@dataclass(frozen=True)
class OP_SHA256:
    opcode: Opcode = Opcode.OP_SHA256

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        ctx.stack.push(ScriptCrypto.sha256(ctx.stack.pop()))


@dataclass(frozen=True)
class OP_HASH160:
    opcode: Opcode = Opcode.OP_HASH160

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        ctx.stack.push(ScriptCrypto.hash160(ctx.stack.pop()))


@dataclass(frozen=True)
class OP_HASH256:
    opcode: Opcode = Opcode.OP_HASH256

    def execute(self, ctx: ScriptContext) -> None:
        ctx.require_stack_min_size(1)
        ctx.stack.push(ScriptCrypto.hash256(ctx.stack.pop()))


@dataclass(frozen=True)
class OP_CODESEPARATOR:
    opcode: Opcode = Opcode.OP_CODESEPARATOR

    def execute(self, ctx: ScriptContext) -> None:
        raise NotImplementedError("TODO")


@dataclass(frozen=True)
class OP_CHECKSIG:
    opcode: Opcode = Opcode.OP_CHECKSIG

    def execute(self, ctx: ScriptContext) -> None:
        raise NotImplementedError("TODO")


@dataclass(frozen=True)
class OP_CHECKSIGVERIFY:
    opcode: Opcode = Opcode.OP_CHECKSIGVERIFY

    def execute(self, ctx: ScriptContext) -> None:
        raise NotImplementedError("TODO")


@dataclass(frozen=True)
class OP_CHECKMULTISIG:
    opcode: Opcode = Opcode.OP_CHECKMULTISIG

    def execute(self, ctx: ScriptContext) -> None:
        raise NotImplementedError("TODO")


@dataclass(frozen=True)
class OP_CHECKMULTISIGVERIFY:
    opcode: Opcode = Opcode.OP_CHECKMULTISIGVERIFY

    def execute(self, ctx: ScriptContext) -> None:
        raise NotImplementedError("TODO")


@dataclass(frozen=True)
class OP_CHECKSIGADD:
    opcode: Opcode = Opcode.OP_CHECKSIGADD

    def execute(self, ctx: ScriptContext) -> None:
        raise NotImplementedError("TODO")


@dataclass(frozen=True)
class OP_CHECKLOCKTIMEVERIFY:  # OP_NOP2
    opcode: Opcode = Opcode.OP_CHECKLOCKTIMEVERIFY

    def execute(self, ctx: ScriptContext) -> None:
        raise NotImplementedError("TODO")


@dataclass(frozen=True)
class OP_CHECKSEQUENCEVERIFY:  # OP_NOP3
    opcode: Opcode = Opcode.OP_CHECKSEQUENCEVERIFY

    def execute(self, ctx: ScriptContext) -> None:
        raise NotImplementedError("TODO")


@dataclass(frozen=True)
class OP_RESERVED:
    opcode: Opcode = Opcode.OP_RESERVED

    def execute(self, ctx: ScriptContext) -> None:
        raise ScriptExecutionError(
            ScriptError.SCRIPT_ERR_BAD_OPCODE,
            "Encountered reserved/illegal opcode: OP_RESERVED",
        )


@dataclass(frozen=True)
class OP_VER:
    opcode: Opcode = Opcode.OP_VER

    def execute(self, ctx: ScriptContext) -> None:
        raise ScriptExecutionError(
            ScriptError.SCRIPT_ERR_BAD_OPCODE,
            "Encountered reserved/illegal opcode: OP_VER",
        )


@dataclass(frozen=True)
class OP_VERIF:
    opcode: Opcode = Opcode.OP_VERIF

    def execute(self, ctx: ScriptContext) -> None:
        raise ScriptExecutionError(
            ScriptError.SCRIPT_ERR_BAD_OPCODE,
            "Encountered reserved/illegal opcode: OP_VERIF",
        )


@dataclass(frozen=True)
class OP_VERNOTIF:
    opcode: Opcode = Opcode.OP_VERNOTIF

    def execute(self, ctx: ScriptContext) -> None:
        raise ScriptExecutionError(
            ScriptError.SCRIPT_ERR_BAD_OPCODE,
            "Encountered reserved/illegal opcode: OP_VERNOTIF",
        )


@dataclass(frozen=True)
class OP_RESERVED1:
    opcode: Opcode = Opcode.OP_RESERVED1

    def execute(self, ctx: ScriptContext) -> None:
        raise ScriptExecutionError(
            ScriptError.SCRIPT_ERR_BAD_OPCODE,
            "Encountered reserved/illegal opcode: OP_RESERVED1",
        )


@dataclass(frozen=True)
class OP_RESERVED2:
    opcode: Opcode = Opcode.OP_RESERVED2

    def execute(self, ctx: ScriptContext) -> None:
        raise ScriptExecutionError(
            ScriptError.SCRIPT_ERR_BAD_OPCODE,
            "Encountered reserved/illegal opcode: OP_RESERVED2",
        )


@dataclass(frozen=True)
class OP_NOP1:
    opcode: Opcode = Opcode.OP_NOP1

    def execute(self, ctx: ScriptContext) -> None:
        pass


@dataclass(frozen=True)
class OP_NOP4:
    opcode: Opcode = Opcode.OP_NOP4

    def execute(self, ctx: ScriptContext) -> None:
        pass


@dataclass(frozen=True)
class OP_NOP5:
    opcode: Opcode = Opcode.OP_NOP5

    def execute(self, ctx: ScriptContext) -> None:
        pass


@dataclass(frozen=True)
class OP_NOP6:
    opcode: Opcode = Opcode.OP_NOP6

    def execute(self, ctx: ScriptContext) -> None:
        pass


@dataclass(frozen=True)
class OP_NOP7:
    opcode: Opcode = Opcode.OP_NOP7

    def execute(self, ctx: ScriptContext) -> None:
        pass


@dataclass(frozen=True)
class OP_NOP8:
    opcode: Opcode = Opcode.OP_NOP8

    def execute(self, ctx: ScriptContext) -> None:
        pass


@dataclass(frozen=True)
class OP_NOP9:
    opcode: Opcode = Opcode.OP_NOP9

    def execute(self, ctx: ScriptContext) -> None:
        pass


@dataclass(frozen=True)
class OP_NOP10:
    opcode: Opcode = Opcode.OP_NOP10

    def execute(self, ctx: ScriptContext) -> None:
        pass


@dataclass(frozen=True)
class OP_INVALIDOPCODE:
    opcode: Opcode = Opcode.OP_INVALIDOPCODE

    def execute(self, ctx: ScriptContext) -> None:
        raise ScriptExecutionError(
            ScriptError.SCRIPT_ERR_BAD_OPCODE,
            "Encountered OP_INVALIDOPCODE (0xFF)",
        )


class ScriptInterpreter:
    ctx: ScriptContext
    op_pushdata_direct: OP_PUSHDATA_DIRECT = OP_PUSHDATA_DIRECT()
    op_pushdata1: OP_PUSHDATA1 = OP_PUSHDATA1()
    op_pushdata2: OP_PUSHDATA2 = OP_PUSHDATA2()
    op_pushdata4: OP_PUSHDATA4 = OP_PUSHDATA4()
    op_1negate: OP_1NEGATE = OP_1NEGATE()
    op_0: OP_0 = OP_0()
    op_1: OP_1 = OP_1()
    op_2: OP_2 = OP_2()
    op_3: OP_3 = OP_3()
    op_4: OP_4 = OP_4()
    op_5: OP_5 = OP_5()
    op_6: OP_6 = OP_6()
    op_7: OP_7 = OP_7()
    op_8: OP_8 = OP_8()
    op_9: OP_9 = OP_9()
    op_10: OP_10 = OP_10()
    op_11: OP_11 = OP_11()
    op_12: OP_12 = OP_12()
    op_13: OP_13 = OP_13()
    op_14: OP_14 = OP_14()
    op_15: OP_15 = OP_15()
    op_16: OP_16 = OP_16()
    op_nop: OP_NOP = OP_NOP()
    op_if: OP_IF = OP_IF()
    op_notif: OP_NOTIF = OP_NOTIF()
    op_else: OP_ELSE = OP_ELSE()
    op_endif: OP_ENDIF = OP_ENDIF()
    op_verify: OP_VERIFY = OP_VERIFY()
    op_return: OP_RETURN = OP_RETURN()
    op_toaltstack: OP_TOALTSTACK = OP_TOALTSTACK()
    op_fromaltstack: OP_FROMALTSTACK = OP_FROMALTSTACK()
    op_ifdup: OP_IFDUP = OP_IFDUP()
    op_depth: OP_DEPTH = OP_DEPTH()
    op_drop: OP_DROP = OP_DROP()
    op_dup: OP_DUP = OP_DUP()
    op_nip: OP_NIP = OP_NIP()
    op_over: OP_OVER = OP_OVER()
    op_pick: OP_PICK = OP_PICK()
    op_roll: OP_ROLL = OP_ROLL()
    op_rot: OP_ROT = OP_ROT()
    op_swap: OP_SWAP = OP_SWAP()
    op_tuck: OP_TUCK = OP_TUCK()
    op_2drop: OP_2DROP = OP_2DROP()
    op_2dup: OP_2DUP = OP_2DUP()
    op_3dup: OP_3DUP = OP_3DUP()
    op_2over: OP_2OVER = OP_2OVER()
    op_2rot: OP_2ROT = OP_2ROT()
    op_2swap: OP_2SWAP = OP_2SWAP()
    op_cat: OP_CAT = OP_CAT()
    op_substr: OP_SUBSTR = OP_SUBSTR()
    op_left: OP_LEFT = OP_LEFT()
    op_right: OP_RIGHT = OP_RIGHT()
    op_size: OP_SIZE = OP_SIZE()
    op_invert: OP_INVERT = OP_INVERT()
    op_and: OP_AND = OP_AND()
    op_or: OP_OR = OP_OR()
    op_xor: OP_XOR = OP_XOR()
    op_equal: OP_EQUAL = OP_EQUAL()
    op_equalverify: OP_EQUALVERIFY = OP_EQUALVERIFY()
    op_1add: OP_1ADD = OP_1ADD()
    op_1sub: OP_1SUB = OP_1SUB()
    op_2mul: OP_2MUL = OP_2MUL()
    op_2div: OP_2DIV = OP_2DIV()
    op_negate: OP_NEGATE = OP_NEGATE()
    op_abs: OP_ABS = OP_ABS()
    op_not: OP_NOT = OP_NOT()
    op_0notequal: OP_0NOTEQUAL = OP_0NOTEQUAL()
    op_add: OP_ADD = OP_ADD()
    op_sub: OP_SUB = OP_SUB()
    op_mul: OP_MUL = OP_MUL()
    op_div: OP_DIV = OP_DIV()
    op_mod: OP_MOD = OP_MOD()
    op_lshift: OP_LSHIFT = OP_LSHIFT()
    op_rshift: OP_RSHIFT = OP_RSHIFT()
    op_booland: OP_BOOLAND = OP_BOOLAND()
    op_boolor: OP_BOOLOR = OP_BOOLOR()
    op_numequal: OP_NUMEQUAL = OP_NUMEQUAL()
    op_numequalverify: OP_NUMEQUALVERIFY = OP_NUMEQUALVERIFY()
    op_numnotequal: OP_NUMNOTEQUAL = OP_NUMNOTEQUAL()
    op_lessthan: OP_LESSTHAN = OP_LESSTHAN()
    op_greaterthan: OP_GREATERTHAN = OP_GREATERTHAN()
    op_lessthanorequal: OP_LESSTHANOREQUAL = OP_LESSTHANOREQUAL()
    op_greaterthanorequal: OP_GREATERTHANOREQUAL = OP_GREATERTHANOREQUAL()
    op_min: OP_MIN = OP_MIN()
    op_max: OP_MAX = OP_MAX()
    op_within: OP_WITHIN = OP_WITHIN()
    op_ripemd160: OP_RIPEMD160 = OP_RIPEMD160()
    op_sha1: OP_SHA1 = OP_SHA1()
    op_sha256: OP_SHA256 = OP_SHA256()
    op_hash160: OP_HASH160 = OP_HASH160()
    op_hash256: OP_HASH256 = OP_HASH256()
    op_codeseparator: OP_CODESEPARATOR = OP_CODESEPARATOR()
    op_checksig: OP_CHECKSIG = OP_CHECKSIG()
    op_checksigverify: OP_CHECKSIGVERIFY = OP_CHECKSIGVERIFY()
    op_checkmultisig: OP_CHECKMULTISIG = OP_CHECKMULTISIG()
    op_checkmultisigverify: OP_CHECKMULTISIGVERIFY = OP_CHECKMULTISIGVERIFY()
    op_checksigadd: OP_CHECKSIGADD = OP_CHECKSIGADD()
    op_checklocktimeverify: OP_CHECKLOCKTIMEVERIFY = OP_CHECKLOCKTIMEVERIFY()
    op_checksequenceverify: OP_CHECKSEQUENCEVERIFY = OP_CHECKSEQUENCEVERIFY()
    op_reserved: OP_RESERVED = OP_RESERVED()
    op_ver: OP_VER = OP_VER()
    op_verif: OP_VERIF = OP_VERIF()
    op_vernotif: OP_VERNOTIF = OP_VERNOTIF()
    op_reserved1: OP_RESERVED1 = OP_RESERVED1()
    op_reserved2: OP_RESERVED2 = OP_RESERVED2()
    op_nop1: OP_NOP1 = OP_NOP1()
    op_nop4: OP_NOP4 = OP_NOP4()
    op_nop5: OP_NOP5 = OP_NOP5()
    op_nop6: OP_NOP6 = OP_NOP6()
    op_nop7: OP_NOP7 = OP_NOP7()
    op_nop8: OP_NOP8 = OP_NOP8()
    op_nop9: OP_NOP9 = OP_NOP9()
    op_nop10: OP_NOP10 = OP_NOP10()
    op_invalidopcode: OP_INVALIDOPCODE = OP_INVALIDOPCODE()

    def __init__(self, stack: ScriptStack | None = None) -> None:
        self.ctx = ScriptContext(stack)

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

            if not self.ctx.branch_flag() and opcode not in (
                Opcode.OP_IF,
                Opcode.OP_NOTIF,
                Opcode.OP_ELSE,
                Opcode.OP_ENDIF,
            ):
                return

            match opcode:
                case Opcode.OP_PUSHDATA_DIRECT:
                    self.op_pushdata_direct.execute(self.ctx)
                case Opcode.OP_PUSHDATA1:
                    self.op_pushdata1.execute(self.ctx)
                case Opcode.OP_PUSHDATA2:
                    self.op_pushdata2.execute(self.ctx)
                case Opcode.OP_PUSHDATA4:
                    self.op_pushdata4.execute(self.ctx)
                case Opcode.OP_1NEGATE:
                    self.op_1negate.execute(self.ctx)
                case Opcode.OP_0:  # OP_FALSE
                    self.op_0.execute(self.ctx)
                case Opcode.OP_1:  # OP_TRUE
                    self.op_1.execute(self.ctx)
                case Opcode.OP_2:
                    self.op_2.execute(self.ctx)
                case Opcode.OP_3:
                    self.op_3.execute(self.ctx)
                case Opcode.OP_4:
                    self.op_4.execute(self.ctx)
                case Opcode.OP_5:
                    self.op_5.execute(self.ctx)
                case Opcode.OP_6:
                    self.op_6.execute(self.ctx)
                case Opcode.OP_7:
                    self.op_7.execute(self.ctx)
                case Opcode.OP_8:
                    self.op_8.execute(self.ctx)
                case Opcode.OP_9:
                    self.op_9.execute(self.ctx)
                case Opcode.OP_10:
                    self.op_10.execute(self.ctx)
                case Opcode.OP_11:
                    self.op_11.execute(self.ctx)
                case Opcode.OP_12:
                    self.op_12.execute(self.ctx)
                case Opcode.OP_13:
                    self.op_13.execute(self.ctx)
                case Opcode.OP_14:
                    self.op_14.execute(self.ctx)
                case Opcode.OP_15:
                    self.op_15.execute(self.ctx)
                case Opcode.OP_16:
                    self.op_16.execute(self.ctx)
                case Opcode.OP_NOP:
                    self.op_nop.execute(self.ctx)
                case Opcode.OP_IF:
                    self.op_if.execute(self.ctx)
                case Opcode.OP_NOTIF:
                    self.op_notif.execute(self.ctx)
                case Opcode.OP_ELSE:
                    self.op_else.execute(self.ctx)
                case Opcode.OP_ENDIF:
                    self.op_endif.execute(self.ctx)
                case Opcode.OP_VERIFY:
                    self.op_verify.execute(self.ctx)
                case Opcode.OP_RETURN:
                    self.op_return.execute(self.ctx)
                case Opcode.OP_TOALTSTACK:
                    self.op_toaltstack.execute(self.ctx)
                case Opcode.OP_FROMALTSTACK:
                    self.op_fromaltstack.execute(self.ctx)
                case Opcode.OP_IFDUP:
                    self.op_ifdup.execute(self.ctx)
                case Opcode.OP_DEPTH:
                    self.op_depth.execute(self.ctx)
                case Opcode.OP_DROP:
                    self.op_drop.execute(self.ctx)
                case Opcode.OP_DUP:
                    self.op_dup.execute(self.ctx)
                case Opcode.OP_NIP:
                    self.op_nip.execute(self.ctx)
                case Opcode.OP_OVER:
                    self.op_over.execute(self.ctx)
                case Opcode.OP_PICK:
                    self.op_pick.execute(self.ctx)
                case Opcode.OP_ROLL:
                    self.op_roll.execute(self.ctx)
                case Opcode.OP_ROT:
                    self.op_rot.execute(self.ctx)
                case Opcode.OP_SWAP:
                    self.op_swap.execute(self.ctx)
                case Opcode.OP_TUCK:
                    self.op_tuck.execute(self.ctx)
                case Opcode.OP_2DROP:
                    self.op_2drop.execute(self.ctx)
                case Opcode.OP_2DUP:
                    self.op_2dup.execute(self.ctx)
                case Opcode.OP_3DUP:
                    self.op_3dup.execute(self.ctx)
                case Opcode.OP_2OVER:
                    self.op_2over.execute(self.ctx)
                case Opcode.OP_2ROT:
                    self.op_2rot.execute(self.ctx)
                case Opcode.OP_2SWAP:
                    self.op_2swap.execute(self.ctx)
                case Opcode.OP_CAT:
                    self.op_cat.execute(self.ctx)
                case Opcode.OP_SUBSTR:
                    self.op_substr.execute(self.ctx)
                case Opcode.OP_LEFT:
                    self.op_left.execute(self.ctx)
                case Opcode.OP_RIGHT:
                    self.op_right.execute(self.ctx)
                case Opcode.OP_SIZE:
                    self.op_size.execute(self.ctx)
                case Opcode.OP_INVERT:
                    self.op_invert.execute(self.ctx)
                case Opcode.OP_AND:
                    self.op_and.execute(self.ctx)
                case Opcode.OP_OR:
                    self.op_or.execute(self.ctx)
                case Opcode.OP_XOR:
                    self.op_xor.execute(self.ctx)
                case Opcode.OP_EQUAL:
                    self.op_equal.execute(self.ctx)
                case Opcode.OP_EQUALVERIFY:
                    self.op_equalverify.execute(self.ctx)
                case Opcode.OP_1ADD:
                    self.op_1add.execute(self.ctx)
                case Opcode.OP_1SUB:
                    self.op_1sub.execute(self.ctx)
                case Opcode.OP_2MUL:
                    self.op_2mul.execute(self.ctx)
                case Opcode.OP_2DIV:
                    self.op_2div.execute(self.ctx)
                case Opcode.OP_NEGATE:
                    self.op_negate.execute(self.ctx)
                case Opcode.OP_ABS:
                    self.op_abs.execute(self.ctx)
                case Opcode.OP_NOT:
                    self.op_not.execute(self.ctx)
                case Opcode.OP_0NOTEQUAL:
                    self.op_0notequal.execute(self.ctx)
                case Opcode.OP_ADD:
                    self.op_add.execute(self.ctx)
                case Opcode.OP_SUB:
                    self.op_sub.execute(self.ctx)
                case Opcode.OP_MUL:
                    self.op_mul.execute(self.ctx)
                case Opcode.OP_DIV:
                    self.op_div.execute(self.ctx)
                case Opcode.OP_MOD:
                    self.op_mod.execute(self.ctx)
                case Opcode.OP_LSHIFT:
                    self.op_lshift.execute(self.ctx)
                case Opcode.OP_RSHIFT:
                    self.op_rshift.execute(self.ctx)
                case Opcode.OP_BOOLAND:
                    self.op_booland.execute(self.ctx)
                case Opcode.OP_BOOLOR:
                    self.op_boolor.execute(self.ctx)
                case Opcode.OP_NUMEQUAL:
                    self.op_numequal.execute(self.ctx)
                case Opcode.OP_NUMEQUALVERIFY:
                    self.op_numequalverify.execute(self.ctx)
                case Opcode.OP_NUMNOTEQUAL:
                    self.op_numnotequal.execute(self.ctx)
                case Opcode.OP_LESSTHAN:
                    self.op_lessthan.execute(self.ctx)
                case Opcode.OP_GREATERTHAN:
                    self.op_greaterthan.execute(self.ctx)
                case Opcode.OP_LESSTHANOREQUAL:
                    self.op_lessthanorequal.execute(self.ctx)
                case Opcode.OP_GREATERTHANOREQUAL:
                    self.op_greaterthanorequal.execute(self.ctx)
                case Opcode.OP_MIN:
                    self.op_min.execute(self.ctx)
                case Opcode.OP_MAX:
                    self.op_max.execute(self.ctx)
                case Opcode.OP_WITHIN:
                    self.op_within.execute(self.ctx)
                case Opcode.OP_RIPEMD160:
                    self.op_ripemd160.execute(self.ctx)
                case Opcode.OP_SHA1:
                    self.op_sha1.execute(self.ctx)
                case Opcode.OP_SHA256:
                    self.op_sha256.execute(self.ctx)
                case Opcode.OP_HASH160:
                    self.op_hash160.execute(self.ctx)
                case Opcode.OP_HASH256:
                    self.op_hash256.execute(self.ctx)
                case Opcode.OP_CODESEPARATOR:
                    self.op_codeseparator.execute(self.ctx)
                case Opcode.OP_CHECKSIG:
                    self.op_checksig.execute(self.ctx)
                case Opcode.OP_CHECKSIGVERIFY:
                    self.op_checksigverify.execute(self.ctx)
                case Opcode.OP_CHECKMULTISIG:
                    self.op_checkmultisig.execute(self.ctx)
                case Opcode.OP_CHECKMULTISIGVERIFY:
                    self.op_checkmultisigverify.execute(self.ctx)
                case Opcode.OP_CHECKSIGADD:
                    self.op_checksigadd.execute(self.ctx)
                case Opcode.OP_CHECKLOCKTIMEVERIFY:  # OP_NOP2
                    self.op_checklocktimeverify.execute(self.ctx)
                case Opcode.OP_CHECKSEQUENCEVERIFY:  # OP_NOP3
                    self.op_checksequenceverify.execute(self.ctx)
                case Opcode.OP_RESERVED:
                    self.op_reserved.execute(self.ctx)
                case Opcode.OP_VER:
                    self.op_ver.execute(self.ctx)
                case Opcode.OP_VERIF:
                    self.op_verif.execute(self.ctx)
                case Opcode.OP_VERNOTIF:
                    self.op_vernotif.execute(self.ctx)
                case Opcode.OP_RESERVED1:
                    self.op_reserved1.execute(self.ctx)
                case Opcode.OP_RESERVED2:
                    self.op_reserved2.execute(self.ctx)
                case Opcode.OP_NOP1:
                    self.op_nop1.execute(self.ctx)
                case Opcode.OP_NOP4:
                    self.op_nop4.execute(self.ctx)
                case Opcode.OP_NOP5:
                    self.op_nop5.execute(self.ctx)
                case Opcode.OP_NOP6:
                    self.op_nop6.execute(self.ctx)
                case Opcode.OP_NOP7:
                    self.op_nop7.execute(self.ctx)
                case Opcode.OP_NOP8:
                    self.op_nop8.execute(self.ctx)
                case Opcode.OP_NOP9:
                    self.op_nop9.execute(self.ctx)
                case Opcode.OP_NOP10:
                    self.op_nop10.execute(self.ctx)
                case Opcode.OP_INVALIDOPCODE:
                    self.op_invalidopcode.execute(self.ctx)

                case _:
                    raise ScriptExecutionError(
                        ScriptError.SCRIPT_ERR_BAD_OPCODE,
                        f"Unhandled opcode: {opcode.name}",
                    )
        except ScriptExecutionError as e:
            self.ctx.state = ScriptContext.Terminated(error=e.error)


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

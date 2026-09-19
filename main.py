from collections.abc import Iterator
from enum import IntEnum
from typing import NamedTuple, Self, override


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

    def pop_bool(self) -> bool:
        raw = self.pop()
        for i, b in enumerate(raw):
            if b != 0:
                return not (i == len(raw) - 1 and b == 0b1000_0000)
        return False

    def push_bool(self, value: bool) -> None:
        self.push(b"\x01" if value else b"")

    def pop_num(self, require_minimal: bool, max_size: int) -> int:
        return ScriptNumDecoder.decode(
            self.pop(), require_minimal=require_minimal, max_size=max_size
        )

    def push_num(self, value: int) -> None:
        self.push(ScriptNumEncoder.encode(value))


class ScriptExecutionError(Exception):
    error: ScriptError

    def __init__(self, error: ScriptError, message: str = ""):
        super().__init__(message or error.name)
        self.error = error


class ScriptInterpreter:
    stack: ScriptStack
    altstack: ScriptStack
    vf_exec: list[bool]

    def __init__(self, stack: ScriptStack | None = None) -> None:
        self.stack = stack if stack is not None else ScriptStack()
        self.altstack = ScriptStack()
        self.vf_exec = []

    def execute(self, script_bytes: bytes) -> None:
        parser = ScriptParser(script_bytes)
        for token in parser:
            self._step(token)

    def _step(self, token: ScriptToken) -> None:
        opcode = token.opcode
        match opcode:
            case Opcode.OP_PUSHDATA_DIRECT:
                assert token.data is not None
                self.stack.push(token.data)

            case Opcode.OP_PUSHDATA1:
                assert token.data is not None
                self.stack.push(token.data)

            case Opcode.OP_PUSHDATA2:
                assert token.data is not None
                self.stack.push(token.data)

            case Opcode.OP_PUSHDATA4:
                assert token.data is not None
                self.stack.push(token.data)

            case Opcode.OP_1NEGATE:
                self.stack.push_num(-1)

            case Opcode.OP_0:  # OP_FALSE
                self.stack.push(b"")  # self.stack.push_num(0)

            case Opcode.OP_1:  # OP_TRUE
                self.stack.push_num(1)

            case Opcode.OP_2:
                self.stack.push_num(2)

            case Opcode.OP_3:
                self.stack.push_num(3)

            case Opcode.OP_4:
                self.stack.push_num(4)

            case Opcode.OP_5:
                self.stack.push_num(5)

            case Opcode.OP_6:
                self.stack.push_num(6)

            case Opcode.OP_7:
                self.stack.push_num(7)

            case Opcode.OP_8:
                self.stack.push_num(8)

            case Opcode.OP_9:
                self.stack.push_num(9)

            case Opcode.OP_10:
                self.stack.push_num(10)

            case Opcode.OP_11:
                self.stack.push_num(11)

            case Opcode.OP_12:
                self.stack.push_num(12)

            case Opcode.OP_13:
                self.stack.push_num(13)

            case Opcode.OP_14:
                self.stack.push_num(14)

            case Opcode.OP_15:
                self.stack.push_num(15)

            case Opcode.OP_16:
                self.stack.push_num(16)

            case Opcode.OP_NOP:
                pass

            case Opcode.OP_IF:
                raise NotImplementedError("TODO")

            case Opcode.OP_NOTIF:
                raise NotImplementedError("TODO")

            case Opcode.OP_ELSE:
                raise NotImplementedError("TODO")

            case Opcode.OP_ENDIF:
                raise NotImplementedError("TODO")

            case Opcode.OP_VERIFY:
                raise NotImplementedError("TODO")

            case Opcode.OP_RETURN:
                raise NotImplementedError("TODO")

            case Opcode.OP_TOALTSTACK:
                self._require_stack_size(min_size=1)
                self.altstack.push(self.stack.pop())

            case Opcode.OP_FROMALTSTACK:
                self._require_altstack_size(min_size=1)
                self.stack.push(self.altstack.pop())

            case Opcode.OP_IFDUP:
                raise NotImplementedError("TODO")

            case Opcode.OP_DEPTH:
                raise NotImplementedError("TODO")

            case Opcode.OP_DROP:
                raise NotImplementedError("TODO")

            case Opcode.OP_DUP:
                raise NotImplementedError("TODO")

            case Opcode.OP_NIP:
                raise NotImplementedError("TODO")

            case Opcode.OP_OVER:
                raise NotImplementedError("TODO")

            case Opcode.OP_PICK:
                raise NotImplementedError("TODO")

            case Opcode.OP_ROLL:
                raise NotImplementedError("TODO")

            case Opcode.OP_ROT:
                raise NotImplementedError("TODO")

            case Opcode.OP_SWAP:
                raise NotImplementedError("TODO")

            case Opcode.OP_TUCK:
                raise NotImplementedError("TODO")

            case Opcode.OP_2DROP:
                raise NotImplementedError("TODO")

            case Opcode.OP_2DUP:
                raise NotImplementedError("TODO")

            case Opcode.OP_3DUP:
                raise NotImplementedError("TODO")

            case Opcode.OP_2OVER:
                raise NotImplementedError("TODO")

            case Opcode.OP_2ROT:
                raise NotImplementedError("TODO")

            case Opcode.OP_2SWAP:
                raise NotImplementedError("TODO")

            case Opcode.OP_CAT:
                self._require_stack_size(min_size=2)
                b = self.stack.pop()
                a = self.stack.pop()
                self.stack.push(a + b)

            case Opcode.OP_SUBSTR:
                self._require_stack_size(min_size=3)
                size = self.stack.pop_num(require_minimal=False, max_size=1024)
                begin = self.stack.pop_num(require_minimal=False, max_size=1024)
                if begin < 0 or size < 0:
                    raise ScriptExecutionError(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR)
                data = self.stack.pop()
                self.stack.push(data[begin : begin + size])

            case Opcode.OP_LEFT:
                self._require_stack_size(min_size=2)
                size = self.stack.pop_num(require_minimal=False, max_size=1024)
                if size < 0:
                    raise ScriptExecutionError(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR)
                data = self.stack.pop()
                self.stack.push(data[:size])

            case Opcode.OP_RIGHT:
                self._require_stack_size(min_size=2)
                size = self.stack.pop_num(require_minimal=False, max_size=1024)
                if size < 0:
                    raise ScriptExecutionError(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR)
                data = self.stack.pop()
                self.stack.push(data[-size:] if size else b"")

            case Opcode.OP_SIZE:
                self._require_stack_size(min_size=1)
                self.stack.push_num(len(self.stack.peek()))

            case Opcode.OP_INVERT:
                raise NotImplementedError("TODO")

            case Opcode.OP_AND:
                raise NotImplementedError("TODO")

            case Opcode.OP_OR:
                raise NotImplementedError("TODO")

            case Opcode.OP_XOR:
                raise NotImplementedError("TODO")

            case Opcode.OP_EQUAL:
                self._require_stack_size(min_size=2)
                b = self.stack.pop()
                a = self.stack.pop()
                self.stack.push_bool(a == b)

            case Opcode.OP_EQUALVERIFY:
                self._require_stack_size(min_size=2)
                b = self.stack.pop()
                a = self.stack.pop()
                if a != b:
                    raise ScriptExecutionError(ScriptError.SCRIPT_ERR_EQUALVERIFY)

            case Opcode.OP_1ADD:
                self._require_stack_size(min_size=1)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(a + 1)

            case Opcode.OP_1SUB:
                self._require_stack_size(min_size=1)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(a - 1)

            case Opcode.OP_2MUL:
                self._require_stack_size(min_size=1)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(a * 2)

            case Opcode.OP_2DIV:
                self._require_stack_size(min_size=1)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(int(a / 2))

            case Opcode.OP_NEGATE:
                self._require_stack_size(min_size=1)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(-a)

            case Opcode.OP_ABS:
                self._require_stack_size(min_size=1)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(abs(a))

            case Opcode.OP_NOT:
                self._require_stack_size(min_size=1)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(1 if a == 0 else 0)

            case Opcode.OP_0NOTEQUAL:
                self._require_stack_size(min_size=1)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(1 if a != 0 else 0)

            case Opcode.OP_ADD:
                self._require_stack_size(min_size=2)
                b = self.stack.pop_num(require_minimal=False, max_size=1024)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(a + b)

            case Opcode.OP_SUB:
                self._require_stack_size(min_size=2)
                b = self.stack.pop_num(require_minimal=False, max_size=1024)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(a - b)

            case Opcode.OP_MUL:
                self._require_stack_size(min_size=2)
                b = self.stack.pop_num(require_minimal=False, max_size=1024)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(a * b)

            case Opcode.OP_DIV:
                self._require_stack_size(min_size=2)
                b = self.stack.pop_num(require_minimal=False, max_size=1024)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                if b == 0:
                    raise ScriptExecutionError(
                        ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Division by zero"
                    )
                self.stack.push_num(int(a / b))

            case Opcode.OP_MOD:
                self._require_stack_size(min_size=2)
                b = self.stack.pop_num(require_minimal=False, max_size=1024)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                if b == 0:
                    raise ScriptExecutionError(
                        ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Modulo by zero"
                    )
                rem = a - int(a / b) * b
                self.stack.push_num(rem)

            case Opcode.OP_LSHIFT:
                raise NotImplementedError("TODO")

            case Opcode.OP_RSHIFT:
                raise NotImplementedError("TODO")

            case Opcode.OP_BOOLAND:
                raise NotImplementedError("TODO")

            case Opcode.OP_BOOLOR:
                raise NotImplementedError("TODO")

            case Opcode.OP_NUMEQUAL:
                self._require_stack_size(min_size=2)
                b = self.stack.pop_num(require_minimal=False, max_size=1024)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(1 if a == b else 0)

            case Opcode.OP_NUMEQUALVERIFY:
                self._require_stack_size(min_size=2)
                b = self.stack.pop_num(require_minimal=False, max_size=1024)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                if a != b:
                    raise ScriptExecutionError(ScriptError.SCRIPT_ERR_NUMEQUALVERIFY)

            case Opcode.OP_NUMNOTEQUAL:
                self._require_stack_size(min_size=2)
                b = self.stack.pop_num(require_minimal=False, max_size=1024)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(1 if a != b else 0)

            case Opcode.OP_LESSTHAN:
                self._require_stack_size(min_size=2)
                b = self.stack.pop_num(require_minimal=False, max_size=1024)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(1 if a < b else 0)

            case Opcode.OP_GREATERTHAN:
                self._require_stack_size(min_size=2)
                b = self.stack.pop_num(require_minimal=False, max_size=1024)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(1 if a > b else 0)

            case Opcode.OP_LESSTHANOREQUAL:
                self._require_stack_size(min_size=2)
                b = self.stack.pop_num(require_minimal=False, max_size=1024)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(1 if a <= b else 0)

            case Opcode.OP_GREATERTHANOREQUAL:
                self._require_stack_size(min_size=2)
                b = self.stack.pop_num(require_minimal=False, max_size=1024)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(1 if a >= b else 0)

            case Opcode.OP_MIN:
                self._require_stack_size(min_size=2)
                b = self.stack.pop_num(require_minimal=False, max_size=1024)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(min(a, b))

            case Opcode.OP_MAX:
                self._require_stack_size(min_size=2)
                b = self.stack.pop_num(require_minimal=False, max_size=1024)
                a = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(max(a, b))

            case Opcode.OP_WITHIN:
                self._require_stack_size(min_size=3)
                max_value = self.stack.pop_num(require_minimal=False, max_size=1024)
                min_value = self.stack.pop_num(require_minimal=False, max_size=1024)
                x = self.stack.pop_num(require_minimal=False, max_size=1024)
                self.stack.push_num(1 if min_value <= x < max_value else 0)

            case Opcode.OP_RIPEMD160:
                raise NotImplementedError("TODO")

            case Opcode.OP_SHA1:
                raise NotImplementedError("TODO")

            case Opcode.OP_SHA256:
                raise NotImplementedError("TODO")

            case Opcode.OP_HASH160:
                raise NotImplementedError("TODO")

            case Opcode.OP_HASH256:
                raise NotImplementedError("TODO")

            case Opcode.OP_CODESEPARATOR:
                raise NotImplementedError("TODO")

            case Opcode.OP_CHECKSIG:
                raise NotImplementedError("TODO")

            case Opcode.OP_CHECKSIGVERIFY:
                raise NotImplementedError("TODO")

            case Opcode.OP_CHECKMULTISIG:
                raise NotImplementedError("TODO")

            case Opcode.OP_CHECKMULTISIGVERIFY:
                raise NotImplementedError("TODO")

            case Opcode.OP_CHECKSIGADD:
                raise NotImplementedError("TODO")

            case Opcode.OP_CHECKLOCKTIMEVERIFY:  # OP_NOP2
                raise NotImplementedError("TODO")

            case Opcode.OP_CHECKSEQUENCEVERIFY:  # OP_NOP3
                raise NotImplementedError("TODO")

            case Opcode.OP_RESERVED:
                raise ScriptExecutionError(
                    ScriptError.SCRIPT_ERR_BAD_OPCODE,
                    f"Encountered reserved/illegal opcode: {opcode.name}",
                )

            case Opcode.OP_VER:
                raise ScriptExecutionError(
                    ScriptError.SCRIPT_ERR_BAD_OPCODE,
                    f"Encountered reserved/illegal opcode: {opcode.name}",
                )

            case Opcode.OP_VERIF:
                raise ScriptExecutionError(
                    ScriptError.SCRIPT_ERR_BAD_OPCODE,
                    f"Encountered reserved/illegal opcode: {opcode.name}",
                )

            case Opcode.OP_VERNOTIF:
                raise ScriptExecutionError(
                    ScriptError.SCRIPT_ERR_BAD_OPCODE,
                    f"Encountered reserved/illegal opcode: {opcode.name}",
                )

            case Opcode.OP_RESERVED1:
                raise ScriptExecutionError(
                    ScriptError.SCRIPT_ERR_BAD_OPCODE,
                    f"Encountered reserved/illegal opcode: {opcode.name}",
                )

            case Opcode.OP_RESERVED2:
                raise ScriptExecutionError(
                    ScriptError.SCRIPT_ERR_BAD_OPCODE,
                    f"Encountered reserved/illegal opcode: {opcode.name}",
                )

            case Opcode.OP_NOP1:
                pass

            case Opcode.OP_NOP4:
                pass

            case Opcode.OP_NOP5:
                pass

            case Opcode.OP_NOP6:
                pass

            case Opcode.OP_NOP7:
                pass

            case Opcode.OP_NOP8:
                pass

            case Opcode.OP_NOP9:
                pass

            case Opcode.OP_NOP10:
                pass

            case Opcode.OP_INVALIDOPCODE:
                raise NotImplementedError("TODO")

            case _:
                raise ScriptExecutionError(
                    ScriptError.SCRIPT_ERR_BAD_OPCODE,
                    f"Unhandled opcode: {opcode.name}",
                )

    def _require_stack_size(self, *, min_size: int) -> None:
        if len(self.stack) < min_size:
            raise ScriptExecutionError(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION)

    def _require_altstack_size(self, *, min_size: int) -> None:
        if len(self.altstack) < min_size:
            raise ScriptExecutionError(
                ScriptError.SCRIPT_ERR_INVALID_ALTSTACK_OPERATION
            )

import unittest

from main import (
    Opcode,
    ScriptNumDecoder,
    ScriptNumEncoder,
    ScriptParser,
    ScriptStack,
    ScriptToken,
)

parse = ScriptParser.parse


class TestScriptParser(unittest.TestCase):
    def test_empty_script(self):
        self.assertEqual(parse(b""), [])

    def test_single_and_combined_opcodes(self):
        raw = bytes(
            [
                Opcode.OP_DUP,
                Opcode.OP_HASH160,
                Opcode.OP_EQUALVERIFY,
                Opcode.OP_CHECKSIG,
            ]
        )
        expected = [
            ScriptToken(Opcode.OP_DUP),
            ScriptToken(Opcode.OP_HASH160),
            ScriptToken(Opcode.OP_EQUALVERIFY),
            ScriptToken(Opcode.OP_CHECKSIG),
        ]
        self.assertEqual(parse(raw), expected)

    def test_direct_pushdata_direct(self):
        raw_4bytes = b"\x04\xde\xad\xbe\xef"
        self.assertEqual(
            parse(raw_4bytes),
            [ScriptToken(Opcode.OP_PUSHDATA_DIRECT, b"\xde\xad\xbe\xef")],
        )

        # 75 bytes data
        data_75 = b"A" * 75
        raw_75bytes = b"\x4b" + data_75
        self.assertEqual(
            parse(raw_75bytes), [ScriptToken(Opcode.OP_PUSHDATA_DIRECT, data_75)]
        )

    def test_pushdata1(self):
        data_80 = b"B" * 80
        raw = b"\x4c\x50" + data_80
        self.assertEqual(parse(raw), [ScriptToken(Opcode.OP_PUSHDATA1, data_80)])

    # def test_unknown_opcode_raises_error(self):
    #     raw = bytes([0x76, 0xA9, 0xFF, 0x88])
    #     with self.assertRaises(ValueError) as ctx:
    #         _ = parse(raw)

    #     self.assertIn("0xFF", str(ctx.exception))
    #     self.assertIn("offset 2", str(ctx.exception))


class TestScriptNumDecoder(unittest.TestCase):
    def test_decode(self):
        cases = [
            (bytes([]), 0),
            (bytes([0b0000_0001]), 1),
            (bytes([0b1000_0001]), -1),
            (bytes([0b0000_0010]), 2),
            (bytes([0b1000_0010]), -2),
            (bytes([0b1000_0000, 0b0000_0000]), 128),
            (bytes([0b1000_0000, 0b1000_0000]), -128),  # failed here
        ]
        for raw_bytes, expected_val in cases:
            with self.subTest(raw_bytes=raw_bytes, expected_val=expected_val):
                self.assertEqual(
                    ScriptNumDecoder.decode(
                        raw_bytes, require_minimal=True, max_size=4
                    ),
                    expected_val,
                )

    def test_is_minimal(self):
        cases = [
            (bytes([]), True),  # +0 (correct)
            (bytes([0b0000_0000]), False),  # +0 (incorrect)
            (bytes([0b1000_0000]), False),  # -0 (incorrect)
            (bytes([0b0000_0001]), True),  # 1 (correct)
            (bytes([0b0000_0001, 0b0000_0000]), False),  # 1 (incorrect)
            (bytes([0b1000_0001]), True),  # -1 (correct)
            (bytes([0b1000_0001, 0b0000_0000]), True),  # 129 (correct)
            (bytes([0b0111_1111]), True),
        ]
        for raw_bytes, expected_valid in cases:
            with self.subTest(raw_bytes=raw_bytes, expected_valid=expected_valid):
                self.assertIs(ScriptNumDecoder.is_minimal(raw_bytes), expected_valid)


class TestScriptStack(unittest.TestCase):
    def test_len(self):
        self.assertEqual(len(ScriptStack()), 0)
        self.assertEqual(len(ScriptStack([])), 0)
        self.assertEqual(len(ScriptStack([b""])), 1)
        self.assertEqual(len(ScriptStack([b"\x00"])), 1)
        self.assertEqual(len(ScriptStack([b"\x00", b"\x00"])), 2)

    def test_bool(self):
        self.assertEqual(bool(ScriptStack()), False)
        self.assertEqual(bool(ScriptStack([])), False)
        self.assertEqual(bool(ScriptStack([b""])), True)
        self.assertEqual(bool(ScriptStack([b"\x00"])), True)
        self.assertEqual(bool(ScriptStack([b"\x00", b"\x00"])), True)

    def test_repr(self):
        self.assertEqual(repr(ScriptStack()), r"ScriptStack([])")
        self.assertEqual(repr(ScriptStack([])), r"ScriptStack([])")
        self.assertEqual(repr(ScriptStack([b""])), r"ScriptStack([b''])")
        self.assertEqual(repr(ScriptStack([b"\x00"])), r"ScriptStack([b'\x00'])")
        self.assertEqual(
            repr(ScriptStack([b"\x00", b"\x01"])), r"ScriptStack([b'\x00', b'\x01'])"
        )

    def test_push(self):
        stack = ScriptStack()
        self.assertEqual(len(stack), 0)
        stack.push(b"")
        self.assertEqual(len(stack), 1)
        stack.push(b"")
        self.assertEqual(len(stack), 2)

    def test_pop_empty(self):
        stack = ScriptStack()
        with self.assertRaises(ValueError):
            _ = stack.pop()

    def test_push_pop(self):
        stack = ScriptStack()
        self.assertEqual(len(stack), 0)
        stack.push(b"\x01")
        self.assertEqual(len(stack), 1)
        stack.push(b"\x02")
        self.assertEqual(len(stack), 2)
        self.assertEqual(stack.pop(), b"\x02")
        self.assertEqual(len(stack), 1)
        self.assertEqual(stack.pop(), b"\x01")
        self.assertEqual(len(stack), 0)

    def test_peek_empty(self):
        stack = ScriptStack()
        with self.assertRaises(ValueError):
            _ = stack.peek(0)

    def test_push_peek(self):
        stack = ScriptStack()
        self.assertEqual(len(stack), 0)
        stack.push(b"\x01")
        self.assertEqual(len(stack), 1)
        stack.push(b"\x02")
        self.assertEqual(len(stack), 2)
        self.assertEqual(stack.peek(0), b"\x02")
        self.assertEqual(stack.peek(1), b"\x01")


if __name__ == "__main__":
    _ = unittest.main(verbosity=2)

import unittest

from main import Opcode, ScriptParser, ScriptToken

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


if __name__ == "__main__":
    _ = unittest.main(verbosity=2)

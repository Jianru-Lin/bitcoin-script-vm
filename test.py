import unittest

from main import Opcode, Token, parse


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
            Token(Opcode.OP_DUP),
            Token(Opcode.OP_HASH160),
            Token(Opcode.OP_EQUALVERIFY),
            Token(Opcode.OP_CHECKSIG),
        ]
        self.assertEqual(parse(raw), expected)

    def test_direct_pushdata_small(self):
        raw_4bytes = b"\x04\xde\xad\xbe\xef"
        self.assertEqual(
            parse(raw_4bytes), [Token(Opcode.OP_PUSHDATA, b"\xde\xad\xbe\xef")]
        )


if __name__ == "__main__":
    _ = unittest.main(verbosity=2)

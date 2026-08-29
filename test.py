import unittest
from main import Opcode, Token, parse

class TestScriptParser(unittest.TestCase):
    def test_empty_script(self):
        self.assertEqual(parse(b""), [])

if __name__ == "__main__":
    unittest.main()

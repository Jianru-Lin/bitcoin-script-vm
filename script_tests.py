import json
import os
import sys


def parse_script_tests(file_path: str):
    if not os.path.exists(file_path):
        print(f"Error: File not found -> {file_path}")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        try:
            test_cases = json.load(f)
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            return

    case_idx = 0

    for item in test_cases:
        if not isinstance(item, list) or len(item) == 0:
            continue

        # Section header or standalone comment (length == 1)
        if len(item) == 1:
            comment = str(item[0]).strip()
            # Ignore test harness instructions / descriptions
            if "Format is:" in comment or "It is evaluated as if" in comment:
                continue
            print(f"\n{'=' * 20} SECTION: {comment} {'=' * 20}")
            continue

        case_idx += 1
        witness_stack = []
        amount = None

        # Witness test case: first element is a list
        if isinstance(item[0], list):
            wit_info = item[0]
            if len(wit_info) > 0 and isinstance(wit_info[-1], (int, float)):
                amount = wit_info[-1]
                witness_stack = wit_info[:-1]
            else:
                witness_stack = wit_info

            script_sig = item[1]
            script_pubkey = item[2]
            flags = item[3]
            expected = item[4]
            comments = " | ".join(str(c) for c in item[5:]) if len(item) > 5 else ""
        else:
            # Legacy test case without witness
            script_sig = item[0]
            script_pubkey = item[1]
            flags = item[2]
            expected = item[3]
            comments = " | ".join(str(c) for c in item[4:]) if len(item) > 4 else ""

        # Pretty print the parsed test case
        print(f"\n[Test #{case_idx}]")
        if comments:
            print(f"  Comment:       {comments}")
        if amount is not None:
            print(f"  Amount:        {amount:.8f} BTC")
        if witness_stack:
            print(f"  Witness Stack: {witness_stack}")
        print(
            f"  scriptSig:     {repr(script_sig) if script_sig == '' else script_sig}"
        )
        print(f"  scriptPubKey:  {script_pubkey}")
        print(f"  Flags:         {flags if flags else '(NONE)'}")
        print(f"  Expected:      {expected}")
        print("-" * 50)


if __name__ == "__main__":
    parse_script_tests("script_tests.json")

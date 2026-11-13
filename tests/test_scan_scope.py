"""Regression checks for IMAP read-only scan scope and report behavior."""
import ast
from pathlib import Path
import unittest


class ScanScopeTests(unittest.TestCase):
    def test_email_parser_names_not_shadowed_inside_scan(self):
        tree = ast.parse(Path("mailwatch.py").read_text(encoding="utf-8"))
        scan = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "scan")
        shadowed = []
        for node in ast.walk(scan):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    name = alias.asname or alias.name
                    if name in {"BytesParser", "policy"}:
                        shadowed.append((node.lineno, name))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    if name in {"BytesParser", "policy"}:
                        shadowed.append((node.lineno, name))
        self.assertEqual(shadowed, [], "scan() must use module-level BytesParser/policy; local imports produce UnboundLocalError")

    def test_scan_uses_readonly_imap(self):
        tree = ast.parse(Path("mailwatch.py").read_text(encoding="utf-8"))
        scan = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "scan")
        selects = [n for n in ast.walk(scan) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "select"]
        self.assertTrue(selects)
        for select in selects:
            keywords = {k.arg: k.value for k in select.keywords}
            self.assertIsInstance(keywords.get("readonly"), ast.Constant)
            self.assertIs(keywords["readonly"].value, True)


if __name__ == "__main__":
    unittest.main()

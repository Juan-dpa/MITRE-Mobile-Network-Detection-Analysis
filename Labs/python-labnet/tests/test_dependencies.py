from __future__ import annotations

import ast
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LABS = ROOT / "labs"
REQUIREMENT_BY_IMPORT = {
    "Crypto": "pycryptodome",
    "cryptography": "cryptography",
}


def imported_roots(source: Path) -> set[str]:
    roots: set[str] = set()
    for path in source.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(alias.name.partition(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots.add(node.module.partition(".")[0])
    return roots


def local_roots(source: Path) -> set[str]:
    roots = {path.stem for path in source.glob("*.py")}
    roots.update(path.name for path in source.iterdir() if path.is_dir())
    return roots


def declared_modules(launcher: Path) -> set[str]:
    text = launcher.read_text(encoding="utf-8")
    match = re.search(r"^LAB_PYTHON_MODULES=\(([^)]*)\)", text, re.MULTILINE)
    return set(match.group(1).split()) if match else set()


class DependencyDeclarationsTests(unittest.TestCase):
    def test_each_third_party_import_has_a_launcher_preflight(self) -> None:
        stdlib = set(sys.stdlib_module_names) | {"__future__"}
        for lab in sorted(path for path in LABS.iterdir() if path.is_dir()):
            with self.subTest(lab=lab.name):
                source = lab / "source"
                external = imported_roots(source) - stdlib - local_roots(source)
                self.assertEqual(external, declared_modules(lab / "run.sh"))

    def test_each_declared_import_is_covered_by_root_requirements(self) -> None:
        requirements = {
            line.partition(">=")[0].strip().lower()
            for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        declared = set()
        for lab in LABS.iterdir():
            if lab.is_dir():
                declared.update(declared_modules(lab / "run.sh"))

        unknown = declared - REQUIREMENT_BY_IMPORT.keys()
        self.assertFalse(unknown, f"faltan equivalencias import/pip para: {sorted(unknown)}")
        for module in declared:
            with self.subTest(module=module):
                self.assertIn(REQUIREMENT_BY_IMPORT[module], requirements)


if __name__ == "__main__":
    unittest.main()

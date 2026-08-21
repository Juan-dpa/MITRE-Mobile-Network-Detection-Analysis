from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PipelineInventoryTests(unittest.TestCase):
    def test_smoke_all_contains_every_lab_directory(self) -> None:
        expected = {path.name for path in (ROOT / "labs").iterdir() if path.is_dir()}
        smoke = (ROOT / "tools" / "smoke-all.sh").read_text(encoding="utf-8")
        match = re.search(r"^all_labs=\(([^)]*)\)", smoke, re.MULTILINE)
        self.assertIsNotNone(match)
        declared = set(match.group(1).split())
        self.assertEqual(declared, expected)

    def test_central_guide_contains_every_lab_identifier(self) -> None:
        expected = {path.name for path in (ROOT / "labs").iterdir() if path.is_dir()}
        guide = (ROOT.parent / "documentos_normalizados" / "Laboratorios Python.md").read_text(
            encoding="utf-8"
        )
        documented = set(re.findall(r"^\| `([a-z0-9-]+)` \|", guide, re.MULTILINE))
        self.assertEqual(documented, expected)


if __name__ == "__main__":
    unittest.main()

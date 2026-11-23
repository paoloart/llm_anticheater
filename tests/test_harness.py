"""Autotest dell'harness: il mock vulnerabile deve fallire, quello protetto passare."""
import unittest

from harness import adapters, runner


class HarnessSelfTest(unittest.TestCase):
    def setUp(self):
        self.cases = runner.load_cases("*.jsonl")

    def test_naive_mock_is_detected(self):
        res = runner.run(adapters.NaiveMockSUT(), self.cases)
        failed = {r["id"] for r in res if not r["pass"]}
        for cid in ["T1-001", "T2-002", "T4-001", "T5-001", "T6-001", "T7-001", "T11-001", "T13-001", "T4-002"]:
            self.assertIn(cid, failed)

    def test_hardened_mock_passes(self):
        res = runner.run(adapters.HardenedMockSUT(), self.cases)
        failed = [r for r in res if not r["pass"]]
        self.assertEqual(failed, [], failed)

    def test_hardened_survives_mutations(self):
        from harness import mutate
        variants = [m for c in self.cases for m in mutate.mutate_case(c)]
        self.assertGreater(len(variants), 10)
        res = runner.run(adapters.HardenedMockSUT(), variants)
        self.assertEqual([r for r in res if not r["pass"]], [])

    def test_ssh_argv_has_no_secrets(self):
        a = adapters.SSHAdapter("host", "cmd", user="u", port=2222)
        self.assertEqual(a._argv()[:5], ["ssh", "-o", "BatchMode=yes", "-p", "2222"])


if __name__ == "__main__":
    unittest.main()

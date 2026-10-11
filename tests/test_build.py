import ipaddress
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import build  # noqa: E402

SOURCES = {
    "ip": [{"name": "a", "repo": "x/a", "path": "ip.txt"}],
    "ip_exclude": [{"name": "gone", "repo": "x/a", "path": "no_more"}],
    "sni": [{"name": "plain", "repo": "x/b", "path": "list.txt"},
            {"name": "json", "repo": "x/c", "path": "set.json", "format": "sing-box"}],
}


def fake_fetch(files):
    def fetch(url):
        name = url.rsplit("/", 1)[1]
        if name not in files:
            raise OSError("404")
        return files[name]
    return fetch


FILES = {
    "ip.txt": "# comment\n5.8.43.0/24\n5.8.44.1\n2a00:1450::/32\n",
    "no_more": "5.8.43.128/25\n",
    "list.txt": "api.max.ru\nmax.ru\nvk.com\n",
    "set.json": json.dumps({"version": 2, "rules": [{"domain_suffix": ["ozon.ru", "id.vk.com"]}]}),
}


class ParseTest(unittest.TestCase):
    def test_networks_reject_broad_private_and_garbage(self):
        networks, rejected = build.parse_networks("0.0.0.0/0\n10.0.0.0/8\nnot-an-ip\n5.8.43.7\n")
        self.assertEqual(networks, [ipaddress.ip_network("5.8.43.7/32")])
        self.assertEqual(rejected, ["0.0.0.0/0", "10.0.0.0/8", "not-an-ip"])

    def test_domains_v2fly_and_plain(self):
        text = "domain:Ya.RU\nfull:api.max.ru\nkeyword:yandex\ndomain:psk\n*.ozon.ru\nрф.рф @ads\n"
        domains, rejected = build.parse_domains(text)
        self.assertEqual(domains, ["ya.ru", "api.max.ru", "ozon.ru", "xn--p1ai.xn--p1ai"])
        self.assertEqual(rejected, ["keyword:yandex", "psk"])

    def test_domains_sing_box_json(self):
        domains, _ = build.parse_domains(FILES["set.json"], "sing-box")
        self.assertEqual(domains, ["ozon.ru", "id.vk.com"])


class MergeTest(unittest.TestCase):
    def test_exclusion_splits_and_drops(self):
        merged = build.merge_networks(["5.8.0.0/16", "6.6.6.0/24"], ["5.8.128.0/17", "6.0.0.0/8"])
        self.assertEqual(merged, ["5.8.0.0/17"])

    def test_adjacent_networks_collapse(self):
        self.assertEqual(build.merge_networks(["5.8.0.0/25", "5.8.0.128/25"], []), ["5.8.0.0/24"])

    def test_domains_under_parent_suffix_dropped(self):
        merged = build.merge_domains(["api.max.ru", "max.ru", "id.vk.com", "ok.ru"], ["ok.ru"])
        self.assertEqual(merged, ["id.vk.com", "max.ru"])


class LoadSourceTest(unittest.TestCase):
    source = {"name": "a", "repo": "x/a", "path": "ip.txt"}

    def previous_with(self, root, entries):
        path = root / "sources" / "ip" / "a.txt"
        path.parent.mkdir(parents=True)
        path.write_text("\n".join(entries) + "\n", encoding="utf-8")

    def test_failure_keeps_last_good_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.previous_with(Path(tmp), ["5.8.43.0/24"])
            entries, status = build.load_source(self.source, "ip", Path(tmp), fake_fetch({}))
        self.assertEqual(entries, ["5.8.43.0/24"])
        self.assertTrue(status["stale"])

    def test_shrunken_source_replaced_by_last_good(self):
        old = [f"5.8.{i}.0/24" for i in range(10)]
        with tempfile.TemporaryDirectory() as tmp:
            self.previous_with(Path(tmp), old)
            entries, status = build.load_source(self.source, "ip", Path(tmp), fake_fetch({"ip.txt": "5.8.0.0/24\n"}))
        self.assertEqual(len(entries), 10)
        self.assertIn("сократился", status["error"])

    def test_failure_without_copy_gives_nothing(self):
        entries, status = build.load_source(self.source, "ip", None, fake_fetch({}))
        self.assertEqual(entries, [])
        self.assertFalse(status["stale"])
        self.assertEqual(status["error"], "404")


class BuildTest(unittest.TestCase):
    def test_build_then_rebuild_without_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            first, second = Path(tmp, "first"), Path(tmp, "second")
            first.mkdir()
            second.mkdir()
            self.assertTrue(build.build(SOURCES, None, first, fake_fetch(FILES)))
            ip = (first / "ru-mobile-whitelist-ip.txt").read_text().split()
            sni = (first / "ru-mobile-whitelist-sni.txt").read_text().split()
            ruleset = json.loads((first / "ru-mobile-whitelist-sni.json").read_text())
            self.assertFalse(build.build(SOURCES, first, second, fake_fetch(FILES)))
        self.assertEqual(ip, ["5.8.43.0/25", "5.8.44.1/32", "2a00:1450::/32"])
        self.assertEqual(sni, ["max.ru", "ozon.ru", "vk.com"])
        self.assertEqual(ruleset, {"version": 2, "rules": [{"domain_suffix": sni}]})

    def test_total_shrink_blocks_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous, out = Path(tmp, "prev"), Path(tmp, "out")
            previous.mkdir()
            out.mkdir()
            many = "".join(f"5.{i}.0.0/16\n" for i in range(9, 30))
            (previous / "ru-mobile-whitelist-ip.txt").write_text(many)
            with self.assertRaises(SystemExit):
                build.build(SOURCES, previous, out, fake_fetch(FILES))


if __name__ == "__main__":
    unittest.main()

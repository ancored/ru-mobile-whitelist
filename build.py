#!/usr/bin/env python3
"""Сборка белых списков мобильного интернета РФ (IP и SNI) из открытых источников."""
import argparse
import ipaddress
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RAW_URL = "https://raw.githubusercontent.com/{repo}/HEAD/{path}"
COMMITS_URL = "https://api.github.com/repos/{repo}/commits?path={path}&per_page=1"
MAX_BYTES = 32 * 1024 * 1024
# Источник, потерявший больше 30% записей, заменяется прошлой удачной копией;
# итоговый список, потерявший больше половины, не публикуется.
SOURCE_SHRINK_LIMIT = 0.7
TOTAL_SHRINK_LIMIT = 0.5
MIN_PREFIX = {4: 8, 6: 16}
RULESET_VERSION = 2  # читается sing-box 1.10 и новее
OUTPUTS = {"ip": "ru-mobile-whitelist-ip", "sni": "ru-mobile-whitelist-sni"}
LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def http_get(url, token=None):
    headers = {"User-Agent": "ru-mobile-whitelist"}
    if token:
        headers["Authorization"] = "Bearer " + token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("источник больше 32 МиБ")
    return data.decode("utf-8")


def text_lines(text):
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            yield line


def parse_networks(text):
    """Строки списка → (корректные сети, отброшенные строки)."""
    networks, rejected = [], []
    for line in text_lines(text):
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            rejected.append(line)
            continue
        if network.prefixlen < MIN_PREFIX[network.version] or not network.is_global:
            rejected.append(line)
        else:
            networks.append(network)
    return networks, rejected


def normalize_domain(name):
    name = name.strip().lower().rstrip(".").removeprefix("*.").removeprefix(".")
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = name.split(".")
    if len(labels) < 2 or not all(LABEL.match(label) for label in labels):
        return None
    return name


def parse_domains(text, fmt=None):
    """Простой список, формат v2fly (domain:/full:) или rule-set sing-box в JSON.

    Всё сводится к domain_suffix: full: тоже становится суффиксом.
    """
    if fmt == "sing-box":
        names = [name for rule in json.loads(text).get("rules", [])
                 for key in ("domain", "domain_suffix") for name in rule.get(key, [])]
    else:
        names = []
        for line in text_lines(text):
            token = line.split()[0]
            kind, sep, value = token.partition(":")
            if not sep:
                kind, value = "domain", token
            names.append(value if kind in ("domain", "full") else token)
    domains, rejected = [], []
    for name in names:
        domain = normalize_domain(name)
        if domain:
            domains.append(domain)
        else:
            rejected.append(name)
    return domains, rejected


def parse(kind, text, fmt=None):
    if kind == "sni":
        return parse_domains(text, fmt)
    networks, rejected = parse_networks(text)
    return [str(network) for network in networks], rejected


def previous_file(previous, *parts):
    """Файл прошлой сборки, если он есть."""
    if previous is None:
        return None
    path = previous.joinpath(*parts)
    return path if path.is_file() else None


def load_source(source, kind, previous, fetch):
    """Записи источника и его состояние; при сбое — прошлая удачная копия."""
    url = RAW_URL.format(**source)
    status = {"name": source["name"], "kind": kind, "url": url, "stale": False, "error": None, "rejected": 0}
    snapshot = previous_file(previous, "sources", kind, source["name"] + ".txt")
    old = snapshot.read_text(encoding="utf-8").split() if snapshot else None
    try:
        entries, rejected = parse(kind, fetch(url), source.get("format"))
        if not entries:
            raise ValueError("пустой список")
        if old and len(entries) < len(old) * SOURCE_SHRINK_LIMIT:
            raise ValueError(f"список сократился с {len(old)} до {len(entries)}")
        status["rejected"] = len(rejected)
    except Exception as exc:
        status["error"] = str(exc)
        status["stale"] = old is not None
        entries = old or []
    status["count"] = len(entries)
    return sorted(set(entries)), status


def last_commit_date(source, token):
    try:
        commits = json.loads(http_get(COMMITS_URL.format(**source), token))
        return commits[0]["commit"]["committer"]["date"] if commits else None
    except Exception:
        return None


def subtract(networks, hole):
    result = []
    for network in networks:
        if not network.overlaps(hole):
            result.append(network)
        elif hole.subnet_of(network):
            result.extend(network.address_exclude(hole))
    return result


def merge_networks(included, excluded):
    """Строки подсетей → слитые подсети без исключённых диапазонов."""
    included = [ipaddress.ip_network(n) for n in included]
    excluded = [ipaddress.ip_network(n) for n in excluded]
    result = []
    for version in (4, 6):
        networks = list(ipaddress.collapse_addresses(n for n in included if n.version == version))
        for hole in ipaddress.collapse_addresses(n for n in excluded if n.version == version):
            networks = subtract(networks, hole)
        result.extend(str(n) for n in ipaddress.collapse_addresses(networks))
    return result


def merge_domains(included, excluded):
    """Объединение без исключённых; домен под уже включённым суффиксом лишний."""
    names = set(included) - set(excluded)

    def has_parent(name):
        labels = name.split(".")
        return any(".".join(labels[i:]) in names for i in range(1, len(labels) - 1))

    return sorted(name for name in names if not has_parent(name))


def read_local(path, kind):
    return parse(kind, path.read_text(encoding="utf-8"))[0] if path.is_file() else []


def write_lists(out, name, key, values):
    (out / (name + ".txt")).write_text("".join(v + "\n" for v in values), encoding="utf-8")
    ruleset = {"version": RULESET_VERSION, "rules": [{key: values}]}
    (out / (name + ".json")).write_text(json.dumps(ruleset, indent=1) + "\n", encoding="utf-8")


def previous_list(previous, kind):
    path = previous_file(previous, OUTPUTS[kind] + ".txt")
    return path.read_text(encoding="utf-8").split() if path else None


def health(statuses):
    return {(s["kind"], s["name"]): s["error"] is None for s in statuses}


def previous_statuses(previous):
    path = previous_file(previous, "status.json")
    return json.loads(path.read_text(encoding="utf-8"))["sources"] if path else []


def changes_report(lists, old_lists, statuses):
    lines = []
    for kind, title in (("ip", "IP"), ("sni", "SNI")):
        new, old = set(lists[kind]), set(old_lists[kind] or [])
        lines.append(f"- {title}: {len(new)} записей (+{len(new - old)} / −{len(old - new)})")
    lines += ["", "| Источник | Тип | Записей | Изменён в источнике | Состояние |", "|---|---|---|---|---|"]
    for s in statuses:
        state = "ок" if not s["error"] else ("прошлая копия: " if s["stale"] else "нет данных: ") + s["error"]
        updated = (s.get("updated_at") or "—")[:10]
        lines.append(f"| [{s['name']}]({s['url']}) | {s['kind']} | {s['count']} | {updated} | {state} |")
    return "\n".join(lines) + "\n"


def build(sources, previous, out, fetch, commit_date=lambda source: None):
    """Собирает списки в out; возвращает True, если они изменились."""
    statuses, entries = [], {"ip": [], "ip_exclude": [], "sni": []}
    for kind in entries:
        for source in sources.get(kind, []):
            values, status = load_source(source, kind, previous, fetch)
            status["updated_at"] = commit_date(source)
            print(f"[{kind}] {source['name']}: {status['count']}"
                  + (f", ошибка: {status['error']}" if status["error"] else ""))
            snapshot = out / "sources" / kind / (source["name"] + ".txt")
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            snapshot.write_text("".join(v + "\n" for v in values), encoding="utf-8")
            entries[kind].extend(values)
            statuses.append(status)

    lists = {
        "ip": merge_networks(entries["ip"] + read_local(ROOT / "include" / "ip.txt", "ip"),
                             entries["ip_exclude"] + read_local(ROOT / "exclude" / "ip.txt", "ip")),
        "sni": merge_domains(entries["sni"] + read_local(ROOT / "include" / "sni.txt", "sni"),
                             read_local(ROOT / "exclude" / "sni.txt", "sni")),
    }
    old_lists = {kind: previous_list(previous, kind) for kind in lists}
    for kind, values in lists.items():
        old = old_lists[kind]
        if old and len(values) < len(old) * TOTAL_SHRINK_LIMIT:
            raise SystemExit(f"{kind}: итог сократился с {len(old)} до {len(values)}, публикация отменена")

    write_lists(out, OUTPUTS["ip"], "ip_cidr", lists["ip"])
    write_lists(out, OUTPUTS["sni"], "domain_suffix", lists["sni"])
    (out / "CHANGES.md").write_text(changes_report(lists, old_lists, statuses), encoding="utf-8")
    status = {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "counts": {kind: len(values) for kind, values in lists.items()}, "sources": statuses}
    (out / "status.json").write_text(json.dumps(status, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    # Публикуем и тогда, когда списки те же, но источник сломался или починился.
    return lists != old_lists or health(statuses) != health(previous_statuses(previous))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=ROOT / "sources.json")
    parser.add_argument("--previous", type=Path, help="папка прошлой сборки (ветка release)")
    parser.add_argument("--out", type=Path, default=ROOT / "out")
    args = parser.parse_args(argv)
    token = os.environ.get("GITHUB_TOKEN")
    args.out.mkdir(parents=True, exist_ok=True)
    changed = build(json.loads(args.sources.read_text(encoding="utf-8")), args.previous, args.out,
                    fetch=http_get, commit_date=lambda source: last_commit_date(source, token))
    print("изменения есть" if changed else "без изменений")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write(f"changed={'true' if changed else 'false'}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

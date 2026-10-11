# ru-mobile-whitelist

Списки IP-адресов и доменов (SNI), доступных в мобильном интернете РФ в режиме «белых списков».
Собираются раз в сутки из открытых источников и публикуются в форматах sing-box (`.srs`, `.json`) и
текстом (`.txt`).

## Файлы

| Файл | Что внутри |
|---|---|
| `ru-mobile-whitelist-ip.srs` / `.json` / `.txt` | подсети IPv4 и IPv6 (`ip_cidr`) |
| `ru-mobile-whitelist-sni.srs` / `.json` / `.txt` | домены (`domain_suffix`: домен и все его поддомены) |
| `status.json` | состояние сборки: число записей и состояние каждого источника, дата последнего изменения его файла |
| `CHANGES.md` | что изменилось с прошлой сборки (он же — описание релиза) |
| `sources/` | нормализованные копии источников — по ним видно, откуда пришла запись |

Ссылки (вместо `ip` — `sni` для доменов):

```text
https://github.com/ancored/ru-mobile-whitelist/releases/latest/download/ru-mobile-whitelist-ip.srs
https://raw.githubusercontent.com/ancored/ru-mobile-whitelist/release/ru-mobile-whitelist-ip.srs
https://cdn.jsdelivr.net/gh/ancored/ru-mobile-whitelist@release/ru-mobile-whitelist-ip.srs
```

Rule-set собирается в версии 2 и читается sing-box 1.10 и новее. Релиз выходит только при изменении
списков; хранятся последние 14 релизов, история изменений — в ветке `release`.

## sing-box

```json
{
  "route": {
    "rule_set": [
      {
        "type": "remote",
        "tag": "ru-mobile-whitelist-ip",
        "format": "binary",
        "url": "https://github.com/ancored/ru-mobile-whitelist/releases/latest/download/ru-mobile-whitelist-ip.srs"
      },
      {
        "type": "remote",
        "tag": "ru-mobile-whitelist-sni",
        "format": "binary",
        "url": "https://github.com/ancored/ru-mobile-whitelist/releases/latest/download/ru-mobile-whitelist-sni.srs"
      }
    ],
    "rules": [
      {
        "rule_set": ["ru-mobile-whitelist-ip", "ru-mobile-whitelist-sni"],
        "outbound": "direct"
      }
    ]
  }
}
```

Для подбора серверов под белые списки удобно требовать оба совпадения: адрес сервера — в IP-списке,
SNI — в списке доменов.

## Как собирается

**IP — широко.** Объединение всех источников минус подсети, о которых известно, что их убрали из белых
списков (`whitelist_no_more` из d010b и свой `exclude/ip.txt`). Исключение вычитается диапазоном: если
внутри большой подсети убрали /24, подсеть разрезается. Отбрасываются частные и служебные адреса и слишком
широкие записи (короче /8 для IPv4 и /16 для IPv6). Пересекающиеся и соседние подсети сливаются.

**SNI — тоже широко.** Объединение всех источников. Все записи — суффиксы: `max.ru` покрывает и
`web.max.ru`, поэтому домен под уже включённым суффиксом в список не попадает. Записи формата v2fly
`domain:` и `full:` берутся как суффиксы, `keyword:` и `regexp:` пропускаются. Кириллические домены
переводятся в punycode.

**Свои правки.** `include/ip.txt`, `include/sni.txt` — добавить; `exclude/ip.txt`, `exclude/sni.txt` —
убрать (для SNI удаляется ровно указанная запись). По одной записи на строку, комментарий после `#`.

**Защита от сбоев.** Если источник недоступен, пуст или потерял больше 30% записей, берётся его прошлая
удачная копия из ветки `release`, а в `status.json` и описании релиза он помечается. Если итоговый список
потерял больше половины записей, сборка не публикуется.

## Источники

| Источник | Что берётся | Лицензия |
|---|---|---|
| [hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist) | `cidrwhitelist.txt`, `ipwhitelist.txt`, `whitelist.txt` | MIT |
| [d010b/custom_geoip](https://github.com/d010b/custom_geoip) | `whitelist_url.txt`, исключения `whitelist_no_more` | MIT |
| [hydraponique/roscomvpn-geoip](https://github.com/hydraponique/roscomvpn-geoip) | `release/text/whitelist.txt`, `CUSTOM-WHITELIST.txt` | не указана |
| [hydraponique/roscomvpn-geosite](https://github.com/hydraponique/roscomvpn-geosite) | `data/whitelist` | MIT |
| [escapingworm/russia-whitelist](https://github.com/escapingworm/russia-whitelist) | `ru-whitelist-cidr.txt` | MIT |
| [overskye/ru-cdn-whitelist](https://github.com/overskye/ru-cdn-whitelist) | `ipv4.txt`, `ipv6.txt` | не указана |
| [kirilllavrov/whitelists](https://github.com/kirilllavrov/whitelists) | `release/whitelist.txt` | MIT |
| [jinndi/geosite-cheburnet](https://github.com/jinndi/geosite-cheburnet) | `geosite-cheburnet.json` | MIT |

Источники перечислены в `sources.json`; права на данные принадлежат их авторам.

## Локальный запуск

Нужен Python 3.9+ без сторонних пакетов; `.srs` собирает `sing-box rule-set compile`.

```sh
python3 -m unittest discover -s tests
python3 build.py --out out                      # первая сборка
python3 build.py --previous out --out out-next  # с прошлой удачной копией
```

## Лицензия

Код — [MIT](LICENSE).

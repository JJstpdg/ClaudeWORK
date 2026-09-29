#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Устройства, которые запустили приложение (по логам Ingress), но не отправили ни одного запроса в Trisigma.

Как считаем (см. README.md):
  1. Уровень 1 (ES|QL по mpback-k8s-ingress): «запуск» = устройство обратилось не менее чем в N разных сервисов
     за одну минуту (веер запросов при старте приложения), платформа ios/android, версия приложения выше порога.
     Кандидат = запуск есть, а запросов к trisigma после запуска (до конца окна + буфер) нет.
  2. Уровень 2 (проверка кандидатов): для каждого кандидата ищем ЛЮБОЙ запрос к trisigma после запуска без
     верхней границы по времени - в Ingress и в индексе mpback-k8s-trisigma-composition. Нашли - в выборку не берём
     (это и есть «ошибочные» юзеры, которые «по итогу получили запрос»), причина пишется в *_excluded.csv.
  3. Уровень 3 (по желанию, --events-index): пересечение с событиями, у которых поле эксперимента не пришло/пустое.

Подключение (без сторонних библиотек, только Python 3.8+):
  ES_URL=https://elastic:9200            или   KIBANA_URL=https://kibana.example.com
  ES_API_KEY=...   либо   ES_USER=... ES_PASSWORD=...   либо   -H "Cookie: sid=..."

Команды:
  discover   показать версию ES, примеры документов и поля индексов (чтобы заполнить названия полей)
  sanity     проверить, что фильтры находят то, что надо (сервисы, пути trisigma, версии)
  esql       напечатать ES|QL-запрос для вставки в Kibana Dev Tools / Discover (ничего не выполняет)
  run        выполнить всё и записать CSV
  audit      перепроверить старую выгрузку (CSV): у кого из неё на самом деле были запросы в trisigma

Названия полей и пороги меняются словарём CFG ниже или ключом  --set имя=значение  (см. --help).
"""
import argparse
import base64
import csv
import datetime as dt
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# --------------------------------------------------------------------------------------------------
# Настройки. Названия полей - предположение: проверьте командой `discover` и поправьте под свои логи.
# --------------------------------------------------------------------------------------------------
CFG = {
    # индексы (шаблоны: индексы обычно дневные, *-YYYY.MM.DD)
    "ingress_index": "mpback-k8s-ingress*",
    "comp_index": "mpback-k8s-trisigma-composition*",
    "events_index": "",                       # необязательно: индекс событий с полем эксперимента

    # поля Ingress
    "ts": "@timestamp",
    "device": "device_id",                    # visitorId в Trisigma == user-agent.id == device_uuid на бэке
    "device_term": "",                        # если по device нужен другой (keyword) вариант, напр. device_id.keyword
    "user": "user_id",                        # пусто -> user_id в выгрузке не нужен
    "platform": "platform",                   # значения ios / android (регистр не важен)
    "version": "app_version",                 # 11.10.1_380 (iOS), 11.10.1.g_20300 (Android)
    "path": "path",                           # URI запроса, по нему определяем сервис и запросы в trisigma
    "status": "status",                       # HTTP-статус, только для диагностики
    "svc_dissect": "/gateway/%{svc}/%{?rest}",  # как из path вытащить имя сервиса (для веера запросов)
    "tri_like": "*trisigma*",                 # признак запроса в trisigma в path (регистр не важен)

    # индекс trisigma-composition
    "comp_ts": "@timestamp",
    "comp_device": "",                        # поле с visitorId; пусто -> искать id фразой по всем полям

    # индекс событий (для пересечения)
    "ev_ts": "@timestamp",
    "ev_key": "device_id",                    # по какому полю связываем события с кандидатами
    "ev_key_source": "device",                # device | user - чем из кандидата это поле заполняется
    "ev_experiment": "experiment",            # «не пришло или пустое» = поля нет / null / "" / []

    # логика
    "fanout_min": "7",                        # запуск = не менее N разных сервисов за одну минуту (в старой выгрузке 7-9)
    "pre_margin_min": "2",                    # запрос в trisigma чуть ДО первой минуты веера считаем частью запуска
    "buffer_min": "30",                       # сколько минут после конца окна ещё ищем запросы в trisigma
    "min_gap_min": "0",                       # >0: брать только «холодные» запуски - пауза перед ними не меньше N минут
    "gap_lookback_h": "12",                   # как далеко назад искать предыдущий запрос устройства (колонка gap_before_min)
    "min_version": "11.10.0",
    "inclusive": "false",                     # false: версия строго больше min_version; true: больше или равна
    "esql_limit": "10000",
}

MAIN_ESQL = r'''FROM <<ingress_index>>
| WHERE <<ts>> >= "<<t_from>>" AND <<ts>> < "<<t_end>>" AND <<device>> IS NOT NULL
| GROK <<version>> "^%{INT:v_major:int}[.]%{INT:v_minor:int}[.]%{INT:v_patch:int}"
| EVAL is_tri = TO_LOWER(<<path>>) LIKE "<<tri_like>>", ver_num = v_major * 1000000 + v_minor * 1000 + v_patch
| EVAL ok = NOT is_tri AND TO_LOWER(<<platform>>) IN ("ios", "android") AND ver_num <<op>> <<threshold>>
| DISSECT <<path>> "<<svc_dissect>>"
| EVAL svc_ok = CASE(ok, svc), ver_ok = CASE(ok, ver_num), plat_ok = CASE(ok, CASE(TO_LOWER(<<platform>>) == "ios", 4, 5)), tri_flag = CASE(is_tri, 1, 0)
| EVAL minute = DATE_TRUNC(1 minute, <<ts>>)
| RENAME <<device>> AS dev
| STATS svc_cnt = COUNT_DISTINCT(svc_ok), tri_cnt = SUM(tri_flag), ver_num = MAX(ver_ok), plat = MAX(plat_ok), last_seen = MAX(<<ts>>)<<user_agg1>> BY dev, minute
| EVAL is_launch = svc_cnt >= <<fanout_min>> AND minute < "<<t_to>>"
| EVAL launch_flag = CASE(is_launch, 1, 0), launch_min = CASE(is_launch, minute), fan = CASE(is_launch, svc_cnt), tri_min = CASE(tri_cnt > 0, minute)
| STATS launches = SUM(launch_flag), first_launch = MIN(launch_min), max_fanout = MAX(fan), tri_total = SUM(tri_cnt), last_tri = MAX(tri_min), ver_num = MAX(ver_num), plat = MAX(plat), last_seen = MAX(last_seen)<<user_agg2>> BY dev
| WHERE launches > 0 AND (tri_total == 0 OR last_tri < first_launch - <<pre_margin_min>> minutes)
| EVAL platform = CASE(plat == 4, "ios", "android"), app_version = CONCAT(TO_STRING(ver_num / 1000000), ".", TO_STRING((ver_num / 1000) % 1000), ".", TO_STRING(ver_num % 1000))
| KEEP <<keep_user>>dev, platform, app_version, first_launch, launches, max_fanout, last_seen, tri_total
| SORT first_launch
| LIMIT <<esql_limit>>'''

GATE_TRI = r'''FROM <<ingress_index>>
| WHERE <<ts>> >= "<<t_from>>" AND <<ts>> < "<<t_end>>"
| WHERE TO_LOWER(<<path>>) LIKE "<<tri_like>>"
| EVAL has_dev = <<device>> IS NOT NULL
| STATS docs = COUNT(*), with_device = SUM(CASE(has_dev, 1, 0))'''

SANITY_SERVICES = r'''FROM <<ingress_index>>
| WHERE <<ts>> >= "<<t_from>>" AND <<ts>> < "<<t_end>>"
| WHERE TO_LOWER(<<platform>>) IN ("ios", "android")
| DISSECT <<path>> "<<svc_dissect>>"
| RENAME <<device>> AS dev
| STATS docs = COUNT(*), devices = COUNT_DISTINCT(dev) BY svc
| SORT docs DESC
| LIMIT 30'''

SANITY_TRI = r'''FROM <<ingress_index>>
| WHERE <<ts>> >= "<<t_from>>" AND <<ts>> < "<<t_end>>"
| WHERE TO_LOWER(<<path>>) LIKE "<<tri_like>>"
| RENAME <<device>> AS dev
| STATS docs = COUNT(*), devices = COUNT_DISTINCT(dev), first_ts = MIN(<<ts>>), last_ts = MAX(<<ts>>) BY <<path>>
| SORT docs DESC
| LIMIT 15'''

SANITY_VERSIONS = r'''FROM <<ingress_index>>
| WHERE <<ts>> >= "<<t_from>>" AND <<ts>> < "<<t_end>>"
| WHERE TO_LOWER(<<platform>>) IN ("ios", "android")
| GROK <<version>> "^%{INT:v_major:int}[.]%{INT:v_minor:int}[.]%{INT:v_patch:int}"
| RENAME <<device>> AS dev
| STATS docs = COUNT(*), devices = COUNT_DISTINCT(dev) BY v_major, v_minor, v_patch
| SORT v_major DESC, v_minor DESC, v_patch DESC
| LIMIT 30'''


# --------------------------------------------------------------------------------------------------
# Вспомогательное
# --------------------------------------------------------------------------------------------------
def die(msg):
    sys.stderr.write("ОШИБКА: " + msg + "\n")
    sys.exit(2)


def utcnow():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def parse_time(s):
    """ISO-время (UTC, если пояс не указан) или now / now-6h / now-2d / now-30m."""
    s = s.strip()
    m = re.fullmatch(r"now(?:-(\d+)([mhd]))?", s)
    if m:
        t = utcnow()
        if m.group(1):
            t -= dt.timedelta(**{{"m": "minutes", "h": "hours", "d": "days"}[m.group(2)]: int(m.group(1))})
        return t
    s = s.replace(" ", "T").replace("Z", "+00:00")
    try:
        t = dt.datetime.fromisoformat(s)
    except ValueError:
        die("не понимаю время %r (пример: 2026-09-29T00:00:00Z или now-6h)" % s)
    return t.replace(tzinfo=dt.timezone.utc) if t.tzinfo is None else t.astimezone(dt.timezone.utc)


def iso(t):
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_es_time(s):
    """Время из ответа ES (…Z, с долями секунды или без)."""
    s = s.replace("Z", "+00:00")
    if "." in s:
        head, tail = s.split(".", 1)
        frac, tz = re.match(r"(\d+)(.*)", tail).groups()
        s = head + "." + (frac + "000000")[:6] + tz
    return dt.datetime.fromisoformat(s).astimezone(dt.timezone.utc)


def ms_to_iso(sort_values):
    """Время из поля sort (мс с начала эпохи) - на случай, если поля времени нет в _source."""
    if not sort_values or not isinstance(sort_values[0], (int, float)):
        return ""
    ms = sort_values[0] / 1e6 if sort_values[0] > 1e15 else sort_values[0]
    return dt.datetime.fromtimestamp(ms / 1000.0, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (ms % 1000)


def parse_version(s):
    m = re.match(r"^\s*v?(\d+)\.(\d+)\.(\d+)", s or "")
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def ver_num(v):
    return v[0] * 1000000 + v[1] * 1000 + v[2]


def as_bool(s):
    return str(s).strip().lower() in ("1", "true", "yes", "y", "да")


def qid(name):
    """Идентификатор для ES|QL: экранируем обратными кавычками, если в имени есть служебные символы."""
    parts = name.split(".")
    if all(re.fullmatch(r"[A-Za-z_@][A-Za-z0-9_@]*", p) for p in parts):
        return name
    return ".".join("`" + p.replace("`", "``") + "`" for p in parts)


def render(tpl, **kw):
    out = tpl
    for k, v in kw.items():
        out = out.replace("<<%s>>" % k, str(v))
    left = re.findall(r"<<\w+>>", out)
    if left:
        raise RuntimeError("не подставлены параметры: %s" % left)
    return out


def esql_params(cfg, t_from, t_to, t_end):
    thr = parse_version(cfg["min_version"])
    if not thr:
        die("min_version должен быть вида 11.10.0")
    user = cfg["user"].strip()
    p = dict(
        ingress_index=cfg["ingress_index"], ts=qid(cfg["ts"]), device=qid(cfg["device"]),
        platform=qid(cfg["platform"]), version=qid(cfg["version"]), path=qid(cfg["path"]),
        svc_dissect=cfg["svc_dissect"].replace('"', '\\"'),
        tri_like=cfg["tri_like"].lower().replace('"', '\\"'),
        t_from=iso(t_from), t_to=iso(t_to), t_end=iso(t_end),
        op=">=" if as_bool(cfg["inclusive"]) else ">", threshold=ver_num(thr),
        fanout_min=int(cfg["fanout_min"]), pre_margin_min=int(cfg["pre_margin_min"]),
        esql_limit=int(cfg["esql_limit"]),
        user_agg1=(", uid = MAX(%s)" % qid(user)) if user else "",
        user_agg2=", uid = MAX(uid)" if user else "",
        keep_user="uid, " if user else "",
    )
    return p


def build_main_esql(cfg, t_from, t_to, t_end):
    return render(MAIN_ESQL, **esql_params(cfg, t_from, t_to, t_end))


def chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def table(rows, cols=None, limit=40):
    if not rows:
        print("  (пусто)")
        return
    cols = cols or list(rows[0].keys())
    data = [[("" if r.get(c) is None else str(r.get(c))) for c in cols] for r in rows[:limit]]
    w = [max(len(c), *(len(d[i]) for d in data)) for i, c in enumerate(cols)]
    print("  " + "  ".join(c.ljust(w[i]) for i, c in enumerate(cols)))
    for d in data:
        print("  " + "  ".join(d[i].ljust(w[i]) for i in range(len(cols))))
    if len(rows) > limit:
        print("  ... ещё %d строк" % (len(rows) - limit))


# --------------------------------------------------------------------------------------------------
# Подключение к Elasticsearch напрямую или через Kibana (Dev Tools console proxy)
# --------------------------------------------------------------------------------------------------
class EsError(Exception):
    def __init__(self, code, detail):
        Exception.__init__(self, "HTTP %s: %s" % (code, detail))
        self.code, self.detail = code, detail


class Client(object):
    def __init__(self, es_url=None, kibana_url=None, api_key=None, user=None, password=None,
                 headers=None, insecure=False, cafile=None, timeout=300):
        if bool(es_url) == bool(kibana_url):
            die("укажите ровно одно: --es-url (или ES_URL) либо --kibana-url (или KIBANA_URL)")
        self.kibana = bool(kibana_url)
        self.base = (kibana_url or es_url).rstrip("/")
        self.timeout = timeout
        self.headers = {"Accept": "application/json"}
        if api_key:
            self.headers["Authorization"] = "ApiKey " + api_key
        elif user:
            token = base64.b64encode(("%s:%s" % (user, password or "")).encode()).decode()
            self.headers["Authorization"] = "Basic " + token
        for h in headers or []:
            k, _, v = h.partition(":")
            self.headers[k.strip()] = v.strip()
        if self.kibana:
            self.headers["kbn-xsrf"] = "true"
        self.ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
        if insecure:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def call(self, method, path, body=None, ndjson=False, retries=3):
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            data = body.encode("utf-8")
        else:
            data = None
        if self.kibana:
            url = "%s/api/console/proxy?path=%s&method=%s" % (self.base, urllib.parse.quote(path, safe=""), method)
            http_method = "POST"
        else:
            url, http_method = self.base + path, method
        headers = dict(self.headers)
        headers["Content-Type"] = "application/x-ndjson" if ndjson else "application/json"
        for attempt in range(retries):
            req = urllib.request.Request(url, data=data, method=http_method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                    raw = r.read()
                return json.loads(raw.decode("utf-8")) if raw else {}
            except urllib.error.HTTPError as e:
                detail = e.read().decode("utf-8", "replace")[:3000]
                if e.code in (429, 502, 503, 504) and attempt + 1 < retries:
                    time.sleep(2 * (attempt + 1))
                    continue
                raise EsError(e.code, detail)
            except urllib.error.URLError as e:
                if attempt + 1 < retries:
                    time.sleep(2 * (attempt + 1))
                    continue
                die("нет соединения с %s: %s" % (self.base, e.reason))


def rows_from_esql(resp):
    cols = [c["name"] for c in resp.get("columns", [])]
    return [dict(zip(cols, v)) for v in resp.get("values", [])]


def run_esql(cli, query, use_async=True, verbose=True):
    """Выполнить ES|QL. Асинхронно (устойчиво к таймаутам Kibana), если версия кластера позволяет."""
    if use_async:
        try:
            r = cli.call("POST", "/_query/async", {"query": query, "wait_for_completion_timeout": "8s",
                                                    "keep_on_completion": True, "keep_alive": "2h"})
        except EsError as e:
            if e.code in (404, 405) or "no handler" in e.detail.lower():
                return run_esql(cli, query, use_async=False, verbose=verbose)
            raise
        qid_ = r.get("id")
        started = time.time()
        while r.get("is_running"):
            if verbose:
                sys.stderr.write("\r  ES|QL выполняется… %ds" % (time.time() - started))
                sys.stderr.flush()
            r = cli.call("GET", "/_query/async/%s?wait_for_completion_timeout=8s" % urllib.parse.quote(qid_, safe=""))
        if verbose and time.time() - started > 8:
            sys.stderr.write("\n")
        if qid_:
            try:
                cli.call("DELETE", "/_query/async/%s" % urllib.parse.quote(qid_, safe=""))
            except EsError:
                pass
        return rows_from_esql(r)
    return rows_from_esql(cli.call("POST", "/_query?format=json", {"query": query}))


def esql_hint(e):
    d = e.detail
    m = re.search(r"Unknown column \[([^\]]+)\]", d)
    if m:
        return ("В индексе нет поля [%s]. Выполните `discover`, найдите настоящее имя и передайте его через "
                "--set (например --set device=device_uuid)." % m.group(1))
    if "no handler found" in d.lower() or e.code == 404:
        return "Похоже, в этом кластере нет ES|QL (нужен Elasticsearch 8.14+). Сообщите версию - переделаю на DSL."
    return ""


def safe_esql(cli, query, **kw):
    try:
        return run_esql(cli, query, **kw)
    except EsError as e:
        hint = esql_hint(e)
        die("ES|QL вернул ошибку.\n%s\n%s" % (e.detail[:1500], ("Подсказка: " + hint) if hint else ""))


# --------------------------------------------------------------------------------------------------
# Уровень 1
# --------------------------------------------------------------------------------------------------
def level1(cli, cfg, t_from, t_to, slice_hours, use_async):
    """Кандидаты по Ingress. Окно режется на куски по slice_hours (экономит память ES)."""
    buffer = dt.timedelta(minutes=int(cfg["buffer_min"]))
    slices = []
    cur = t_from
    step = dt.timedelta(hours=slice_hours) if slice_hours else (t_to - t_from)
    while cur < t_to:
        nxt = min(cur + step, t_to)
        slices.append((cur, nxt))
        cur = nxt
    found = {}
    for i, (a, b) in enumerate(slices, 1):
        q = build_main_esql(cfg, a, b, b + buffer)
        sys.stderr.write("Уровень 1: окно %d/%d  %s .. %s\n" % (i, len(slices), iso(a), iso(b)))
        rows = safe_esql(cli, q, use_async=use_async)
        if len(rows) >= int(cfg["esql_limit"]):
            sys.stderr.write("  ВНИМАНИЕ: получено %d строк (лимит). Возможно, выборка обрезана - "
                             "уменьшите --slice-hours.\n" % len(rows))
        for r in rows:
            d = r["dev"]
            cur_ = found.get(d)
            if cur_ is None:
                found[d] = dict(r)
            else:
                cur_["launches"] = (cur_["launches"] or 0) + (r["launches"] or 0)
                if r["first_launch"] and (not cur_["first_launch"] or r["first_launch"] < cur_["first_launch"]):
                    cur_["first_launch"] = r["first_launch"]
                if r["last_seen"] and (not cur_["last_seen"] or r["last_seen"] > cur_["last_seen"]):
                    cur_["last_seen"] = r["last_seen"]
                cur_["max_fanout"] = max(cur_["max_fanout"] or 0, r["max_fanout"] or 0)
    return sorted(found.values(), key=lambda r: r["first_launch"] or "")


# --------------------------------------------------------------------------------------------------
# Уровень 2: для каждого кандидата ищем запрос в trisigma БЕЗ верхней границы по времени
# --------------------------------------------------------------------------------------------------
def ingress_probe(cfg, dev, since):
    ts, path = cfg["ts"], cfg["path"]
    dev_field = cfg["device_term"] or cfg["device"]
    return {
        "size": 1, "track_total_hits": False,
        "_source": [ts, path, cfg["status"]],
        "sort": [{ts: {"order": "asc", "unmapped_type": "date"}}],
        "query": {"bool": {"filter": [
            {"term": {dev_field: {"value": dev}}},
            {"range": {ts: {"gte": iso(since)}}},
            {"wildcard": {path: {"value": cfg["tri_like"].lower(), "case_insensitive": True}}},
        ]}},
    }


def comp_probe(cfg, dev, since):
    ts = cfg["comp_ts"]
    field = cfg["comp_device"].strip()
    if field:
        match = {"bool": {"should": [
            {"term": {field: {"value": dev, "case_insensitive": True}}},
            {"match_phrase": {field: dev}},
        ], "minimum_should_match": 1}}
    else:
        match = {"query_string": {"query": '"%s"' % dev.replace("\\", "\\\\").replace('"', '\\"'),
                                   "lenient": True, "default_operator": "AND"}}
    return {
        "size": 1, "track_total_hits": False,
        "sort": [{ts: {"order": "asc", "unmapped_type": "date"}}],
        "query": {"bool": {"filter": [match, {"range": {ts: {"gte": iso(since)}}}]}},
    }


def msearch(cli, pairs, batch=100):
    """pairs: [(index, body)] -> список ответов _msearch в том же порядке."""
    out = []
    for part in chunks(pairs, batch):
        lines = []
        for index, body in part:
            lines.append(json.dumps({"index": index, "ignore_unavailable": True}))
            lines.append(json.dumps(body))
        r = cli.call("POST", "/_msearch?max_concurrent_searches=8", "\n".join(lines) + "\n", ndjson=True)
        out.extend(r.get("responses", []))
    return out


def first_hit(resp):
    if resp.get("error"):
        raise EsError(resp.get("status", 500), json.dumps(resp["error"])[:1500])
    hits = resp.get("hits", {}).get("hits", [])
    return hits[0] if hits else None


def level2(cli, cfg, cands, since_key="first_launch"):
    """Возвращает (оставшиеся, исключённые). У исключённых заполнено found_*."""
    margin = dt.timedelta(minutes=int(cfg["pre_margin_min"]))
    pairs = []
    for c in cands:
        since = parse_es_time(c[since_key]) - margin
        pairs.append((cfg["ingress_index"], ingress_probe(cfg, c["dev"], since)))
        pairs.append((cfg["comp_index"], comp_probe(cfg, c["dev"], since)))
    try:
        resp = msearch(cli, pairs)
    except EsError as e:
        die("проверка кандидатов не удалась: %s" % e.detail)
    kept, dropped = [], []
    for i, c in enumerate(cands):
        try:
            h_ing, h_comp = first_hit(resp[2 * i]), first_hit(resp[2 * i + 1])
        except EsError as e:
            hint = ""
            if "too many fields" in e.detail or "field expansion" in e.detail:
                hint = " Задайте поле с visitorId: --set comp_device=<поле>."
            die("ошибка в проверке кандидата %s: %s.%s" % (c["dev"], e.detail, hint))
        c = dict(c)
        found = []
        if h_ing:
            s = h_ing.get("_source", {})
            found.append(("ingress", _get(s, cfg["ts"]) or ms_to_iso(h_ing.get("sort")),
                          _get(s, cfg["path"]), _get(s, cfg["status"])))
        if h_comp:
            s = h_comp.get("_source", {})
            msg = s.get("message") or json.dumps(s, ensure_ascii=False)
            found.append(("composition", _get(s, cfg["comp_ts"]) or ms_to_iso(h_comp.get("sort")),
                          str(msg)[:200], ""))
        if found:
            c["found_in"] = "+".join(f[0] for f in found)
            f0 = min(found, key=lambda f: str(f[1]))
            c["found_ts"], c["found_what"], c["found_status"] = f0[1], f0[2], f0[3]
            dropped.append(c)
        else:
            kept.append(c)
    return kept, dropped


def _get(src, dotted):
    cur = src
    for p in dotted.split("."):
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return src.get(dotted)
    return cur


def prev_activity_probe(cfg, dev, before, lookback):
    ts = cfg["ts"]
    return {
        "size": 1, "track_total_hits": False, "_source": False,
        "sort": [{ts: {"order": "desc", "unmapped_type": "date"}}],
        "query": {"bool": {"filter": [
            {"term": {cfg["device_term"] or cfg["device"]: {"value": dev}}},
            {"range": {ts: {"gte": iso(before - lookback), "lt": iso(before)}}},
        ]}},
    }


def add_gap(cli, cfg, cands):
    """gap_before_min: сколько минут устройство молчало перед запуском (как в старой выгрузке). None = дольше lookback."""
    look_h = int(cfg["gap_lookback_h"])
    lookback = dt.timedelta(hours=look_h)
    pairs, launches = [], []
    for c in cands:
        launch = parse_es_time(c["first_launch"])
        launches.append(launch)
        pairs.append((cfg["ingress_index"], prev_activity_probe(cfg, c["dev"], launch, lookback)))
    resp = msearch(cli, pairs)
    out = []
    for c, launch, r in zip(cands, launches, resp):
        h = first_hit(r)
        c = dict(c)
        if h and h.get("sort"):
            ms = h["sort"][0]
            ms = ms / 1e6 if ms > 1e15 else ms                      # date_nanos -> ms
            c["gap_before_min"] = int((launch.timestamp() * 1000 - ms) // 60000)
        else:
            c["gap_before_min"] = ">%dч" % look_h
        out.append(c)
    return out


def gap_value(c):
    g = c.get("gap_before_min")
    return g if isinstance(g, int) else None


# --------------------------------------------------------------------------------------------------
# Уровень 3: пересечение с событиями без эксперимента
# --------------------------------------------------------------------------------------------------
def nonempty(field):
    return {"bool": {"filter": [{"exists": {"field": field}}], "must_not": [{"term": {field: ""}}]}}


def level3(cli, cfg, cands, t_from, t_end):
    key_src = cfg["ev_key_source"]
    key_field = cfg["ev_key"]
    keys = {}
    for c in cands:
        v = c.get("dev") if key_src == "device" else c.get("uid")
        if v not in (None, ""):
            keys[v] = c
    stats = {}
    for part in chunks(list(keys), 500):
        body = {
            "size": 0, "track_total_hits": False,
            "query": {"bool": {"filter": [{"range": {cfg["ev_ts"]: {"gte": iso(t_from), "lt": iso(t_end)}}},
                                          {"terms": {key_field: part}}]}},
            "aggs": {"k": {"terms": {"field": key_field, "size": len(part)},
                           "aggs": {"with_exp": {"filter": nonempty(cfg["ev_experiment"])}}}},
        }
        try:
            r = cli.call("POST", "/%s/_search?ignore_unavailable=true" % cfg["events_index"], body)
        except EsError as e:
            die("проверка событий не удалась: %s" % e.detail)
        for b in r.get("aggregations", {}).get("k", {}).get("buckets", []):
            stats[b["key"]] = (b["doc_count"], b["with_exp"]["doc_count"])
    out = []
    for c in cands:
        v = c.get("dev") if key_src == "device" else c.get("uid")
        total, with_exp = stats.get(v, (0, 0))
        c = dict(c)
        c["events_total"], c["events_with_experiment"] = total, with_exp
        c["intersection"] = ("unknown" if total == 0 else ("yes" if with_exp == 0 else "no"))
        out.append(c)
    return out


# --------------------------------------------------------------------------------------------------
# Вывод
# --------------------------------------------------------------------------------------------------
FINAL_COLS = ["user_id", "device_id", "platform", "app_version", "first_launch_utc", "gap_before_min",
              "launch_bursts", "max_fanout_services", "last_seen_utc"]
EXCL_COLS = ["device_id", "user_id", "first_launch_utc", "reason", "found_in", "found_ts", "found_status", "found_what"]


def final_row(c):
    return {
        "user_id": c.get("uid", ""), "device_id": c["dev"], "platform": c.get("platform", ""),
        "app_version": c.get("app_version", ""), "first_launch_utc": c.get("first_launch", ""),
        "gap_before_min": c.get("gap_before_min", ""),
        "launch_bursts": c.get("launches", ""), "max_fanout_services": c.get("max_fanout", ""),
        "last_seen_utc": c.get("last_seen", ""),
    }


def write_csv(path, cols, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, delimiter=";", extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: ("" if r.get(k) is None else r.get(k)) for k in cols})
    print("  записано: %s (%d строк)" % (path, len(rows)))


def excl_row(c):
    return {"device_id": c["dev"], "user_id": c.get("uid", ""), "first_launch_utc": c.get("first_launch", ""),
            "reason": c.get("reason", "запрос в trisigma найден"),
            "found_in": c.get("found_in", ""), "found_ts": c.get("found_ts", ""),
            "found_status": c.get("found_status", ""), "found_what": c.get("found_what", "")}


# --------------------------------------------------------------------------------------------------
# Команды
# --------------------------------------------------------------------------------------------------
def cmd_discover(cli, cfg, args):
    info = cli.call("GET", "/")
    print("== кластер ==")
    print("  Elasticsearch %s, кластер %s" % (info.get("version", {}).get("number"), info.get("cluster_name")))
    pat = re.compile(r"device|user|visitor|platform|version|path|uri|url|status|session|experiment|label|"
                     r"feature|service|upstream|message|request|@timestamp", re.I)
    for name, index in (("Ingress", cfg["ingress_index"]), ("trisigma-composition", cfg["comp_index"]),
                        ("события", cfg["events_index"])):
        if not index:
            continue
        print("\n== %s: %s ==" % (name, index))
        try:
            caps = cli.call("GET", "/%s/_field_caps?fields=*&ignore_unavailable=true" % index).get("fields", {})
        except EsError as e:
            print("  не удалось прочитать поля: %s" % e.detail[:300])
            continue
        names = sorted(n for n in caps if pat.search(n) and not n.startswith("_"))
        print("  подходящие поля (%d из %d):" % (len(names), len(caps)))
        for n in names[:120]:
            print("    %-55s %s" % (n, ",".join(sorted(caps[n].keys()))))
        for label, query in (("последний документ", {"match_all": {}}),
                             ("последний документ про trisigma",
                              {"query_string": {"query": "*trisigma*", "lenient": True, "analyze_wildcard": True}})):
            body = {"size": 1, "sort": [{cfg["ts"]: {"order": "desc", "unmapped_type": "date"}}],
                    "query": {"bool": {"filter": [{"range": {cfg["ts"]: {"gte": "now-3d"}}}, query]}}}
            try:
                hits = cli.call("POST", "/%s/_search?ignore_unavailable=true" % index, body)["hits"]["hits"]
            except EsError as e:
                print("  %s: ошибка %s" % (label, e.detail[:200]))
                continue
            print("  %s:" % label)
            print("    " + (json.dumps(hits[0]["_source"], ensure_ascii=False)[:2500] if hits else "(не найден за 3 суток)"))


def sanity_window(args):
    t_to = parse_time(args.to) if args.to else utcnow()
    t_from = parse_time(args.frm) if args.frm else t_to - dt.timedelta(hours=1)
    return t_from, t_to


def cmd_sanity(cli, cfg, args):
    t_from, t_to = sanity_window(args)
    p = esql_params(cfg, t_from, t_to, t_to)
    print("Окно проверки: %s .. %s (UTC)" % (iso(t_from), iso(t_to)))
    print("\n1) Сервисы, которые разбираются из path (если пусто/только null - поправьте svc_dissect):")
    svc = safe_esql(cli, render(SANITY_SERVICES, **p))
    table(svc)
    print("\n2) Запросы к trisigma в Ingress по фильтру %r (если пусто - поправьте tri_like/path, иначе в выборку "
          "попадут ВСЕ):" % cfg["tri_like"])
    tri = safe_esql(cli, render(SANITY_TRI, **p))
    table(tri)
    print("\n3) Версии приложения (порог: версия %s %s):" % (">=" if as_bool(cfg["inclusive"]) else ">", cfg["min_version"]))
    table(safe_esql(cli, render(SANITY_VERSIONS, **p)))
    print("\n4) Индекс composition за окно:")
    body = {"query": {"range": {cfg["comp_ts"]: {"gte": iso(t_from), "lt": iso(t_to)}}}}
    try:
        n = cli.call("POST", "/%s/_count?ignore_unavailable=true" % cfg["comp_index"], body).get("count")
        print("  документов: %s" % n)
    except EsError as e:
        print("  ошибка: %s" % e.detail[:300])
    problems = []
    if not [r for r in svc if r.get("svc")]:
        problems.append("сервисы из path не разбираются (svc_dissect)")
    if not tri:
        problems.append("в Ingress не найдено ни одного запроса к trisigma (tri_like / поле path)")
    elif not any((r.get("devices") or 0) > 0 for r in tri):
        problems.append("у запросов к trisigma пустое поле %r - привязать их к устройствам нельзя" % cfg["device"])
    if problems:
        print("\n!!! НЕ ЗАПУСКАЙТЕ run, пока не исправите: " + "; ".join(problems))
        sys.exit(1)
    print("\nOK: фильтры находят и сервисы, и запросы к trisigma.")


def cmd_esql(cli, cfg, args):
    t_from, t_to = parse_time(args.frm), parse_time(args.to)
    t_end = t_to + dt.timedelta(minutes=int(cfg["buffer_min"]))
    q = build_main_esql(cfg, t_from, t_to, t_end)
    if args.devtools:
        print('POST /_query?format=txt\n{\n  "query": """\n' + "\n".join("    " + l for l in q.splitlines()) + '\n  """\n}')
    else:
        print(q)


def cmd_run(cli, cfg, args):
    t_from, t_to = parse_time(args.frm), parse_time(args.to)
    if t_to <= t_from:
        die("--to должно быть позже --from")
    t_end = t_to + dt.timedelta(minutes=int(cfg["buffer_min"]))
    print("Окно запусков: %s .. %s (UTC), буфер для запросов в trisigma +%s мин; версия %s %s" % (
        iso(t_from), iso(t_to), cfg["buffer_min"], ">=" if as_bool(cfg["inclusive"]) else ">", cfg["min_version"]))
    if not args.no_gate:
        gate = safe_esql(cli, render(GATE_TRI, **esql_params(cfg, t_from, t_to, t_end)), verbose=False)
        docs = (gate[0].get("docs") or 0) if gate else 0
        with_dev = (gate[0].get("with_device") or 0) if gate else 0
        if docs == 0:
            die("в Ingress за окно нет ни одного запроса к trisigma (tri_like=%r, поле path=%r): при такой проверке "
                "в выборку попали бы ВСЕ. Запустите `sanity` и поправьте фильтр." % (cfg["tri_like"], cfg["path"]))
        if with_dev == 0:
            die("у запросов к trisigma в Ingress пустое поле %r: привязать их к устройствам нельзя, и в выборку попали "
                "бы ВСЕ. Проверяйте по индексу composition (audit) или уточните поле устройства." % cfg["device"])
        print("Проверка фильтров: запросов к trisigma в Ingress за окно %d, из них с device_id %d" % (docs, with_dev))
    cands = level1(cli, cfg, t_from, t_to, args.slice_hours, not args.sync)
    print("Уровень 1: кандидатов (запуск есть, запроса в trisigma после него нет): %d" % len(cands))
    if not cands:
        return
    kept, dropped = level2(cli, cfg, cands)
    for d in dropped:
        d["reason"] = "запрос в trisigma найден"
    by = {}
    for d in dropped:
        by[d["found_in"]] = by.get(d["found_in"], 0) + 1
    print("Уровень 2: исключено, потому что запрос в trisigma всё-таки нашёлся: %d %s" % (len(dropped), by or ""))
    print("           останется: %d" % len(kept))
    kept = add_gap(cli, cfg, kept) if kept else kept
    min_gap = int(cfg["min_gap_min"])
    if min_gap > 0:
        warm = [c for c in kept if gap_value(c) is not None and gap_value(c) < min_gap]
        for c in warm:
            c["reason"] = "пауза перед запуском < %d мин (не холодный старт)" % min_gap
        dropped += warm
        kept = [c for c in kept if c not in warm]
        print("Пауза: убрано запусков с паузой меньше %d мин: %d, останется: %d" % (min_gap, len(warm), len(kept)))
    else:
        short = sum(1 for c in kept if gap_value(c) is not None and gap_value(c) < 60)
        print("Пауза перед запуском: у %d из %d меньше 60 мин (возможно, не холодный старт; отфильтровать: "
              "--set min_gap_min=60)" % (short, len(kept)))
    final = kept
    cols = list(FINAL_COLS)
    if cfg["events_index"]:
        final = level3(cli, cfg, kept, t_from, t_end)
        cols += ["events_total", "events_with_experiment", "intersection"]
        yes = [c for c in final if c["intersection"] == "yes"]
        no = sum(1 for c in final if c["intersection"] == "no")
        unk = sum(1 for c in final if c["intersection"] == "unknown")
        print("Уровень 3: пересечение с событиями без эксперимента: да=%d, нет (эксперимент в событиях есть)=%d, "
              "событий нет=%d" % (len(yes), no, unk))
    print("Итог:")
    pref = args.out
    write_csv(pref + "_final.csv", cols, [dict(final_row(c), **{k: c.get(k, "") for k in cols[len(FINAL_COLS):]}) for c in final])
    if cfg["events_index"]:
        write_csv(pref + "_intersection.csv", cols,
                  [dict(final_row(c), **{k: c.get(k, "") for k in cols[len(FINAL_COLS):]}) for c in final if c["intersection"] == "yes"])
    write_csv(pref + "_excluded.csv", EXCL_COLS, [excl_row(c) for c in dropped])
    write_csv(pref + "_level1_all.csv", FINAL_COLS, [final_row(c) for c in cands])


def cmd_audit(cli, cfg, args):
    with open(args.csv, newline="", encoding="utf-8-sig") as f:
        head = f.readline()
        f.seek(0)
        delim = ";" if head.count(";") >= head.count(",") else ","
        rows = list(csv.DictReader(f, delimiter=delim))
    need = {"device_id", "launch_ts_utc"}
    if not rows or not need.issubset(rows[0].keys()):
        die("в CSV нужны колонки device_id и launch_ts_utc (как в старой выгрузке)")
    thr = parse_version(cfg["min_version"])
    cands = []
    for r in rows:
        v = parse_version(r.get("app_version", ""))
        in_scope = bool(v and thr and ((v >= thr) if as_bool(cfg["inclusive"]) else (v > thr)))
        cands.append({"dev": r["device_id"], "uid": r.get("user_id", ""), "first_launch": r["launch_ts_utc"],
                      "platform": r.get("platform", ""), "app_version": r.get("app_version", ""),
                      "in_version_scope": "yes" if in_scope else "no"})
    kept, dropped = level2(cli, cfg, cands)
    verdict = {}
    for c in kept:
        verdict[c["dev"]] = dict(c, verdict="OK: запросов в trisigma после запуска не найдено")
    for c in dropped:
        verdict[c["dev"]] = dict(c, verdict="ОШИБКА: запрос в trisigma был (%s)" % c["found_in"])
    out = []
    for c in cands:
        v = verdict[c["dev"]]
        gap = ""
        if v.get("found_ts"):
            try:
                gap = int((parse_es_time(str(v["found_ts"])) - parse_es_time(c["first_launch"])).total_seconds() // 60)
            except Exception:
                gap = ""
        out.append({"device_id": c["dev"], "user_id": c["uid"], "platform": c["platform"], "app_version": c["app_version"],
                    "in_version_scope": c["in_version_scope"], "launch_ts_utc": c["first_launch"],
                    "verdict": v["verdict"], "found_in": v.get("found_in", ""), "found_ts": v.get("found_ts", ""),
                    "minutes_after_launch": gap, "found_status": v.get("found_status", ""), "found_what": v.get("found_what", "")})
    cols = ["device_id", "user_id", "platform", "app_version", "in_version_scope", "launch_ts_utc", "verdict",
            "found_in", "found_ts", "minutes_after_launch", "found_status", "found_what"]
    bad = sum(1 for r in out if r["verdict"].startswith("ОШИБКА"))
    print("Из %d строк старой выгрузки запрос в trisigma после запуска был у %d." % (len(out), bad))
    by = {}
    for r in out:
        if r["found_in"]:
            by[r["found_in"]] = by.get(r["found_in"], 0) + 1
    if by:
        print("  где нашли: %s" % by)
    mins = sorted(r["minutes_after_launch"] for r in out if r["minutes_after_launch"] != "")
    if mins:
        print("  через сколько минут после запуска (мин/медиана/макс): %s / %s / %s" % (mins[0], mins[len(mins) // 2], mins[-1]))
    write_csv(args.out + "_audit.csv", cols, out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["discover", "sanity", "esql", "run", "audit"])
    ap.add_argument("csv", nargs="?", help="для audit: старая выгрузка CSV")
    ap.add_argument("--es-url", default=os.environ.get("ES_URL"))
    ap.add_argument("--kibana-url", default=os.environ.get("KIBANA_URL"))
    ap.add_argument("--api-key", default=os.environ.get("ES_API_KEY"))
    ap.add_argument("--user", default=os.environ.get("ES_USER"))
    ap.add_argument("--password", default=os.environ.get("ES_PASSWORD"))
    ap.add_argument("-H", "--header", action="append", default=[], help='доп. заголовок, напр. -H "Cookie: sid=..."')
    ap.add_argument("--insecure", action="store_true", help="не проверять TLS-сертификат")
    ap.add_argument("--cacert", help="файл с корпоративным CA")
    ap.add_argument("--from", dest="frm", help="начало окна запусков (UTC), напр. 2026-09-29T00:00:00Z или now-6h")
    ap.add_argument("--to", help="конец окна запусков (UTC)")
    ap.add_argument("--slice-hours", type=float, default=0, help="резать окно на куски по N часов (для больших окон)")
    ap.add_argument("--sync", action="store_true", help="не использовать асинхронный ES|QL")
    ap.add_argument("--no-gate", action="store_true", help="не проверять перед запуском, что запросы к trisigma находятся")
    ap.add_argument("--devtools", action="store_true", help="для esql: обернуть в POST /_query для Dev Tools")
    ap.add_argument("--out", default="trisigma_no_request", help="префикс выходных CSV")
    ap.add_argument("--set", action="append", default=[], metavar="ключ=значение",
                    help="переопределить настройку из CFG (например --set device=device_uuid --set min_version=11.10.0)")
    args = ap.parse_args()
    cfg = dict(CFG)
    for kv in args.set:
        k, sep, v = kv.partition("=")
        if not sep or k not in cfg:
            die("--set ожидает ключ=значение, ключ из: %s" % ", ".join(sorted(cfg)))
        cfg[k] = v
    if args.command == "esql":
        if not (args.frm and args.to):
            die("нужны --from и --to")
        return cmd_esql(None, cfg, args)
    cli = Client(args.es_url, args.kibana_url, args.api_key, args.user, args.password, args.header,
                 args.insecure, args.cacert)
    if args.command in ("run",) and not (args.frm and args.to):
        die("нужны --from и --to")
    if args.command == "audit" and not args.csv:
        die("укажите файл: audit старая_выгрузка.csv")
    {"discover": cmd_discover, "sanity": cmd_sanity, "run": cmd_run, "audit": cmd_audit}[args.command](cli, cfg, args)


if __name__ == "__main__":
    try:
        main()
    except EsError as e:
        die(str(e))

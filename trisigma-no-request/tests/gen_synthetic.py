"""Load synthetic Ingress / trisigma-composition / events logs into a local Elasticsearch and dump the expected answer.

Every device gets one scenario; SCENARIOS documents what a correct selection must (not) return.
"""
import datetime as dt
import json
import random
import sys
import urllib.request
import uuid

ES = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:9200"
OUT = sys.argv[2] if len(sys.argv) > 2 else "expected.json"   # oracle: which device must (not) be selected
rnd = random.Random(42)

T0 = dt.datetime(2026, 9, 29, 0, 0, tzinfo=dt.timezone.utc)      # analysis window start
T1 = dt.datetime(2026, 9, 29, 6, 0, tzinfo=dt.timezone.utc)      # analysis window end (launches counted before it)

SERVICES = ["auth", "cart", "config", "delivery", "loyalty", "menu", "order", "restaurant", "review", "user"]
TRI_FEATURES = "/gateway/trisigma-composition/api/v7/trisigma/features"
TRI_EXPERIMENTS = "/gateway/trisigma-composition/api/v7/trisigma/experiments"

VER = {
    ("android", "new"): "11.10.1.g_20300",
    ("android", "new2"): "11.11.0.r_20400",
    ("android", "edge"): "11.10.0.g_20261",
    ("android", "old"): "11.9.0.g_20241",
    ("ios", "new"): "11.10.1_380",
    ("ios", "new2"): "11.12.3_412",
    ("ios", "edge"): "11.10.0_372",
    ("ios", "old"): "11.9.0_347",
}


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def new_id(platform):
    u = str(uuid.UUID(int=rnd.getrandbits(128), version=4))
    return u.upper() if platform == "ios" else u


TRI_AFTER_LAUNCH = {"normal", "late20", "very_late", "only_comp", "only_comp_unmapped", "failed_tri", "exp_only",
                    "tri_no_platform"}          # scenarios where the device DID send a trisigma request after launching
ingress, comp, events = [], [], []
expected = {}  # device_id -> dict(level1: bool, final: bool, note: str)


def ing(t, dev, user, platform, ver, svc=None, path=None, status=200, method="GET", omit=()):
    d = {
        "@timestamp": iso(t), "device_id": dev, "user_id": user, "platform": platform, "app_version": ver,
        "path": path or f"/gateway/{svc}/api/v7/{svc}/state", "status": status, "method": method,
        "remote_addr": f"10.1.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}",
    }
    for k in omit:
        d.pop(k, None)
    ingress.append(d)


def burst(t, dev, user, platform, ver, n=8, split_at=None, skip=()):
    svcs = [s for s in SERVICES if s not in skip][:n]
    for i, s in enumerate(svcs):
        tt = t + dt.timedelta(milliseconds=150 * i)
        if split_at is not None and i >= split_at:
            tt = tt + dt.timedelta(seconds=30)
        ing(tt, dev, user, platform, ver, svc=s)


def comp_doc(t, dev, upper=False, mapped=True):
    body = {"params": {"participant": {"visitorId": dev, "userId": 1}}}
    d = {"@timestamp": iso(t), "message": "trisigma-composition request " + json.dumps(body)}
    if mapped:
        d["visitor_id"] = dev.upper() if upper else dev.lower()
    comp.append(d)


def tri(t, dev, user, platform, ver, status=200, experiments=False):
    ing(t, dev, user, platform, ver, path=TRI_EXPERIMENTS if experiments else TRI_FEATURES,
        status=status, method="POST" if experiments else "GET")


def t_in_window(minutes_from_start):
    return T0 + dt.timedelta(minutes=minutes_from_start)


def add(scn, platform, vkey, n, level1, final, note, fn, events_mode=None):
    for _ in range(n):
        dev = new_id(platform)
        user = None if scn == "anon_no_tri" else rnd.randint(1000, 90_000_000)
        ver = VER[(platform, vkey)]
        t = t_in_window(rnd.randint(10, 300))
        fn(t, dev, user, platform, ver)
        expected[dev] = {"scenario": scn, "platform": platform, "vkey": vkey, "level1": level1, "final": final, "note": note,
                         "launch": iso(t), "app_version": ver, "user_id": user,
                         "tri_after_launch": scn in TRI_AFTER_LAUNCH}
        if events_mode:
            expected[dev]["events_mode"] = events_mode
            for k in range(3):
                e = {"@timestamp": iso(t + dt.timedelta(minutes=k + 1)), "device_id": dev, "user_id": user, "event": f"evt{k}"}
                if events_mode == "empty":
                    e["experiment"] = ""
                elif events_mode == "filled":
                    e["experiment"] = "AA_pilot_1:control"
                elif events_mode == "mixed":
                    if k == 0:
                        e["experiment"] = "AA_pilot_1:test"
                # events_mode == "missing": field absent
                events.append(e)


def normal(t, dev, user, platform, ver):
    burst(t, dev, user, platform, ver)
    tri(t + dt.timedelta(seconds=2), dev, user, platform, ver)


def never(t, dev, user, platform, ver):
    burst(t, dev, user, platform, ver)


def late20(t, dev, user, platform, ver):
    burst(t, dev, user, platform, ver)
    tri(t + dt.timedelta(minutes=20), dev, user, platform, ver)


def very_late(t, dev, user, platform, ver):
    burst(t, dev, user, platform, ver)
    tri(T1 + dt.timedelta(hours=3), dev, user, platform, ver)     # far after window end + buffer


def only_comp(t, dev, user, platform, ver):
    burst(t, dev, user, platform, ver)
    comp_doc(t + dt.timedelta(seconds=3), dev, upper=False)       # note: lowercased visitor_id even for iOS


def only_comp_unmapped(t, dev, user, platform, ver):
    burst(t, dev, user, platform, ver)
    comp_doc(t + dt.timedelta(seconds=3), dev, mapped=False)      # id only inside the message text


def tri_before_only(t, dev, user, platform, ver):
    tri(t - dt.timedelta(hours=2), dev, user, platform, ver)      # previous session
    burst(t, dev, user, platform, ver)


def failed_tri(t, dev, user, platform, ver):
    burst(t, dev, user, platform, ver)
    tri(t + dt.timedelta(seconds=2), dev, user, platform, ver, status=502)


def exp_only(t, dev, user, platform, ver):
    burst(t, dev, user, platform, ver)
    tri(t + dt.timedelta(minutes=5), dev, user, platform, ver, experiments=True)


def tri_no_platform(t, dev, user, platform, ver):
    burst(t, dev, user, platform, ver)
    ing(t + dt.timedelta(seconds=2), dev, user, platform, ver, path=TRI_FEATURES, omit=("platform", "app_version"))


def short_gap(t, dev, user, platform, ver):
    ing(t - dt.timedelta(minutes=10), dev, user, platform, ver, svc="menu")
    burst(t, dev, user, platform, ver)


def cold_gap(t, dev, user, platform, ver):
    ing(t - dt.timedelta(minutes=180), dev, user, platform, ver, svc="menu")
    burst(t, dev, user, platform, ver)


def low_fanout(t, dev, user, platform, ver):
    burst(t, dev, user, platform, ver, n=3)


def split_burst(t, dev, user, platform, ver):
    t = t.replace(second=40, microsecond=0)
    burst(t, dev, user, platform, ver, n=8, split_at=4)          # 4 services in minute m, 4 in minute m+1


def web(t, dev, user, platform, ver):
    burst(t, dev, user, "web", "1.0", n=9)


def launch_after_window(t, dev, user, platform, ver):
    burst(T1 + dt.timedelta(minutes=45), dev, user, platform, ver)   # launch outside the analysed window


# --- scenarios: (name, platform, version key, count, level1?, final?, note, builder, events_mode)
add("normal", "android", "new", 40, False, False, "has trisigma", normal)
add("normal", "ios", "new", 40, False, False, "has trisigma", normal)
add("never_new", "android", "new", 6, True, True, "true positive", never, "missing")
add("never_new", "android", "new2", 3, True, True, "true positive, 11.11", never, "empty")
add("never_new", "ios", "new", 5, True, True, "true positive iOS", never, "missing")
add("never_new", "ios", "new2", 2, True, True, "true positive iOS 11.12", never, "filled")     # events say experiment present -> dropped by intersection
add("never_new", "android", "new", 2, True, True, "true positive, mixed events", never, "mixed")
add("anon_no_tri", "ios", "new", 3, True, True, "unauthorised, no user_id", never, "missing")
add("never_edge", "android", "edge", 3, "edge", "edge", "exactly 11.10.0: only with --inclusive", never)
add("never_edge", "ios", "edge", 2, "edge", "edge", "exactly 11.10.0: only with --inclusive", never)
add("never_old", "android", "old", 4, False, False, "11.9.0 out of scope", never)
add("never_old", "ios", "old", 3, False, False, "11.9.0 out of scope", never)
add("late20", "android", "new", 5, False, False, "trisigma 20 min later, inside window", late20)
add("very_late", "android", "new", 4, True, False, "trisigma 3h after window end: Level 1 false positive, Level 2 removes", very_late)
add("only_comp", "ios", "new", 4, True, False, "request only visible in composition index (lowercased id)", only_comp)
add("only_comp", "android", "new", 3, True, False, "request only visible in composition index", only_comp)
add("only_comp_unmapped", "ios", "new", 2, True, False, "id only inside composition message text", only_comp_unmapped)
add("tri_before_only", "android", "new", 3, True, True, "trisigma only BEFORE the launch", tri_before_only, "missing")
add("failed_tri", "android", "new", 4, False, False, "trisigma request answered 502 -> still a request", failed_tri)
add("exp_only", "ios", "new", 3, False, False, "only /experiments call", exp_only)
add("tri_no_platform", "android", "new", 3, False, False, "trisigma row without platform/app_version fields", tri_no_platform)
add("tri_no_platform", "ios", "new", 2, False, False, "trisigma row without platform/app_version fields", tri_no_platform)
add("short_gap", "android", "new", 3, True, True, "gap 10 min before the burst", short_gap)
add("cold_gap", "ios", "new", 3, True, True, "gap 180 min before the burst", cold_gap)
add("low_fanout", "android", "new", 5, False, False, "3 services: not a launch", low_fanout)
add("split_burst", "android", "new", 3, False, False, "burst split across minute boundary: known limitation", split_burst)
add("web", "android", "new", 4, False, False, "web traffic", web)
add("late_launch", "ios", "new", 3, False, False, "launch after window end", launch_after_window)

# --- some background noise: devices with a single request
for _ in range(200):
    p = rnd.choice(["ios", "android"])
    dev = new_id(p)
    ing(T0 + dt.timedelta(minutes=rnd.randint(0, 400)), dev, rnd.randint(1, 10**7), p, VER[(p, "new")], svc=rnd.choice(SERVICES))

MAPPINGS = {
    "mpback-k8s-ingress-2026.09.29": {"properties": {
        "@timestamp": {"type": "date"}, "device_id": {"type": "keyword"}, "user_id": {"type": "long"},
        "platform": {"type": "keyword"}, "app_version": {"type": "keyword"}, "path": {"type": "keyword"},
        "status": {"type": "integer"}, "method": {"type": "keyword"}, "remote_addr": {"type": "ip"}}},
    "mpback-k8s-trisigma-composition-2026.09.29": {"properties": {
        "@timestamp": {"type": "date"}, "message": {"type": "text"}, "visitor_id": {"type": "keyword"}}},
    "mpback-k8s-events-2026.09.29": {"properties": {
        "@timestamp": {"type": "date"}, "device_id": {"type": "keyword"}, "user_id": {"type": "long"},
        "event": {"type": "keyword"}, "experiment": {"type": "keyword"}}},
}
DATA = {
    "mpback-k8s-ingress-2026.09.29": ingress,
    "mpback-k8s-trisigma-composition-2026.09.29": comp,
    "mpback-k8s-events-2026.09.29": events,
}


def call(method, path, body=None, ndjson=False):
    data = None
    if body is not None:
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
    req = urllib.request.Request(ES + path, data=data, method=method,
                                 headers={"Content-Type": "application/x-ndjson" if ndjson else "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=120).read())


for idx, mapping in MAPPINGS.items():
    try:
        call("DELETE", "/" + idx)
    except Exception:
        pass
    call("PUT", "/" + idx, {"settings": {"number_of_shards": 1, "number_of_replicas": 0}, "mappings": mapping})
    docs = DATA[idx]
    for i in range(0, len(docs), 2000):
        lines = []
        for d in docs[i:i + 2000]:
            lines.append(json.dumps({"index": {}}))
            lines.append(json.dumps(d))
        r = call("POST", f"/{idx}/_bulk?refresh=true", "\n".join(lines) + "\n", ndjson=True)
        assert not r["errors"], r
    print(idx, len(docs), "docs")

json.dump(expected, open(OUT, "w"), indent=1)

# an export in the format of the old CSV (input for `audit`); web traffic and out-of-window launches are not in it
import csv
with open(OUT.replace(".json", "_old_export.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f, delimiter=";")
    w.writerow(["user_id", "device_id", "platform", "app_version", "launch_ts_utc", "gap_before_min",
                "services_in_fanout", "fanout_services", "server_side_check"])
    for dev, v in expected.items():
        if v["scenario"] in ("web", "late_launch"):
            continue
        w.writerow([v["user_id"] or "", dev, v["platform"], v["app_version"], v["launch"], ">8h", 8,
                    "auth cart config delivery loyalty menu order restaurant", "fanout_ok_no_trisigma_call"])
print("devices:", len(expected))

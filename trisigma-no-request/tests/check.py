"""Compare the CSVs written by find_no_trisigma.py with the oracle written by gen_synthetic.py.

usage: check.py <expected.json> <output-prefix> [strict|inclusive|gap60|ok_only|audit]
"""
import csv
import json
import sys

expected_path, prefix = sys.argv[1], sys.argv[2]
mode = sys.argv[3] if len(sys.argv) > 3 else "strict"       # strict | inclusive | gap60
exp = json.load(open(expected_path))


def load(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f, delimiter=";"))


def want(key):
    out = set()
    for dev, v in exp.items():
        x = v[key]
        if x is True or (x == "edge" and mode == "inclusive") or (mode == "ok_only" and v["scenario"] in ("failed_tri", "tri_401")):
            out.add(dev)
    return out


ok = True

if mode == "audit":                     # verdicts of `audit` on an old-style export
    rows = load(prefix + "_audit.csv")
    bad = 0
    for r in rows:
        want_err = exp[r["device_id"]]["tri_after_launch"]
        got_err = r["verdict"].startswith("\u041e\u0428\u0418\u0411\u041a\u0410")   # "ОШИБКА"
        if want_err != got_err:
            bad += 1
            print("   mismatch:", r["device_id"], exp[r["device_id"]]["scenario"], r["verdict"])
    print("OK " if not bad else "FAIL", "audit verdicts:", len(rows), "rows,", bad, "mismatches")
    sys.exit(1 if bad else 0)


def compare(name, got, expected):
    global ok
    miss, extra = expected - got, got - expected
    status = "OK " if not miss and not extra else "FAIL"
    if miss or extra:
        ok = False
    print(f"{status} {name}: got {len(got)}, expected {len(expected)}")
    for d in sorted(miss):
        print("   missing:", d, exp.get(d))
    for d in sorted(extra):
        print("   extra  :", d, exp.get(d))


l1 = {r["device_id"] for r in load(prefix + "_level1_all.csv")}
final_rows = load(prefix + "_final.csv")
final = {r["device_id"] for r in final_rows}
excl_rows = load(prefix + "_excluded.csv")
excl = {r["device_id"] for r in excl_rows}
warm = {d for d, v in exp.items() if v["scenario"] == "short_gap"}
want_final = want("final") - (warm if mode == "gap60" else set())
compare("level1 candidates", l1, want("level1"))
compare("final", final, want_final)
compare("excluded (level2 + gap filter)", excl, want("level1") - want_final)
reasons = {r["reason"] for r in excl_rows}
print("     exclusion reasons:", reasons)

# gap_before_min sanity
kinds = {"short_gap": (8, 10), "cold_gap": (178, 180), "tri_before_only": (118, 120)}
bad = 0
for r in final_rows:
    sc = exp[r["device_id"]]["scenario"]
    g = r["gap_before_min"]
    if sc in kinds:
        lo, hi = kinds[sc]
        if not (g.lstrip("-").isdigit() and lo <= int(g) <= hi):
            bad += 1; print("   gap mismatch", sc, g)
    elif sc in ("never_new", "anon_no_tri", "never_edge") and g != ">12ч":
        bad += 1; print("   gap mismatch", sc, g)
print("OK " if not bad else "FAIL", "gap_before_min values,", bad, "mismatches")
ok = ok and not bad
sys.exit(0 if ok else 1)

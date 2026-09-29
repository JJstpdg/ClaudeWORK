#!/usr/bin/env bash
# Проверка скрипта на локальном Elasticsearch с синтетическими логами (ничего не трогает в вашем кластере).
#
# 1) Поднимите одноузловой Elasticsearch 8.14+ (ES|QL нужен для уровня 1), например:
#      docker run --rm -p 9200:9200 -e discovery.type=single-node -e xpack.security.enabled=false \
#        -e ES_JAVA_OPTS="-Xms1g -Xmx1g" docker.elastic.co/elasticsearch/elasticsearch:8.19.22
# 2) ES_URL=http://localhost:9200 ./tests/run_local.sh
#
# gen_synthetic.py грузит в ES три индекса (Ingress, trisigma-composition, события) со сценариями «нормальный запуск»,
# «нет запроса», «запрос позже», «запрос только в composition», «запрос без платформы/версии» и т.д. и пишет эталон;
# check.py сверяет с ним результат run/audit. Код возврата 0 = всё совпало.
set -euo pipefail
ES_URL=${ES_URL:-http://localhost:9200}
cd "$(dirname "$0")"
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
S=../find_no_trisigma.py
W=(--from 2026-09-29T00:00:00Z --to 2026-09-29T06:00:00Z)

python3 gen_synthetic.py "$ES_URL" "$OUT/expected.json"

echo "== версия строго > 11.10.0 (по умолчанию), с пересечением по событиям"
python3 $S --es-url "$ES_URL" sanity "${W[@]}" > /dev/null
python3 $S --es-url "$ES_URL" run "${W[@]}" --out "$OUT/strict" --set events_index='mpback-k8s-events*' > /dev/null
python3 check.py "$OUT/expected.json" "$OUT/strict" strict

echo "== версия >= 11.10.0"
python3 $S --es-url "$ES_URL" run "${W[@]}" --out "$OUT/incl" --set inclusive=true > /dev/null
python3 check.py "$OUT/expected.json" "$OUT/incl" inclusive

echo "== окно кусками по 1.5 часа"
python3 $S --es-url "$ES_URL" run "${W[@]}" --out "$OUT/sliced" --slice-hours 1.5 > /dev/null
python3 check.py "$OUT/expected.json" "$OUT/sliced" strict

echo "== только холодные запуски (пауза >= 60 мин)"
python3 $S --es-url "$ES_URL" run "${W[@]}" --out "$OUT/gap" --set min_gap_min=60 > /dev/null
python3 check.py "$OUT/expected.json" "$OUT/gap" gap60
echo "== audit: перепроверка выгрузки в формате старой"
python3 $S --es-url "$ES_URL" audit "$OUT/expected_old_export.csv" --out "$OUT/audit" > /dev/null
python3 check.py "$OUT/expected.json" "$OUT/audit" audit
echo "ALL OK"

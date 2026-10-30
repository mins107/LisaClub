"""민원 키워드의 시즌(달) 분석. 어느 달에 늘어나는 키워드인지, 같은 시기에 함께 늘어나는(상관관계가 높은) 키워드는 무엇인지 찾는다.

입력은 [(접수 날짜, [키워드...])]. 키워드는 분류 때 민원에서 찾은 말(rules.DEPARTMENTS의 kw)이다. 한 민원 안에서는 키워드를 한 번만 센다.
기준값은 학교가 정한 것이 아니라 임의 시작값이다. 데이터가 적으면 판단하지 않는다.
"""
from collections import Counter
from math import sqrt

MIN_MONTHS_OF_DATA = 3     # 서로 다른 (연, 월)이 이만큼은 있어야 분석한다
MIN_KEYWORD_CASES = 5      # 키워드가 이만큼은 나와야 후보가 된다
MIN_LIFT = 1.5             # 한 달 쪽 쏠림: (키워드 중 그 달 비중) / (전체 민원 중 그 달 비중)
MIN_PEAK_SHARE = 0.35      # 키워드 접수의 이 비율 이상이 가장 많은 달에 몰려야 시즌 키워드
MIN_CORR = 0.6             # 같이 늘어나는 키워드로 보는 상관계수
HEATMAP_ROWS = 12


def _pearson(a, b):
    n = len(a)
    if n < 3:
        return 0.0
    ma, mb = sum(a) / n, sum(b) / n
    va, vb = sum((x - ma) ** 2 for x in a), sum((y - mb) ** 2 for y in b)
    if va == 0 or vb == 0:
        return 0.0
    return sum((x - ma) * (y - mb) for x, y in zip(a, b)) / sqrt(va * vb)


def season_report(rows, today=None):
    """반환: {enough, months_of_data, total, monthly_totals[12], keywords:[{keyword, counts[12], total, peak_month, lift, share,
    seasonal, related:[{keyword, r}]}]}. 달은 1~12(여러 해의 같은 달을 합친다). today를 주면 이번 달 민원은 분석에서 뺀다. keywords는 시즌 키워드가 앞, 그다음 많이 나온 순."""
    if today:       # 아직 끝나지 않은 이번 달은 건수가 적거나 치우쳐 있어 제외한다
        rows = [(d, k) for d, k in rows if (d.year, d.month) != (today.year, today.month)]
    total = len(rows)
    ym = {(d.year, d.month) for d, _ in rows}
    T = [0] * 12
    C = {}
    for d, kws in rows:
        T[d.month - 1] += 1
        for k in set(kws):
            C.setdefault(k, [0] * 12)[d.month - 1] += 1
    out = {"enough": len(ym) >= MIN_MONTHS_OF_DATA and total > 0, "months_of_data": len(ym), "total": total,
           "monthly_totals": T, "keywords": []}
    if not out["enough"]:
        return out
    months = [m for m in range(12) if T[m] > 0]
    share = {k: [C[k][m] / T[m] for m in months] for k in C}       # 달 전체 민원 대비 비율(접수량 차이를 걷어낸 흐름)
    cand = [k for k in C if sum(C[k]) >= MIN_KEYWORD_CASES]
    items = []
    for k in cand:
        n = sum(C[k])
        pm = max(range(12), key=lambda m: C[k][m])
        sh = C[k][pm] / n
        lift = sh / (T[pm] / total)
        seasonal = lift >= MIN_LIFT and sh >= MIN_PEAK_SHARE
        related = sorted(({"keyword": o, "r": round(_pearson(share[k], share[o]), 2)} for o in cand if o != k
                          and _pearson(share[k], share[o]) >= MIN_CORR), key=lambda x: -x["r"])[:3]
        items.append({"keyword": k, "counts": C[k], "total": n, "peak_month": pm + 1, "lift": round(lift, 2),
                      "share": round(sh, 2), "seasonal": seasonal, "related": related})
    items.sort(key=lambda x: (not x["seasonal"], -x["total"]))
    out["keywords"] = items[:HEATMAP_ROWS]
    out["all_seasonal"] = [i for i in items if i["seasonal"]]
    return out


def cooccurrence(rows, keyword, top=3):
    """같은 민원에 keyword와 함께 나온 키워드 상위(건수). 상관계수와 달리 한 민원 안에서의 동반 출현이다."""
    c = Counter(k for _, kws in rows if keyword in kws for k in set(kws) if k != keyword)
    return c.most_common(top)

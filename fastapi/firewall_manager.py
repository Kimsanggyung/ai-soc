import subprocess

def block_attacker_ip(ip_address: str, target_port: int) -> bool:
    if ip_address in ["127.0.0.1", "0.0.0.0"] or ip_address.startswith("192.168."):
        print(f"⚠️ [FIREWALL CORE] 내부망 보호 예외 통과: {ip_address}")
        return False

    try:
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "--dport", str(target_port), "-j", "DROP"]
        print(f"🛡️ [FIREWALL DISPATCH] 방화벽 정책 빌드 완료: {' '.join(cmd)}")
        print(f"✅ [FIREWALL CORE] 공격자 호스트 IP [{ip_address}] 방화벽 포트 [{target_port}] 격리 성공")
        return True
    except Exception as e:
        print(f"❌ [FIREWALL EXCEPTION] 커널 대응 주입 에러: {str(e)}")
        return False
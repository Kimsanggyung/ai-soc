import { useState } from 'react';

// 포워더 및 백엔드 파이프라인에서 인입되는 데이터 규격 명시
interface SecurityEvent {
  event_id: number;
  timestamp: string;
  src_ip: string;
  dest_ip: string;
  proto: string;
  alert_msg: string;
  sid: number;
  payload_raw: string;
  http_info: {
    uri: string;
    user_agent: string;
  };
  status: string;
  risk_score: number;
  mitigation_action: string;
  ai_report: string;
}

export default function App() {
  const [activeMenu, setActiveMenu] = useState('dashboard');

  // 💡 실시간 인입된 가상 로그 데이터셋 정의 (화면 인터랙션 연동용)
  const [events] = useState<SecurityEvent[]>([
    {
      event_id: 104,
      timestamp: "2026-07-09 23:03:08",
      src_ip: "172.20.0.100",
      dest_ip: "172.20.0.20",
      proto: "TCP",
      alert_msg: "WEB Sensitive File Access etc-passwd",
      sid: 1000004,
      payload_raw: "GET /api/v1/kdx/data-trading/market?file=../../../../etc/passwd HTTP/1.1\nHost: 172.20.0.20\nConnection: keep-alive\nUpgrade-Insecure-Requests: 1",
      http_info: {
        uri: "/api/v1/kdx/data-trading/market",
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) WebKit/537.36 (KHTML, like Gecko) PathTraversalScanner/v1.2"
      },
      status: "COMPLETED",
      risk_score: 95.0, // 💡 연동을 위한 점수 세팅
      mitigation_action: "DROP",
      ai_report: "## 침해사고 분석 보고서\n\n### [1] 위협 식별\n- **공격 유형**: Path Traversal (디렉터리 탐색 우회)\n- **위험도**: 95.0 (Critical)\n\n### [2] 상세 분석\n외부 자산(`172.20.0.100`)으로부터 리눅스 핵심 민감 파일인 `/etc/passwd` 파일에 접근하려는 URI 악성 시그니처가 최전방 Suricata IDS에 적발되었습니다.\n\n### [3] 대응 조치\n인프라 무결성을 위해 해당 리스크 식별 즉시 Gateway Firewall 체인을 업데이트하여 해당 IP를 30분간 차단(DROP) 조치했습니다."
    },
    {
      event_id: 103,
      timestamp: "2026-07-09 23:03:04",
      src_ip: "172.20.0.100",
      dest_ip: "172.20.0.20",
      proto: "TCP",
      alert_msg: "WEB Path Traversal Attempt in URI",
      sid: 1000003,
      payload_raw: "GET /api/v1/dashboard/overview?dir=..\\..\\windows\\win.ini HTTP/1.1\nHost: 172.20.0.20\nUser-Agent: Nikto Scanner\nAccept: */*",
      http_info: {
        uri: "/api/v1/dashboard/overview",
        user_agent: "Mozilla/5.0 (Nikto Vulnerability Scanner v2.1.5)"
      },
      status: "COMPLETED",
      risk_score: 90.0,
      mitigation_action: "DROP",
      ai_report: "## 침해사고 분석 보고서\n\n### [1] 위협 식별\n- **공격 유형**: Path Traversal injection\n- **위험도**: 90.0 (High)\n\n### [2] 상세 분석\n`Nikto` 취약점 스캐너 도구를 활용한 무작위 엔드포인트 탐색 행위가 식별되었습니다. 웹 애플리케이션 상위 디렉터리 구조 탈취를 목적으로 윈도우 시스템 설정값 탐색 시그니처가 매칭되었습니다.\n\n### [3] 대응 조치\nSOAR 자동화 엔진 규칙에 의거하여 위협 유입 세션을 즉각 강제 단절 처리를 완료했습니다."
    },
    {
      event_id: 102,
      timestamp: "2026-07-09 23:02:59",
      src_ip: "172.20.0.1",
      dest_ip: "172.20.0.20",
      proto: "TCP",
      alert_msg: "WEB Sensitive File Access etc-passwd",
      sid: 1000002,
      payload_raw: "POST /api/v1/metric/logs HTTP/1.1\nHost: 172.20.0.20\nContent-Type: application/json\n\n{\"attack\": \"cat /etc/passwd\"}",
      http_info: {
        uri: "/api/v1/metric/logs",
        user_agent: "curl/7.79.1"
      },
      status: "COMPLETED",
      risk_score: 88.0,
      mitigation_action: "DROP",
      ai_report: "## 침해사고 분석 보고서\n\n### [1] 위협 요약\n- **탐지 유형**: 파일 접근 권한 오용 공격\n- **대응 조치**: DROP (차단 완료)\n\n### [2] 기술적 평가\nL7 패킷 원본 페이로드 디코딩 분석 결과, 본체 내부 API 인입 게이트웨이 파이프라인 상에서 비인가 시스템 명령어 형태 of 인젝션 구문이 연속 탐지되어 차단 처리되었습니다."
    },
    {
      event_id: 101,
      timestamp: "2026-07-09 23:02:55",
      src_ip: "172.20.0.1",
      dest_ip: "172.20.0.20",
      proto: "TCP",
      alert_msg: "WEB Path Traversal Attempt in URI",
      sid: 1000001,
      payload_raw: "GET /api/v1/dashboard/event/101?path=/../etc/hosts HTTP/1.1\nHost: 172.20.0.20\nUser-Agent: Pycurl/7.43.0.6",
      http_info: {
        uri: "/api/v1/dashboard/event/101",
        user_agent: "Mozilla/5.0 (Suricata Live Alert Custom Forwarder)"
      },
      status: "COMPLETED",
      risk_score: 50.0,
      mitigation_action: "DROP",
      ai_report: "## 침해사고 분석 보고서\n1호기 침해사고 보고서\n\n- **침해사고 유형**: Path Traversal injection\n- **IP 주소**: 172.20.0.1\n- **포트**: 80\n- **신뢰도 점수**: 50.0%\n- **대응 조치**: DROP (차단)\n- **CVE**: CVE-2026-9999 (원격 코드 실행 / 경로 탐색)\n- **탐지 시그니처**: Suricata Signature: WEB Path Traversal Attempt in URI\n- **침해된 시스템**: 1호기"
    }
  ]);

  // 💡 [핵심] 현재 어떤 로그가 선택되었는지 제어하는 리액트 State (기본값: 최신 ID 104번)
  const [selectedEventId, setSelectedEventId] = useState<number>(104);

  // 선택된 ID에 매칭되는 진짜 객체를 동적으로 추출
  const currentEvent = events.find(e => e.event_id === selectedEventId) || events[0];

  return (
    <div className="flex h-screen bg-[#070a13] text-[#c9d1d9] font-sans antialiased">
      {/* 1. 사이드바 내비게이션 */}
      <aside className="w-64 bg-[#010306] border-r border-[#1f293d] flex flex-col justify-between z-10">
        <div>
          <div className="p-6 border-b border-[#1f293d] bg-[#02050a]">
            <div className="flex items-center gap-3">
              <span className="text-xl animate-pulse">🛡️</span>
              <h1 className="text-xl font-black tracking-widest text-red-500 font-mono">
                AI-SOC PLATFORM
              </h1>
            </div>
            <p className="text-xs text-slate-300 font-bold mt-2 pl-1">
              지능형 통합 보안 관제 시스템
            </p>
          </div>
          
          <nav className="p-4 space-y-2">
            <button 
              onClick={() => setActiveMenu('dashboard')}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-bold transition-colors ${activeMenu === 'dashboard' ? 'bg-[#1b2336] text-white border-l-4 border-red-500 shadow-md' : 'text-slate-300 hover:bg-[#0f1524] hover:text-white'}`}
            >
              📊 관제 대시보드
            </button>
            <button 
              onClick={() => setActiveMenu('monitor')}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-bold transition-colors ${activeMenu === 'monitor' ? 'bg-[#1b2336] text-white border-l-4 border-red-500 shadow-md' : 'text-slate-300 hover:bg-[#0f1524] hover:text-white'}`}
            >
              🔴 실시간 전투 모니터링
            </button>
            <button 
              onClick={() => setActiveMenu('api-security')}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-bold transition-colors ${activeMenu === 'api-security' ? 'bg-[#1b2336] text-white border-l-4 border-red-500 shadow-md' : 'text-slate-300 hover:bg-[#0f1524] hover:text-white'}`}
            >
              🔑 API 취약점 진단
            </button>
          </nav>
        </div>
        <div className="p-4 border-t border-[#1f293d] text-xs text-slate-400 font-bold text-center bg-[#010306]">
          TEAM LEADER SYSTEM v1.0
        </div>
      </aside>

      {/* 2. 메인 콘텐츠 영역 */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* 상단 헤더 */}
        <header className="h-16 bg-[#010306] border-b border-[#1f293d] flex items-center justify-between px-8">
          <div className="text-sm font-bold text-slate-300 flex items-center gap-2">
            <span>🛡️ AI-SOC 지능형 통합 보안 자동 관제 플랫폼</span>
            <span className="text-gray-500 text-xs hidden md:inline">| Suricata IDS + Llama 3.1 Real-Time SOAR Pipeline</span>
          </div>
          <div className="flex items-center gap-4 text-sm text-slate-300">
            <span className="bg-green-950/40 border border-green-700/60 text-green-400 px-3 py-1 rounded-full text-xs font-bold flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 bg-green-400 rounded-full animate-ping"></span>
              파이프라인 연결됨
            </span>
            <span className="text-xs font-mono text-gray-400">System Time: 오후 11:03:50</span>
          </div>
        </header>

        {/* 메인 뷰 패널 */}
        <main className="flex-1 overflow-y-auto p-6 space-y-6 bg-[#070a13]">
          
          {/* TAB 1: 종합 관제 대시보드 */}
          {activeMenu === 'dashboard' && (
            <>
              {/* 💡 [수정] 기획안 동기화를 위한 상단 KPI 5분할 카드 그리드 */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
                <div className="bg-[#0b0f19] border border-[#1b2336] p-4 rounded-xl flex items-center gap-4">
                  <div className="p-2.5 bg-red-950/40 text-red-400 rounded-lg border border-red-900/50 text-lg">⚠️</div>
                  <div>
                    <div className="text-[11px] font-bold text-gray-400 uppercase">누적 탐지 위협 건수</div>
                    <div className="text-2xl font-black text-white mt-0.5 font-mono">4</div>
                  </div>
                </div>
                <div className="bg-[#0b0f19] border border-[#1b2336] p-4 rounded-xl flex items-center gap-4">
                  <div className="p-2.5 bg-orange-950/40 text-orange-400 rounded-lg border border-orange-900/50 text-lg">🚫</div>
                  <div>
                    <div className="text-[11px] font-bold text-gray-400 uppercase">자동 방화벽 차단(DROP)</div>
                    <div className="text-2xl font-black text-white mt-0.5 font-mono">4</div>
                  </div>
                </div>
                <div className="bg-[#0b0f19] border border-[#1b2336] p-4 rounded-xl flex items-center gap-4">
                  <div className="p-2.5 bg-green-950/40 text-green-400 rounded-lg border border-green-900/50 text-lg">🎯</div>
                  <div>
                    <div className="text-[11px] font-bold text-gray-400 uppercase">네트워크 위협 탐지율</div>
                    <div className="text-2xl font-black text-green-400 mt-0.5 font-mono">98.2%</div>
                  </div>
                </div>
                <div className="bg-[#0b0f19] border border-[#1b2336] p-4 rounded-xl flex items-center gap-4">
                  <div className="p-2.5 bg-blue-950/40 text-blue-400 rounded-lg border border-blue-900/50 text-lg">⚡</div>
                  <div>
                    <div className="text-[11px] font-bold text-gray-400 uppercase">평균 자동화 대응 (MTTR)</div>
                    <div className="text-2xl font-black text-blue-400 mt-0.5 font-mono">3.8s</div>
                  </div>
                </div>
                {/* 💡 [추가] PDF 4페이지 Security Context DB 정보 가시화 영역 */}
                <div className="bg-[#0b0f19] border border-[#1b2336] p-4 rounded-xl flex items-center gap-4 border-l-4 border-yellow-600">
                  <div className="p-2.5 bg-yellow-950/40 text-yellow-400 rounded-lg border border-yellow-900/50 text-lg">🗄️</div>
                  <div>
                    <div className="text-[11px] font-bold text-yellow-500 uppercase tracking-tight">Security Context DB</div>
                    <div className="text-xl font-black text-white mt-0.5 font-mono">1,425 <span className="text-[10px] text-gray-400 font-normal">개</span></div>
                  </div>
                </div>
              </div>

              {/* 하단 대시보드 2단 레이아웃 (좌측 리스트 - 우측 정밀 분석창) */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                {/* 좌측: 위협 스트리밍 리스트 */}
                <div className="lg:col-span-4 bg-[#0b0f19] border border-[#1b2336] p-4 rounded-xl flex flex-col h-[520px]">
                  <div className="flex justify-between items-center mb-3">
                    <h3 className="text-xs font-black tracking-wider text-white uppercase flex items-center gap-1.5">💥 위협 스트리밍 리스트 (선택형)</h3>
                    <span className="text-[10px] text-gray-500 font-medium animate-pulse">실시간 갱신 중</span>
                  </div>
                  
                  <div className="flex-1 space-y-2 overflow-y-auto pr-1">
                    {events.map((e) => (
                      <div 
                        key={e.event_id}
                        onClick={() => setSelectedEventId(e.event_id)}
                        className={`p-3 rounded-lg border text-left cursor-pointer transition-all ${selectedEventId === e.event_id ? 'bg-[#151d30] border-blue-500 shadow-md scale-[0.99]' : 'bg-[#0e1424] border-[#1b2336] hover:bg-[#12192c]'}`}
                      >
                        <div className="flex justify-between items-center text-[10px] font-mono text-gray-400">
                          <span className={`${selectedEventId === e.event_id ? 'text-blue-400 font-bold' : 'text-gray-500'}`}>ID: {e.event_id}</span>
                          <span>{e.timestamp}</span>
                        </div>
                        <h4 className="text-xs font-bold text-slate-200 mt-1 truncate">{e.alert_msg}</h4>
                        <div className="flex justify-between items-center mt-2 text-[10px] font-mono">
                          <span className="text-gray-500">🌐 {e.src_ip}</span>
                          <span className="px-1.5 py-0.5 bg-red-950/60 text-red-400 border border-red-900/60 rounded text-[9px] font-bold">DROP</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* 우측: 정밀 분석 파트 (상단 패킷 분석 + 하단 LLM 보고서) */}
                <div className="lg:col-span-8 flex flex-col space-y-4 h-[520px]">
                  
                  {/* 심층 패킷 페이로드 분석창 */}
                  <div className="bg-[#0b0f19] border border-[#1b2336] p-4 rounded-xl">
                    <h3 className="text-xs font-black text-white mb-2.5 font-mono flex items-center gap-1.5">
                      <span>{"</>"}</span> 심층 패킷 페이로드 분석 (DPI & HTTP Context)
                    </h3>
                    
                    <div className="bg-[#040711] border border-[#161b26] p-3 rounded text-[11px] font-mono text-yellow-500 max-h-24 overflow-y-auto whitespace-pre-wrap text-left">
                      <div className="text-orange-400 font-black mb-1">[RAW FLOW PAYLOAD]</div>
                      {currentEvent.payload_raw}
                    </div>

                    {/* 💡 [점수 추가 영역] sm:grid-cols-4를 5로 확장하고, 마지막 컬럼에 AI 위험도 라벨을 단 한 줄도 훼손하지 않고 정밀 결합했습니다. */}
                    <div className="grid grid-cols-2 sm:grid-cols-5 gap-4 mt-3 text-[11px] font-mono text-left border-t border-[#1b2336]/60 pt-3 items-center">
                      <div><span className="text-gray-500">Source IP:</span> <span className="text-slate-300 font-bold">{currentEvent.src_ip}</span></div>
                      <div><span className="text-gray-500">Protocol:</span> <span className="text-blue-400 font-bold">{currentEvent.proto}</span></div>
                      <div className="col-span-1 sm:col-span-2"><span className="text-gray-500">Request URI:</span> <span className="text-green-400 font-bold truncate inline-block max-w-[130px] align-bottom">{currentEvent.http_info.uri}</span></div>
                      {/* 동적 AI 위험도 예측 점수 라벨 컴포넌트 추가 */}
                      <div className="text-right font-sans font-black text-red-500 text-xs tracking-tight bg-red-950/40 border border-red-900/40 px-2 py-0.5 rounded flex justify-end items-center gap-1">
                        <span className="text-[10px] text-gray-400 font-normal">AI Risk:</span> {currentEvent.risk_score.toFixed(1)}
                      </div>
                    </div>
                  </div>

                  {/* Llama 3.1 실시간 침해분석 기술 보고서 */}
                  <div className="flex-1 bg-[#0b0f19] border border-[#1b2336] p-4 rounded-xl flex flex-col overflow-hidden">
                    <div className="flex justify-between items-center border-b border-[#1b2336] pb-2 mb-2">
                      <h3 className="text-xs font-black text-white flex items-center gap-1.5">📄 Llama 3.1 실시간 침해사고 분석 기술 보고서</h3>
                      <span className="text-[10px] font-mono bg-red-950/40 text-red-400 px-2 py-0.5 border border-red-900/50 rounded font-bold">대응 상태: {currentEvent.mitigation_action}</span>
                    </div>
                    
                    <div className="flex-1 overflow-y-auto text-left text-xs font-mono bg-[#040711] p-4 rounded border border-[#161b26] whitespace-pre-wrap text-slate-300 leading-relaxed">
                      {currentEvent.ai_report}
                    </div>
                  </div>

                </div>

              </div>
            </>
          )}

          {/* TAB 2: 실시간 전투 모니터링 */}
          {activeMenu === 'monitor' && (
            <div className="bg-[#0b0f19] border border-[#1b2336] p-6 rounded-xl space-y-6">
              <div className="flex justify-between items-center border-b border-[#1b2336] pb-4">
                <div>
                  <h2 className="text-lg font-bold text-white">🔴 Red Team 공격 vs 🔵 Blue Team 방어 실시간 교전 보드</h2>
                  <p className="text-xs text-gray-400 mt-1">`monitor.py` 엔진 파이프라인 실시간 패킷 파싱 모니터</p>
                </div>
                <span className="bg-red-900/40 text-red-400 px-3 py-1 rounded text-xs font-mono border border-red-700 animate-pulse">● LIVE STREAMING</span>
              </div>
              
              <div className="bg-[#04060b] p-6 rounded-xl border border-[#1b2336] font-mono text-xs space-y-2 h-[450px] overflow-y-auto text-green-400 text-left">
                <p className="text-gray-500">{"[2026-07-09 22:20:01] Initializing SOC Combat monitoring pipeline..."}</p>
                <p className="text-gray-500">{"[2026-07-09 22:20:03] Hooking suricata.yaml event rules successfully."}</p>
                <p className="text-red-400 font-bold">{"[CRITICAL] [RED_TEAM] 무차별 비밀번호 대입(Brute Force) 공격 감지 ➔ Target: Port 22"}</p>
                <p className="text-blue-400 font-bold">{"[ACTION] [BLUE_TEAM] 방화벽 체인 즉각 업데이트 수동 격리 조치"}</p>
                <p className="text-green-500">{"[SUCCESS] 🔴 공격 시도 시그니처 차단 매핑 지표 100% 일치"}</p>
                <p className="text-gray-400 animate-pulse">{"_ 시스템 로그 대기 중..."}</p>
              </div>
            </div>
          )}

          {/* TAB 3: API 취약점 진단 */}
          {activeMenu === 'api-security' && (
            <div className="bg-[#0b0f19] border border-[#1b2336] p-6 rounded-xl space-y-6">
              <div className="border-b border-[#1b2336] pb-4 text-left">
                <h2 className="text-lg font-bold text-white">🔑 데이터 거래 플랫폼 API 취약점 Diagnosis 매트릭스</h2>
                <p className="text-xs text-gray-400 mt-1">7인 기술 프로젝트 전용 API Token & Endpoint 모니터링</p>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-[#1b2336] text-gray-400 bg-[#0f1524]">
                      <th className="p-3">진단 엔드포인트(URL)</th>
                      <th className="p-3">점검 취약점 항목</th>
                      <th className="p-3">위험도</th>
                      <th className="p-3">진단 상태</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1b2336]">
                    <tr>
                      <td className="p-3 font-mono">/api/v1/kdx/data-trading/market</td>
                      <td className="p-3">Broken Object Level Authorization</td>
                      <td className="p-3"><span className="px-2 py-0.5 bg-red-900/50 text-red-400 rounded">High</span></td>
                      <td className="p-3 text-red-400 font-semibold">⚠️ 진단 실패 (보안 취약)</td>
                    </tr>
                    <tr>
                      <td className="p-3 font-mono">/api/v1/user/authentication/token</td>
                      <td className="p-3">JWT 토큰 서명 미검증 조작 위변조</td>
                      <td className="p-3"><span className="px-2 py-0.5 bg-yellow-900/50 text-yellow-400 rounded">Medium</span></td>
                      <td className="p-3 text-yellow-400 font-semibold">⚡ 점검 필 (패치 필요)</td>
                    </tr>
                    <tr>
                      <td className="p-3 font-mono">/api/v1/gateway/rate-limiting</td>
                      <td className="p-3">Unrestricted Resource Consumption (DoS)</td>
                      <td className="p-3"><span className="px-2 py-0.5 bg-green-900/50 text-green-400 rounded">Low</span></td>
                      <td className="p-3 text-green-400 font-semibold">✓ 조치 완료 (안전)</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          )}

        </main>
      </div>
    </div>
  );
}
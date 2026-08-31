# ZedBoard PQC Secure Channel

AMD Zynq-7000 ZedBoard(`XC7Z020-1CLG484`)를 대상으로 만든 연구·교육용 PQC 보안 통신 프로토타입입니다. Zynq PS는 Ethernet/UART와 소프트웨어 제어를 담당하고, PL은 ML-KEM-512 decapsulation과 ChaCha20-Poly1305 AEAD를 가속합니다.

## 시스템 구성

```text
PC clients
    |
    | Ethernet (최종 통합 예정)
    v
Zynq PS / Cortex-A9
    |- UART 로그
    |- 세션 및 네트워크 제어
    `- AXI4-Lite
         |- 0x43C0_0000 : AEAD
         `- 0x43C1_0000 : ML-KEM
                    |
                    v
Zynq PL
    |- ML-KEM-512 decapsulation
    |- shared SHA3/SHAKE (Keccak)
    |- ChaCha20-Poly1305
    |- 64-session BRAM table / indexed request port
    `- fault detection / fail-closed protection
```

현재 RTL은 **64개의 논리 세션**을 지원하며 암호 연산 엔진 하나를 공유합니다. 세션 상태는 PL의 BRAM에 저장하고, 요청 순서는 PS의 준비 비트맵 기반 round-robin 스케줄러가 결정합니다. 기존 4세션 RTL은 회귀 비교용으로 남겨 두었습니다.

## 구현된 기능

- ML-KEM-512 전체 decapsulation
  - NTT, INTT, BaseMul
  - 샘플링과 행렬 생성
  - 다항식 압축·해제 및 직렬화·역직렬화
  - 재암호화 및 ciphertext 전체 비교
  - 실패 시 대체 비밀 선택
- 공유 Keccak datapath 기반 SHA3/SHAKE
- ML-KEM 공유 비밀에서 방향별 traffic material 생성
- ChaCha20-Poly1305 고정 64-byte AEAD 패킷 처리
- 세션별 TX/RX key, nonce prefix, packet counter 분리
- Poly1305 인증 실패 시 plaintext 차단
- 64개 세션 BRAM 저장 및 6-bit indexed slot 처리
- PS용 64세션 event-driven round-robin 스케줄러
- AXI4-Lite 기반 PS-PL 제어
- ciphertext, counter, session key 및 출력 제어 경로 fault protection

## 검증 상태

보드 없이 수행한 RTL 회귀 테스트에서 다음 항목을 검증했습니다.

- ChaCha20 및 Poly1305 표준/골든 벡터
- AEAD encrypt/decrypt 및 변조 tag 거부
- SHA3/SHAKE
- NTT, INTT, BaseMul 개별 연산
- K-PKE decrypt/reencrypt
- ML-KEM-512 전체 decapsulation
- 변조된 ML-KEM ciphertext 거부
- 공유 Keccak 및 dual AXI 인터페이스
- fault injection과 fail-closed 동작
- PS Bring-up 프로그램 ARM 빌드 및 ELF 링크

실제 ZedBoard에서의 PS-PL 하드웨어 검증과 Ethernet 통신은 아직 남아 있습니다.

## 타이밍 최적화 및 구현 결과

BaseMul을 다중 사이클화하고 NTT/INTT의 Montgomery/Barrett 연산을 파이프라인화했습니다.

| 단계 | WNS | TNS | Setup 실패 endpoint |
|---|---:|---:|---:|
| 최초 구현 | -15.607 ns | -2554.274 ns | 1460 |
| BaseMul 수정 후 | -1.611 ns | -74.895 ns | 64 |
| NTT/INTT 수정 후(4세션) | +0.215 ns | 0 ns | 0 |
| **64세션 BRAM 구조** | **+0.282 ns** | **0 ns** | **0** |
| **100 MHz 최적화 후(64세션)** | **+0.048 ns** | **0 ns** | **0** |

64세션 설계는 50 MHz timing constraint를 만족하며, 상수 곱셈 축소·AEAD 데이터패스 분할·팬아웃 복제·이중화 비교 레지스터화를 적용한 뒤 **100 MHz(10 ns)에서도 배치·배선을 완주하고 timing을 만족합니다**. 100 MHz 기준 hold slack은 `+0.019 ns`, setup/hold 실패 endpoint와 routing error는 모두 0개입니다.

### XC7Z020 64세션 post-synthesis 결과

| Resource | Used | Available | Utilization |
|---|---:|---:|---:|
| Slice LUT | 29,598 | 53,200 | 55.64% |
| Slice Register | 26,158 | 106,400 | 24.58% |
| BRAM Tile | 9 | 140 | 6.43% |

### XC7Z020 64세션 post-implementation 결과

| Resource | Used | Available | Utilization |
|---|---:|---:|---:|
| LUT | 29,777 | 53,200 | 55.97% |
| LUTRAM | 62 | 17,400 | 0.36% |
| FF | 26,845 | 106,400 | 25.23% |
| BRAM | 9 | 140 | 6.43% |
| DSP | 61 | 220 | 27.73% |
| BUFG | 2 | 32 | 6.25% |

Vivado methodology report에는 DSP/BRAM 파이프라인 관련 warning이 남아 있지만, 구현·배선·timing을 막는 error 또는 critical warning은 확인되지 않았습니다.

64세션 테이블은 `1,536 × 32-bit` 상태 메모리로 구성되며 `RAMB36E1 2개`로 추론되었다. 기존 4세션 대비 LUT와 FF 사용량을 줄이면서 64세션 동시 처리를 지원한다.

## 64세션 통합본 합성·구현 결과

PR #2 타이밍 파이프라인과 후속 사이클 최적화를 반영한 64세션 ML-KEM Secure Channel 설계의 Vivado 검증 결과이다.

### 검증 결과

| 항목 | 결과 |
|---|---:|
| 전체 ML-KEM decapsulation 테스트 | PASS |
| 총 decapsulation 지연 | 104,245 cycles |
| CORE decapsulation | 97,364 cycles |
| 목표 클록 | 100 MHz |
| 타이밍 제약 | 모두 만족 |

100 MHz 최적화로 파이프라인 단수가 늘어 decapsulation 지연이 약 0.7% 증가했습니다(동일 조건 RTL 시뮬레이션 기준 148,092 → 149,133 cycles). 동작 클록이 2배가 되므로 실제 소요 시간은 절반 가까이 줄어듭니다.

### 구현 후 자원 사용량

| 자원 | 사용량 |
|---|---:|
| LUT | 21,758 |
| FF | 25,755 |
| BRAM | 9 |
| DSP | 52 |

### 타이밍 요약

| 항목 | 결과 |
|---|---:|
| WNS | +0.048 ns |
| TNS | 0.000 ns |
| WHS | +0.019 ns |
| 설정 주파수 | 100 MHz (10 ns period) |
| 타이밍 상태 | PASS |

### 해소된 최악 경로

50 MHz 기준 상위 경로는 모두 100 MHz 최적화로 해소되었다.

| 경로/블록 | 원인 | 수정 |
|---|---|---|
| Poly1305 accumulation | 곱셈기 2개 직렬 + 자리올림 44단 | r*5 사전 계산, 곱셈/누산/자리올림 분할 |
| SHA3/Hash | 1,600비트 갱신망 2벌, 팬아웃 1,630 | 갱신망 1벌로 축소, 제어 신호 복제 |
| POLY→MESSAGE | 조합 경로의 16x32 곱셈 | Compress_1을 비교 2개로 대체 |
| Public-key unpack | 복원 곱셈이 메모리 쓰기 경로에 위치 | 3329 곱셈을 시프트-덧셈으로 대체 |
| Pack/Compare | 32비트 상수로 DSP 2개 직렬 | 22비트 상수로 DSP 1개 |
| ML-KEM BaseMul | BRAM 출력이 DSP에 직결 | 입력 레지스터 1단 추가 |

PR #2의 Barrett reduction 및 BaseMul 파이프라인과 후속 데이터 이동 최적화를 적용한 결과, 총 decapsulation 지연이 148,093 cycles에서 104,245 cycles로 감소했다. 이어서 Poly1305, SHA3/Hash, 압축·복원 상수 곱셈 경로를 최적화하여 **100 MHz timing을 만족**하며, LUT 사용량도 55.97%에서 40.90%로 감소했다.

## 디렉터리

- `outputs/golden_reference`: PC용 C golden reference와 테스트 벡터
- `outputs/rtl_aead/rtl`: SystemVerilog RTL 원본
- `outputs/rtl_aead/tb`: 단위·통합·공격 테스트벤치
- `outputs/rtl_aead/ps_driver`: PS 드라이버, Bring-up 프로그램, KAT 벡터
- `zed_pqc/ip_repo/secure_channel_ip`: Vivado 패키징용 custom IP
- `zed_pqc/project_1`: ZedBoard Vivado 프로젝트와 Block Design
- `zed_pqc/build_vitis.tcl`: Vitis workspace 재생성 보조 스크립트

Vivado/Vitis 자동 생성 폴더, bitstream, XSA, ELF 및 로컬 archive는 저장소에서 제외될 수 있습니다. 필요한 산출물은 각 PC에서 다시 생성합니다.

## Vivado 프로젝트 재생성

권장 도구 버전은 Vivado/Vitis 2020.2입니다.

1. `zed_pqc/project_1/project_1.xpr`을 엽니다.
2. IP repository가 `zed_pqc/ip_repo`를 가리키는지 확인합니다.
3. Report IP Status에서 custom IP가 최신 revision인지 확인합니다.
4. `system.bd`의 Output Products를 다시 생성합니다.
5. Validate Design을 실행합니다.
6. Run Synthesis와 Run Implementation을 실행합니다.
7. post-route Timing Summary에서 `WNS >= 0`, `TNS = 0`인지 확인합니다.
8. Generate Bitstream을 실행합니다.
9. bitstream을 포함하여 `system_wrapper.xsa`를 export합니다.

## ZedBoard에서 남은 작업

### 1. 장비 준비

- ZedBoard 전원 공급 및 JTAG boot mode 설정
- JTAG/Programming USB 연결
- USB-UART 연결 및 `115200-8-N-1` 터미널 준비
- Ethernet 데모 단계에서는 PC와 ZedBoard Ethernet 연결
- 노트북에 Vivado/Vitis 2020.2, Zynq-7000 device support, cable driver 설치

### 2. PS-PL Bring-up

1. Vivado Hardware Manager 또는 Vitis에서 FPGA를 program합니다.
2. export한 XSA로 Vitis standalone platform을 생성합니다.
3. `outputs/rtl_aead/ps_driver`의 드라이버와 Bring-up 소스를 application에 추가합니다.
4. Cortex-A9용 `zed_pqc_bringup.elf`를 빌드하고 실행합니다.
5. UART에서 각 KAT 결과를 확인합니다.

전체 검사가 성공하면 마지막에 다음 문자열이 출력됩니다.

```text
ALL PS-PL HARDWARE TESTS PASSED
```

Bring-up은 AEAD 골든 결과 비교, 정상 복호화, tag 변조 거부, ML-KEM decapsulation, 세션 설치, ML-KEM ciphertext 변조 거부를 검사합니다.

### 3. 실제 Ethernet 데모

Bring-up 통과 후 다음 소프트웨어를 추가해야 합니다.

- Zynq PS용 lwIP Ethernet 서버
- PC용 ML-KEM/ChaCha20-Poly1305 클라이언트
- 공개키 fingerprint 사전 등록 및 검증
- handshake와 고정 64-byte packet protocol
- `session_id`, counter, timeout 및 오류 처리
- 먼저 PC 클라이언트 1개로 검증한 뒤 64개 논리 세션으로 확장

64명 데모용 RTL과 기본 PS 스케줄러는 준비되었습니다. 실제 데모에는 lwIP 연결별 slot 할당/회수, Ethernet RX 큐, timeout 및 연결 종료 시 세션 폐기 정책을 추가해야 합니다.

## 주의

이 저장소는 연구·교육용 프로토타입입니다. 기능 시뮬레이션과 구현 timing은 통과했지만 실제 보드 검증, 상호운용성 시험, side-channel 평가 및 제품 수준의 보안 검증은 아직 완료되지 않았습니다. 실제 서비스용 암호 시스템으로 사용하면 안 됩니다.

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
    |- 4-session table / round-robin arbiter
    `- fault detection / fail-closed protection
```

현재 RTL은 BRAM 기반 64-session table을 지원하며 ChaCha20-Poly1305 연산 엔진 하나를 공유합니다. 동시에 유효한 요청은 패킷 단위의 비선점형 round-robin 방식으로 선택합니다. 각 패킷의 처리가 끝난 뒤 다음 세션으로 넘어가며 요청이 없는 슬롯은 건너뜁니다.

현재 PS-facing AEAD AXI-Lite frontend는 `pending/inflight` 요청을 한 개만 보관합니다. 따라서 64 session storage는 64개의 암호 엔진이나 64개의 동시 처리 요청을 의미하지 않습니다. 실제 Ethernet 다중 클라이언트 통합에서는 PS 소프트웨어 요청 큐와 descriptor FIFO가 추가로 필요합니다.

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
- 4개 세션 round-robin 처리
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

실제 ZedBoard에서 단일 세션 PS-PL bring-up, 64-session BRAM 검증, 64-user UART join/leave/churn 데모를 완료했습니다. Ethernet 기반 다중 클라이언트 통신, 장시간 안정성, 실제 동시 도착 요청 처리량은 후속 검증 항목입니다.

## 실제 ZedBoard 검증 결과

Vivado/Vitis 2020.2와 실제 ZedBoard에서 다음 PS-PL 통합 경로를 검증했습니다.

- PS의 AXI4-Lite 레지스터 접근과 PL 제어
- ML-KEM-512 decapsulation key와 ciphertext 적재
- ML-KEM-512 decapsulation 및 AEAD session slot 1 자동 설치
- ML-KEM에서 생성된 방향별 RX/TX key 사용
- 변조된 AEAD tag 거부 및 plaintext 차단
- PC-to-ZedBoard 패킷 복호화와 plaintext golden 비교
- ZedBoard-to-PC ChaCha20-Poly1305 응답 암호화
- 첫 TX packet counter가 0인지 확인
- 응답 ciphertext와 Poly1305 tag를 PC golden vector와 비교
- 변조된 ML-KEM ciphertext 거부

~~~text
-- Full ML-KEM to AEAD test --
[PASS] load ML-KEM-512 decapsulation key
[PASS] decapsulate and install session slot 1
[PASS] tampered AEAD tag is rejected
[PASS] decrypt PC packet with ML-KEM-derived RX key
[PASS] ML-KEM session plaintext matches reference
[PASS] encrypt ZedBoard response with derived TX key
[PASS] first TX packet counter is zero
[PASS] ChaCha20 response ciphertext matches PC golden
[PASS] Poly1305 response tag matches PC golden
[PASS] tampered ML-KEM ciphertext is rejected

ALL PS-PL HARDWARE TESTS PASSED
~~~

이 결과는 session slot 1을 이용한 단일 요청의 암호 기능과 PS-PL 통합 경로를 검증한 것입니다. 4개 세션 동시 요청, 장시간 반복 및 실제 Ethernet 통신 검증은 아직 남아 있습니다.

### 64-session BRAM 및 동적 사용자 데모

64-session XSA와 ZedBoard PS preset/DDR 설정을 적용한 실제 보드에서 다음을 검증했습니다.

* slot `0..63` 전체에 ML-KEM 기반 세션을 설치하고 AEAD 암·복호화 수행
* 64개 slot의 첫 TX counter가 모두 `0`에서 시작함을 확인
* slot마다 서로 다른 session ID와 traffic material을 사용함을 확인
* 한 slot의 TX counter 변화가 다른 slot에 영향을 주지 않음을 확인
* 사용자 이탈 후 slot 재사용 시 새 ML-KEM 세션으로 덮어쓰고 counter가 초기화됨을 확인
* 범위를 벗어난 slot `64`를 PS 드라이버에서 거부
* 64 active sessions 상태에서 join, logical leave, rejoin, churn 동작 확인

`LEAVE`는 현재 PS 소프트웨어가 해당 slot을 비활성으로 표시하는 논리적 삭제입니다. 같은 slot에 새 사용자가 `JOIN`하면 새 ML-KEM 세션이 기존 key와 counter를 덮어씁니다. 즉시 key를 0으로 지우는 RTL zeroization은 후속 보안 강화 항목입니다.

## 성능 측정 및 사이클 프로파일

### 실제 ZedBoard 측정 결과

측정 환경은 ZedBoard XC7Z020, Vivado/Vitis 2020.2, PL clock 50 MHz, UART 115200 baud입니다.

작업 | 측정값 | 설명
--- | ---: | ---
ML-KEM service total | 2,832 us | ciphertext 적재, AXI START, 완료 대기 포함
AXI input + START | 91 us | PS에서 ML-KEM AXI frontend까지의 제어·입력 구간
ML-KEM START-to-DONE | 약 2,741 us | PL 내부 ML-KEM 실행 구간
AEAD RX, 64 B | 약 26 us | ChaCha20-Poly1305 인증 복호화
AEAD TX, 64 B | 약 26 us | ChaCha20-Poly1305 암호화
UART round-trip | 약 34.5 ms | UART 전송 및 PC/Python 프로토콜 포함
64-slot ML-KEM 평균 | 2,832.0 us | min 2,832 us, max 2,833 us

UART RTT는 암호 연산보다 훨씬 크므로, 현재 UART 데모의 처리량 병목은 PL 가속기가 아니라 직렬 링크와 PC 측 명령 처리입니다.

### Cortex-A9 software-only 비교

동일 ZedBoard에서 `-O2`로 빌드한 C 구현(ML-KEM-native 및 Monocypher)과 비교했습니다.

작업 | Cortex-A9 software only | PL service | 비교
--- | ---: | ---: | ---
ML-KEM-512 decapsulation | 1,258.523 us | 2,832 us | SW가 약 2.25배 빠름
ChaCha20-Poly1305 encrypt, 64 B | 6.723 us | 약 26 us | SW가 약 3.87배 빠름
ChaCha20-Poly1305 decrypt, 64 B | 6.886 us | 약 26 us | SW가 약 3.78배 빠름

현재 RTL은 단일 요청 latency 기준으로 optimized Cortex-A9 소프트웨어보다 빠르지 않습니다. 현재 하드웨어 구조의 가치는 PL 내부 key 보관, CPU offload, 일정한 실행 시간, 향후 다중 엔진 병렬화 가능성에 있습니다. 따라서 “가속”을 주장하려면 단일 latency뿐 아니라 지속 처리량, CPU 사용률, 다중 요청 처리량을 함께 재측정해야 합니다.

### ML-KEM 사이클 프로파일

ML-KEM AXI frontend에 START부터 DONE까지 계수하는 32-bit counter를 추가했습니다. counter 값은 ML-KEM AXI offset `0x2C`에서 읽습니다.

구간 | Cycles | 50 MHz 환산 | 전체 비율
--- | ---: | ---: | ---:
Total | 137,085 | 2,741.70 us | 100.00%
Core decapsulation | 128,647 | 2,572.94 us | 93.84%
Transcript hash | 8,154 | 163.08 us | 5.95%
Traffic KDF | 254 | 5.08 us | 0.19%
Session install | 28 | 0.56 us | 0.02%

RTL simulation의 `137,085 cycles / 50 MHz = 2,741.7 us`는 실제 보드에서 측정한 START-to-DONE 약 2,741 us와 일치합니다.

연산 | 호출 수 | 호출당 cycles | 합계 cycles | 전체 비율
--- | ---: | ---: | ---: | ---:
NTT | 4 | 4,482 | 17,928 | 13.08%
INTT | 4 | 6,658 | 26,632 | 19.43%
BaseMul | 8 | 514 | 4,112 | 3.00%
H(pk) | 1 | 4,174 | 4,174 | 3.04%
G(m \|\| H(pk)) | 1 | 224 | 224 | 0.16%
J(z \|\| ct) | 1 | 4,078 | 4,078 | 2.97%
Matrix SHAKE | - | - | 6,755 | 4.93%
Noise SHAKE | - | - | 2,590 | 1.89%
Transcript hash | 1 | 8,154 | 8,154 | 5.95%
Traffic KDF hash | 1 | 254 | 254 | 0.19%

Hash/SHAKE 전체 합계는 26,229 cycles(19.13%)입니다.

### 데이터 이동 분석 및 최적화 방향

구간 | Cycles | 전체 비율
--- | ---: | ---:
Bridge input load | 18,432 | 13.45%
Bridge core wait (NTT + INTT + BaseMul) | 48,672 | 35.50%
Bridge result store | 12,288 | 8.96%
CT/SK unpack | 5,892 | 4.30%
Public-key unpack | 3,201 | 2.34%
Polynomial add/sub | 16,137 | 11.77%
Message-to-polynomial | 257 | 0.19%
Polynomial-to-message | 769 | 0.56%
Pack/compare | 5,123 | 3.74%

`Bridge core wait`은 NTT, INTT, BaseMul 합계와 일치합니다. 중복을 제거하면 bridge input/result copy만 30,720 cycles(22.41%)를 차지합니다. 따라서 다음 최적화 우선순위를 둡니다.

1. 공유 BRAM 또는 dual-port memory로 bridge copy 축소
2. ping-pong buffer/streaming으로 데이터 이동과 연산 중첩
3. polynomial add/sub의 메모리 접근 파이프라인 개선
4. INTT scaling/final reduction 결합 및 critical path 파이프라이닝
5. Hash/SHAKE streaming
6. timing을 유지하며 50 MHz 이상 FCLK를 단계적으로 탐색
7. UART와 분리한 AXI 처리량 및 Ethernet 다중 요청 처리량 측정

## 타이밍 최적화 및 구현 결과

BaseMul을 다중 사이클화하고 NTT/INTT의 Montgomery/Barrett 연산을 파이프라인화했습니다.

| 단계 | WNS | TNS | Setup 실패 endpoint |
|---|---:|---:|---:|
| 최초 구현 | -15.607 ns | -2554.274 ns | 1460 |
| BaseMul 수정 후 | -1.611 ns | -74.895 ns | 64 |
| NTT/INTT 수정 후 | +0.215 ns | 0 ns | 0 |
| AXI-Lite 수정 머지 후 최종 구현 | **+0.265 ns** | **0 ns** | **0** |

최종 post-route 결과는 50 MHz(`20.000 ns`) timing constraint를 만족합니다. Hold slack은 `+0.021 ns`, pulse-width slack은 `+9.020 ns`이며 setup/hold/pulse-width failing endpoint는 모두 0개입니다.

### XC7Z020 post-implementation 자원 사용량

| Resource | Used | Available | Utilization |
|---|---:|---:|---:|
| LUT | 35,866 | 53,200 | 67.42% |
| LUTRAM | 62 | 17,400 | 0.36% |
| FF | 29,815 | 106,400 | 28.02% |
| BRAM | 7 | 140 | 5.00% |
| DSP | 61 | 220 | 27.73% |
| BUFG | 2 | 32 | 6.25% |

Vivado methodology report에는 DSP/BRAM 파이프라인 관련 warning이 남아 있지만, 구현·배선·timing을 막는 error 또는 critical warning은 확인되지 않았습니다.


## 64세션 통합본 합성·구현 결과

64세션 ML-KEM Secure Channel 설계에 PR #2 타이밍 파이프라인 수정을 반영한 뒤, Vivado 합성 및 구현을 수행하였다.

### 검증 결과

| 항목 | 결과 |
|---|---:|
| 전체 ML-KEM decapsulation 테스트 | PASS |
| 총 decapsulation 지연 | 148,093 cycles |
| 목표 클록 | 50 MHz |
| 타이밍 제약 | 모두 만족 |

### 구현 후 자원 사용량

| 자원 | 사용량 |
|---|---:|
| LUT | 29,812 |
| FF | 27,058 |
| BRAM | 9 |
| DSP | 59 |

### 타이밍 요약

| 항목 | 결과 |
|---|---:|
| WNS | +0.606 ns |
| TNS | 0.000 ns |
| WHS | +0.010 ns |
| 설정 주파수 | 50 MHz (20 ns period) |
| 타이밍 상태 | PASS |

### 주요 최악 경로 분석

| 우선순위 | 경로/블록 | 지연 또는 특성 | 분석 |
|---:|---|---:|---|
| 1 | Poly1305 accumulation | 19.084 ns | 현재 전체 최악 경로. `d_acc_reg[0][27] → h_limb_reg[1][21]` 경로이며, 논리 단계 51개와 CARRY4 43개가 집중되어 있음 |
| 2 | SHA3/Hash 경로 | 약 16.110 ns | Poly1305 다음 병목 경로. 100 MHz 목표에서는 추가 파이프라인 검토 필요 |
| 3 | ML-KEM Poly Add/Sub | 약 12.163 ns, 논리 단계 10 | PR #2의 Barrett reduction 파이프라인 적용 후 크게 개선됨 |
| 4 | ML-KEM BaseMul | 약 7.618 ns | PR #2의 BaseMul 파이프라인 적용 후 100 MHz 기준에도 비교적 여유가 있는 경로 |

PR #2 적용으로 ML-KEM Poly Add/Sub 및 BaseMul 경로는 개선되었으며, 50 MHz에서 모든 타이밍 제약을 만족한다. 다음 100 MHz 최적화 단계의 최우선 대상은 Poly1305 accumulation 경로이고, 그 다음은 SHA3/Hash 경로이다.

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

## ZedBoard 실행 절차

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

추가 보드 검증에서는 4개 session slot의 독립성, TX/RX counter 증가, replay 및 skipped-counter 거부, 인증 실패 시 counter 유지, 0/1/63/64-byte 경계 처리와 65-byte/잘못된 slot 거부를 확인했습니다. 별도 XSim testbench에서는 4개 동시 요청의 `0 -> 1 -> 2 -> 3` round-robin 순서, inactive slot 건너뛰기 및 지속 경쟁 시 starvation 부재를 확인했습니다.

### 3. UART 보안 통신 데모

Ethernet 없이 `outputs/rtl_aead/pc_tools/uart_secure_client.py`로 4개의 논리 사용자를 열어 ChaCha20-Poly1305 양방향 secure echo를 실행할 수 있습니다. `/round N`은 네 사용자를 순환하며 패킷 수, ML-KEM session 수립 시간, PL RX/TX 시간 및 PC UART RTT를 출력합니다. 현재 UART frontend는 요청을 직렬화하므로 실제 동시 요청의 arbiter 검증을 대체하지 않습니다.

### 4. 실제 Ethernet 데모

Bring-up 통과 후 다음 소프트웨어를 추가해야 합니다.

- Zynq PS용 lwIP Ethernet 서버
- PC용 ML-KEM/ChaCha20-Poly1305 클라이언트
- 공개키 fingerprint 사전 등록 및 검증
- handshake와 고정 64-byte packet protocol
- `session_id`, counter, timeout 및 오류 처리
- 먼저 PC 클라이언트 1개로 검증한 뒤 현재 RTL 한도인 4개 세션으로 확장

32/64명 최종 데모를 진행하려면 별도 단계에서 session slot 폭을 5/6비트로 확장하고, FF 기반 4세션 테이블을 BRAM 기반 indexed table로 변경한 뒤 PS 연결 관리와 요청 큐를 추가해야 합니다.

## 검증 현황 및 남은 계획

### 1. 보드 기반 다중 세션 검증

**완료:** 4개 slot 독립성, session별 key/context 격리, 독립 counter 및 순차 UART round 측정. Round-robin 동시 경쟁은 확장 XSim testbench에서 완료.

- slot 0~3에 서로 다른 key, nonce prefix 및 session ID 설치
- 4개 요청을 동시에 유지하여 round-robin 처리 순서 확인
- 요청이 없는 슬롯을 건너뛰는지 확인
- 특정 세션의 starvation이 발생하지 않는지 확인
- 세션별 TX/RX counter가 독립적으로 증가하는지 확인
- 세션 사이에서 key, nonce 및 결과가 섞이지 않는지 확인

### 2. Counter 및 replay 방지 검증

**완료:** counter `0 -> 1 -> 2`, replay/skipped counter 거부, 인증 실패 시 counter 유지, session 재설치 시 초기화.

- 동일 세션의 연속 패킷에서 counter `0 -> 1 -> 2` 확인
- 각 counter의 암호문과 tag를 PC golden vector와 비교
- 이전 counter 재전송과 중복 패킷 거부
- 예상 counter를 건너뛴 패킷 거부
- 인증 실패 시 RX counter가 증가하지 않는지 확인
- 세션 재설치·무효화 시 key와 counter 초기화 확인

### 3. 경계값 및 오류 복구 검증

**부분 완료:** 0/1/63/64-byte 처리와 65-byte 및 invalid slot 거부 완료. reset 중단 복구와 장시간 반복 시험은 남아 있습니다.

- 길이 0, 1, 63, 64-byte 패킷 처리
- 64-byte 초과 요청 거부
- 잘못된 slot, session ID, tag 및 ciphertext 거부
- FPGA/PS reset 이후 세션 재초기화 확인
- 처리 중 reset과 timeout 이후 PS 소프트웨어 복구 확인
- 수천~수만 회 반복 암·복호화 및 ML-KEM decapsulation

### 4. 실제 Ethernet 통합

- Zynq PS용 lwIP Ethernet 서버
- PC용 ML-KEM/ChaCha20-Poly1305 클라이언트
- 공개키 fingerprint 등록 및 검증
- PS 다중 클라이언트 요청 큐
- 단일 PC 클라이언트 handshake와 양방향 패킷 통신
- 패킷 손실, 중복, 순서 변경 및 재접속 처리
- PC 클라이언트 4개의 동시 통신과 공정성 확인

### 5. 성능 및 보안 평가

ZedBoard Release(`-O2`) 실측 결과:

| 연산 | Cortex-A9 software | FPGA service | 비고 |
|---|---:|---:|---|
| ML-KEM-512 decapsulation/session | 1,258.523 us | 2,812 us | HW는 AXI 전송, KDF, session 설치 포함 |
| ChaCha20-Poly1305 encrypt 64B | 6.723 us | 19.0 us | HW는 AXI-Lite service 시간 |
| ChaCha20-Poly1305 decrypt 64B | 6.886 us | 19.0 us | HW는 AXI-Lite service 시간 |

4사용자 200패킷 UART round에서는 payload throughput `430.2 byte/s`, 평균 RTT 약 `34.35 ms`가 측정됐습니다. UART/text/hex 직렬화가 end-to-end 병목이며, 현재 50 MHz AXI-Lite 구현은 Cortex-A9 software보다 낮은 실제 처리량을 보였습니다. 성능 개선에는 AXI-Stream/DMA, batching, PL 내부 buffering 및 clock 최적화가 필요합니다.

- ML-KEM decapsulation cycle 수와 latency
- AEAD encrypt/decrypt latency와 throughput
- 4클라이언트별 평균·최대 대기시간
- 보드에서 fault injection과 fail-closed 동작
- reset 후 key와 민감 데이터 잔존 여부
- timing/power side-channel 및 fault 공격 별도 평가
## 주의

이 저장소는 연구·교육용 프로토타입입니다. 기능 시뮬레이션, 50 MHz 구현 timing, 단일 및 64-session PS-PL 보드 검증, UART 기반 사용자 join/leave/churn 데모는 통과했습니다. Ethernet 상호운용성, 실제 동시 도착 요청 처리량, 장시간 안정성, side-channel 평가, 즉시 key zeroization 및 제품 수준의 보안 검증은 아직 완료되지 않았습니다. 실제 서비스용 암호 시스템으로 사용하면 안 됩니다.

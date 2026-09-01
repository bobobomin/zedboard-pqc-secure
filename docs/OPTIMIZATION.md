# ML-KEM 타이밍 및 사이클 최적화

이 문서는 ZedBoard 64세션 통합 설계를 100 MHz에서 동작시키고 ML-KEM-512 Decapsulation의 사이클 수를 줄이기 위해 적용한 변경을 정리한다.

## 최종 결과 요약

| 항목 | 초기 설계 | 최종 설계 | 변화 |
| --- | ---: | ---: | ---: |
| PL 클록 | 50 MHz | **100 MHz** | 2배 |
| TOTAL cycles | 148,093 | **105,286** | **28.9% 감소** |
| 순수 처리시간 | 2,961.9 μs | **1,052.9 μs** | **64.5% 감소** |
| 실제 보드 ML-KEM | 약 2.83–2.96 ms | **약 1.114 ms** | 약 **60–62% 감소** |
| WNS | +0.606 ns @ 50 MHz | **+0.105 ns @ 100 MHz** | PASS |

## 최종 사이클 프로파일

| 구간 | 사이클 |
| --- | ---: |
| TOTAL | **105,286** |
| CORE DECAP | **98,400** |
| NTT TOTAL | 17,928 |
| INTT TOTAL | 26,632 |
| BASEMUL TOTAL | 9,232 |
| H(pk) | 3,380 |
| G(m‖H(pk)) | 225 |
| J(z‖ct) | 3,316 |
| MATRIX SHAKE | 6,759 |
| NOISE SHAKE | 2,595 |
| TRANSCRIPT HASH | 6,598 |
| TRAFFIC KDF HASH | 255 |

## 사이클 최적화

### 1. Polynomial Add/Sub 스케줄 중첩

기존 구조는 한 계수에 대해 RAM에서 A 읽기, B 읽기, Barrett reduction 완료 대기, 결과 쓰기를 순차적으로 수행했다. 최적화 구조는 3단 Barrett 파이프라인을 유지하면서 이전 계수의 reduction이 진행되는 동안 다음 계수의 RAM 읽기를 수행한다.

단일 포트 동기식 RAM의 제약 때문에 완전한 1-cycle 처리 구조는 아니지만, 연산 파이프라인과 메모리 접근을 겹쳐 유휴 사이클을 제거했다. 출력 주소는 현재 인덱스에서 이전 결과의 위치를 계산해 기록하며, 마지막 결과는 drain 상태에서 안전하게 저장한다.

### 2. Polynomial Bridge 데이터 이동

다항식 가속기와 공유 메모리 사이의 bridge가 한 데이터마다 여러 제어 상태를 사용하던 구조를 연속 전송 형태로 변경했다. 입력 적재와 결과 저장의 주소·valid·write 동작을 겹쳐 동일한 데이터를 옮기는 데 필요한 사이클을 줄였다.

### 3. CT/SK 및 Public-key Unpack 대기 제거

동기식 메모리의 read latency보다 보수적으로 삽입되어 있던 대기 상태를 실제 데이터 유효 시점에 맞게 재구성했다. 연속된 word를 읽는 동안 주소 발행과 이전 read 결과 처리를 중첩해 ciphertext, secret key 및 public key unpack 시간을 줄였다.

### 4. Hash 입력 적재 최적화

H(pk), J(z‖ct), transcript hash에 입력 word를 공급하는 제어 경로의 불필요한 상태 전환을 제거했다. Keccak 라운드 자체의 구조는 유지하고, 메시지 적재와 command 전환에서 발생하던 제어 오버헤드를 줄였다.

### 5. Pack/Compare 및 Poly-to-message

패킹·비교 단계의 메모리 대기와 주소 진행을 정리했다. Poly-to-message는 절감 가능한 사이클이 상대적으로 작고 100 MHz 타이밍 경로에 영향을 줄 수 있어 공격적인 추가 최적화보다 검증된 구조를 유지했다.

## 데이터 이동 전후 비교

| 구간 | 초기 | 최종 | 감소 |
| --- | ---: | ---: | ---: |
| BRIDGE INPUT LOAD | 18,432 | **6,168** | 12,264 |
| BRIDGE CORE WAIT | 52,768 | **53,792** | -1,024 |
| BRIDGE RESULT STORE | 12,288 | **4,112** | 8,176 |
| CT/SK UNPACK | 5,892 | **4,356** | 1,536 |
| PUBLIC-KEY UNPACK | 3,201 | **2,337** | 864 |
| POLY ADD/SUB | 23,049 | **6,948** | 16,101 |
| MESSAGE → POLY | 257 | **257** | 0 |
| POLY → MESSAGE | 769 | **513** | 256 |
| PACK/COMPARE | 5,123 | **3,587** | 1,536 |

`BRIDGE CORE WAIT`가 1,024 cycles 증가한 이유는 100 MHz 타이밍 수정을 위해 BaseMul 한 번의 지연이 1,026 cycles에서 1,154 cycles로 128 cycles 증가했고, Decapsulation에서 총 8회 실행되기 때문이다. 이는 기능 오류가 아니라 타이밍 여유를 확보하기 위한 처리량–주파수 절충이다.

## 100 MHz 타이밍 최적화

### ML-KEM BaseMul

곱셈 및 Montgomery reduction으로 이어지는 조합 경로를 레지스터로 분할했다. 그 결과 BaseMul 사이클은 증가했지만, 전체 설계를 100 MHz로 동작시킬 수 있는 타이밍 여유를 확보했다.

### Polynomial Add/Sub Barrett reduction

Barrett reduction은 큰 정수 나눗셈 대신 상수 곱셈과 shift를 이용해 계수를 모듈러 `q` 범위로 줄이는 연산이다. 덧셈·뺄셈 결과에서 reduction까지 이어지는 긴 조합 경로를 단계별 레지스터로 분리했다.

### SHA3/SHAKE 및 제어 fan-out

Keccak 데이터 경로와 넓은 제어 신호의 fan-out을 줄이고 필요한 경계에 레지스터를 배치했다. 세션 관련 wide bus broadcast 및 fault comparison 경로도 등록해 라우팅 지연을 완화했다.

### ChaCha20-Poly1305

ChaCha20과 Poly1305의 긴 조합 경로를 분할했다. AEAD는 본 과제의 주 가속 대상인 ML-KEM보다 처리량 우선순위가 낮으므로, DSP 사용량과 짧은 패킷 제어 오버헤드를 감수하는 자원 절약형 구조를 유지했다.

## 최종 구현 결과

| 항목 | 결과 |
| --- | ---: |
| WNS | **+0.105 ns** |
| TNS | **0.000 ns** |
| WHS | **+0.007 ns** |
| LUT | **24,081** |
| FF | **25,727** |
| BRAM Tile | **9** |
| DSP | **51** |

## RTL 수정 후 Vivado 반영 절차

1. `outputs/rtl_aead/rtl`과 `zed_pqc/ip_repo/secure_channel_ip/src`의 대응 RTL을 함께 수정한다.
2. IP Packager에서 수정된 파일과 top module 참조 상태를 확인한다.
3. **Re-Package IP**를 실행한다.
4. 원래 프로젝트에서 **Refresh All Repositories**를 실행한다.
5. Block Design의 IP 상태를 확인하고 필요하면 업그레이드한다.
6. **Generate Output Products – Global**을 실행한다.
7. 기존 synthesis/implementation run을 reset한 뒤 다시 실행한다.
8. XSim 기능 검증, 구현 타이밍, bitstream 및 Vitis 보드 검증을 순서대로 확인한다.

시뮬레이션 복사본만 수정하면 XSim 결과와 실제 Block Design IP 합성 결과가 달라질 수 있다. 최종 합성에 사용되는 패키지 IP 소스와 `component.xml`을 반드시 확인해야 한다.

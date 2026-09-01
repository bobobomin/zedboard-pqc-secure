# ZedBoard 기반 다중 세션 양자내성암호 보안채널 가속기

> 차량–기지국 연결을 모사한 ML-KEM-512 및 ChaCha20-Poly1305 하드웨어 구현

## 프로젝트 개요

이 프로젝트는 Zynq-7000 기반 ZedBoard에서 양자내성 키 설정과 대칭키 보안 통신을 하나의 하드웨어 시스템으로 구현한다. 이동 차량이 새로운 기지국 영역에 진입해 보안 세션을 설정하는 상황을 응용 모델로 삼았으며, 최대 64개 세션을 서로 독립적으로 관리한다.

실제 검증 환경에서는 PC 클라이언트가 차량·단말 역할을, ZedBoard PS가 기지국 제어부 역할을 수행한다. PC와 PS는 UART로 통신하며, PL은 ML-KEM-512 Decapsulation, SHA3/SHAKE, ChaCha20-Poly1305 및 세션 상태 관리를 가속한다. 실제 이동통신 핸드오버 전체를 구현한 것은 아니며, 그 과정에 필요한 키 설정·세션 관리·데이터 보호 기능을 단순화해 검증했다.

## 시스템 구성

```text
PC 클라이언트(차량/단말 모사)
        │ UART
        ▼
Zynq PS / Cortex-A9(기지국 제어부 모사)
        │ AXI4-Lite
        ▼
Zynq PL 보안 가속기
 ├─ ML-KEM-512 Decapsulation
 ├─ Shared Keccak: SHA3/SHAKE
 ├─ ChaCha20-Poly1305
 ├─ 64-session BRAM table
 └─ Fault detection / fail-closed control
```

## 핵심 기능

- ML-KEM-512 Decapsulation 및 세션 키 설치
- NTT, INTT, BaseMul 및 SHA3/SHAKE 하드웨어 처리
- 64-byte 고정 패킷용 ChaCha20-Poly1305 송수신
- 최대 64개 세션의 키·카운터·상태 독립 관리
- 잘못된 태그, 재전송, 범위 밖 슬롯 및 변조된 ML-KEM 암호문 거부
- 해시 스케줄 감시, watchdog, dual-rail 및 출력 제어 기반 fail-closed 동작

## 최종 검증 결과

| 항목 | 결과 |
| --- | ---: |
| Vivado 버전 | 2020.2 |
| PL 클록 | **100 MHz** |
| ML-KEM 총 지연 | **105,286 cycles** |
| 순수 PL 처리시간 | **약 1,052.9 μs** |
| 실제 보드 ML-KEM 서비스 시간 | **약 1,114 μs** |
| 64개 세션 설치 및 사용 | **64/64 PASS** |
| 전체 PS–PL 보드 검증 | **PASS** |

초기 50 MHz 설계의 148,093 cycles와 비교하면 사이클 수는 42,807 cycles, 약 28.9% 감소했다. 클록 향상까지 포함한 순수 처리시간은 약 2,961.9 μs에서 1,052.9 μs로 약 64.5% 단축되었다.

## PS 소프트웨어와의 비교

동일한 ZedBoard Cortex-A9에서 측정했다. Debug 결과는 최적화되지 않은 참고값이며, 공정한 주 비교 기준은 Release `-O2`이다. PL 측정값에는 AXI 제어 오버헤드가 포함된다.

| 작업 | PS SW Debug | PS SW Release `-O2` | PL HW |
| --- | ---: | ---: | ---: |
| ML-KEM-512 Decapsulation | 5,291.255 μs | **1,258.523 μs** | **1,114 μs** |
| ChaCha20-Poly1305 Encrypt 64B | 50.869 μs | **6.723 μs** | 21 μs |
| ChaCha20-Poly1305 Decrypt 64B | 52.016 μs | **6.886 μs** | 21–22 μs |

ML-KEM은 최적화된 PS 소프트웨어보다 PL이 약 1.13배 빠르며, 최적화되지 않은 Debug 소프트웨어보다 약 4.75배 빠르다. 반면 64-byte AEAD는 `-O2` 소프트웨어가 더 빠르다. 현재 PL의 Poly1305가 DSP 사용량을 줄이기 위해 곱셈기를 직렬 재사용하고 있고, 짧은 패킷에서는 AXI 및 상태 제어 오버헤드의 비중이 크기 때문이다.

## 구현 결과

### 타이밍

| 항목 | 결과 |
| --- | ---: |
| Clock period | 10 ns |
| WNS | **+0.105 ns** |
| TNS | **0.000 ns** |
| WHS | **+0.007 ns** |
| Setup/Hold 위반 | **0 / 0** |

### 자원 및 전력

| 항목 | 결과 |
| --- | ---: |
| LUT | **24,081** |
| FF | **25,727** |
| BRAM Tile | **9** |
| DSP | **51** |
| Total On-Chip Power | **2.323 W** |
| Junction Temperature | **51.8 °C** |

전력 값은 Vivado 구현 후 추정치이며 실제 계측값이 아니다.

## 64세션 보드 검증 항목

- 0–63번 슬롯 전체에 ML-KEM 세션 설치 및 사용
- 세션 ID별 트래픽 키 분리
- 슬롯별 TX counter 독립성 및 초기값 확인
- 슬롯 재사용 시 기존 사용자의 상태 제거와 counter 초기화
- 범위 밖 슬롯 64 거부
- 세션 leave/rejoin 반복 시험
- 정상 암복호화, 태그 변조 및 replay 거부

## 저장소 구조

```text
outputs/rtl_aead/rtl/                  독립 RTL 원본
outputs/rtl_aead/tb/                   RTL 및 통합 테스트벤치
outputs/rtl_aead/pc_tools/             PC UART 클라이언트
outputs/rtl_aead/ps_driver/            Zynq PS 드라이버와 보드 검증 코드
outputs/golden_reference/              소프트웨어 기준 구현
zed_pqc/ip_repo/secure_channel_ip/     Vivado 패키지 IP
zed_pqc/project_64session/             Vivado 2020.2 최종 64세션 프로젝트
docs/OPTIMIZATION.md                   타이밍·사이클 최적화 상세
```

## Vivado 재현 절차

1. Vivado 2020.2에서 `zed_pqc/project_64session/project_1.xpr`을 연다.
2. IP Catalog에서 **Refresh All Repositories**를 실행한다.
3. IP RTL을 수정했다면 `mlkem_secure_channel`을 **Edit in IP Packager**로 열고 **Re-Package IP**를 실행한다.
4. Block Design에서 IP 상태를 확인하고 **Generate Output Products – Global**을 실행한다.
5. `system_wrapper`를 top으로 설정한 뒤 Synthesis, Implementation, Generate Bitstream을 순서대로 실행한다.
6. XSA를 내보내 Vitis 2020.2에서 PS–PL 보드 검증 프로그램을 실행한다.

시뮬레이션 복사본만 수정하면 XSim에는 반영되지만 Block Design의 패키지 IP 합성에는 반영되지 않을 수 있다. 최종 RTL 수정은 독립 RTL과 IP 저장소의 소스를 함께 동기화하고 반드시 IP를 재패키징해야 한다.

## 상세 문서

- [타이밍 및 사이클 최적화 내역](docs/OPTIMIZATION.md)
- [PS 드라이버 사용법](outputs/rtl_aead/ps_driver/README.md)
- [RTL 구성](outputs/rtl_aead/rtl/README.md)

## 범위와 한계

본 프로젝트는 차량–기지국 보안 연결을 응용 모델로 사용했지만 상용 이동통신 프로토콜이나 실제 기지국 핸드오버를 구현한 것은 아니다. UART 기반 시험 환경에서 PQC 키 설정, 64세션 관리 및 데이터 보호 기능을 하드웨어로 검증한 연구용 프로토타입이다.

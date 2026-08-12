# ZedBoard PQC Secure Channel

ZedBoard XC7Z020을 대상으로 한 FPGA 보안 통신 시스템입니다.

## 구성

- ML-KEM-512 decapsulation 가속기
- 공유 Keccak 기반 SHA3/SHAKE 처리
- ChaCha20-Poly1305 AEAD
- 4개 세션과 round-robin arbiter
- PS 연결용 AXI4-Lite 인터페이스
- fault detection 및 fail-closed 보호

## 디렉터리

- `outputs/rtl_aead/rtl`: SystemVerilog RTL
- `outputs/rtl_aead/tb`: 테스트벤치
- `outputs/rtl_aead/ps_driver`: Zynq PS 드라이버
- `zed_pqc/ip_repo`: Vivado 패키징 IP 원본
- `zed_pqc/project_1`: ZedBoard Vivado 프로젝트와 Block Design

Vivado 자동 생성 폴더(`.gen`, `.runs`, `.cache`, `.ip_user_files`)는 저장소에서 제외합니다. 프로젝트를 연 뒤 Block Design의 Output Products를 다시 생성해야 합니다.

## 현재 상태

- RTL 회귀 테스트 통과
- ML-KEM decapsulation 및 AEAD 통합 검증 통과
- 공격 및 fault-protection 테스트 통과
- BaseMul 다중 사이클 최적화 적용
- XC7Z020 배치·배선 성공
- 50 MHz post-route timing: WNS `-1.611 ns`, TNS `-74.895 ns`
- 50 MHz timing closure는 아직 진행 중

## Vivado 재생성

1. `zed_pqc/project_1/project_1.xpr`을 Vivado 2020.2에서 엽니다.
2. IP repository가 `zed_pqc/ip_repo`를 가리키는지 확인합니다.
3. `system.bd`에서 Reset Output Products를 실행합니다.
4. Out of context per IP 방식으로 Generate Output Products를 실행합니다.
5. Run Synthesis와 Run Implementation을 순서대로 실행합니다.

## 주의

이 설계는 연구·교육용 프로토타입입니다. 현재 50 MHz 타이밍을 만족하지 않으므로 완료된 제품이나 실서비스용 암호 구현으로 간주하면 안 됩니다.

# WarCraft: Orcs & Humans (DOS 1.12) — 네이티브 arm64 재컴파일

원본 `WAR.EXE`(Watcom C/C++32, DOS/4GW)의 x86 기계어를 **함수 1,323개 전부 C로 변환**하고,
clang으로 **맥 arm64 네이티브 실행 파일**(`build/war`)을 만듭니다. 에뮬레이터 없이 원본 게임 로직이 그대로 돌고,
DOS·DOS/4GW·PC 하드웨어가 하던 일은 런타임(`runtime/game.c`)이 대신합니다.

## 실행

```bash
cd recomp
make play
```

처음 실행하면 CD 이미지(`../CD_DIC/WARCRAFT.bin`)에서 실행 파일과 데이터를 꺼내고, 게임 전체를 C로 변환해 빌드한 뒤 창을 띄웁니다.
필요한 것: Xcode clang, Python 3 + `capstone`, `7zz`, SDL2(`brew install sdl2`).

- 조작: 원본과 같습니다(마우스 + 키보드). 창 크기는 960×600(3배)입니다.
- 인트로는 ESC로 건너뜁니다. CD 검사는 런타임이 D: 드라이브를 CD-ROM처럼 흉내 내서 통과시킵니다.
- 설정·저장 파일은 `work/game/`에 생깁니다.

## 지금 되는 것 / 안 되는 것

확인한 흐름(창 없이 입력 스크립트로 재현, 아래 "자동 실행" 참고):

- 인트로 동영상과 자막 → 메인 메뉴 → 싱글 플레이 → 캠페인 선택 → 오크 1번 임무 브리핑 → **맵 로드, 유닛 애니메이션, 건물 선택**

아직 확인하지 않았거나 지원하지 않는 것:

- **소리 없음.** 사운드 카드 설정 파일이 없어 게임이 Miles AIL을 소리 없이 초기화합니다. 사운드는 Blizzard 사운드 래퍼(진입점 14개)를 SDL로 대체하는 작업이 남아 있습니다([SCOPING.md](SCOPING.md)).
- **네트워크·모뎀 대전 불가.** DPMI 실모드 인터럽트(IPX)를 지원하지 않습니다.
- **임무를 끝까지 플레이하거나 저장/불러오기, 휴먼 캠페인, 이후 임무는 아직 검증하지 않았습니다.** 실행 중 처리하지 못한 DOS 호출이나 변환되지 않은 명령을 만나면 무엇이었는지 출력하고 멈춥니다.
- FPU가 없는 386처럼 동작합니다(게임 로직은 정수 연산만 씀).
- 게임 속도는 원본처럼 DOS 시계(`int 21h/2Ch`)로 맞추지만, 실기와 같은지는 측정하지 않았습니다.

## 구조

| 경로 | 역할 |
|---|---|
| `tools/le.py`, `tools/disasm.py` | LE 로더, 재귀 하강 디스어셈블러 |
| `tools/lift.py --all` | 전체 프로그램 x86 → C 변환 (`build/game.c`, 약 28만 줄) |
| `tools/mkimage.py` | 재배치된 메모리 이미지 (`build/image.bin`) |
| `runtime/x86.h` | 게스트 메모리, 플래그, ALU, 런타임 훅 |
| `runtime/game.c` | DOS/DOS4GW/DPMI/VGA/키보드/마우스 대체 구현, SDL2 창 |
| `tools/ckdiff.py`, `tools/bisect_call.sh` | 디버깅: 함수 진입 상태를 덤프해 Unicorn(원본 x86)과 비교 |

변환 방식과 검증은 [LIFTER.md](LIFTER.md), 바이너리 분석은 [SCOPING.md](SCOPING.md)에 있습니다.

## 부팅하면서 고친 것

`build/war`가 맵까지 가는 동안 막혔던 지점과 원인입니다. 각각 아래 디버깅 도구로 원본과 비교해 찾았습니다.

| 증상 | 원인 | 수정 |
|---|---|---|
| CRT FPU 감지에서 `fld1` 트랩 | x87 미지원 | `fninit`/`fnstcw`를 FPU 없는 386처럼 처리 |
| 공유 에필로그를 가진 함수가 시작하자마자 반환 | 주소순 배치로 낮은 주소의 공유 코드가 함수 맨 앞에 옴 | 진입 지점이 첫 명령이 아니면 `goto` |
| `int386x`에서 잘못된 복귀 | `push`/`ret`으로 `int N; ret` 스텁에 점프 | 해당 함수(`0x3CC50`)를 런타임 구현으로 대체 |
| 자원 테이블이 516바이트만 복사됨 | capstone이 `f2 a5`(repne movsd)의 접두사를 버림(7곳) | 원시 바이트에서 `F2`/`F3` 접두사를 읽음 |
| "Please insert Warcraft CD" | CD 판별: 여유 공간 0 + 파일 존재 + 속성 변경 실패 | D: 드라이브를 읽기 전용 CD로 흉내, 가상 `path.war` |
| 브리핑 후 잘못된 복귀 | 스크립트 인터프리터 핸들러가 자기 복귀 주소를 버리고 탈출(`0x10498`) | 피호출자가 우리 프레임까지 정리했으면 바깥으로 반환 전파 |
| (예방) 입력 처리 중 스택 덮어쓰기 가능 | 포트 I/O 훅이 레지스터를 내보내지 않고 ISR을 호출할 수 있음 | 포트 I/O 전후로 레지스터 저장·복원 |

## 자동 실행 · 디버깅

```bash
# 창 없이, 정해진 시각에 입력을 넣고 화면을 저장 (초:동작)
SDL_VIDEODRIVER=dummy WAR_INPUT="6:esc,8:return,10:return,12:return,15:click@160,100,18:space,21:return,25:click@160,180,28:snap" \
  WAR_SNAPSHOT=30 ./build/war          # build/screen_28.ppm, build/screen.ppm

# 디버그 빌드: 그림자 호출 스택, 함수 진입 덤프, 메모리 쓰기 감시
make war GAME_DEFS=-DRECOMP_TRACE
WAR_DUMP_AT=318a0 ./build/war && python3 tools/ckdiff.py build/dump_318a0.bin
WAR_WATCH=64ee4,8 ./build/war
WAR_TRACE=1 ./build/war                # 모든 인터럽트 기록
```

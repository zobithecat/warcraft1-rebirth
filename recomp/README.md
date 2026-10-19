# WarCraft: Orcs & Humans (DOS 1.12) — 네이티브 arm64 재컴파일

원본 `WAR.EXE`(Watcom C/C++32, DOS/4GW)의 x86 기계어를 **함수 1,338개 전부 C로 변환**하고,
clang으로 **맥 arm64 네이티브 실행 파일**(`build/war`)을, Emscripten으로 **브라우저용 WebAssembly**(`build/web`)를 만듭니다. 에뮬레이터 없이 원본 게임 로직이 그대로 돌고,
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

### 브라우저 (WebAssembly)

```bash
cd recomp
make serve        # build/web을 만들고 http://localhost:8000/ 에서 서비스
```

필요한 것: 위 항목 + Emscripten(`brew install emscripten`), Node.js(헤드리스 테스트용).

- 같은 `build/game.c`와 `runtime/game.c`를 `emcc`로 빌드합니다. 게임 루프가 브라우저에 제어를 돌려주지 않으므로
  게임은 Web Worker(`web/worker.js`)에서 돌고, 화면은 `postMessage`로, 입력은 `SharedArrayBuffer` 링으로 주고받습니다.
  `SharedArrayBuffer`에는 COOP/COEP 헤더가 필요해 `tools/serve.py`로 서비스해야 합니다.
- 게임 데이터(`work/game`, 약 70MB)는 `build/web/war.data`로 묶여 같은 서버에서 읽힙니다. 이 파일은 빌드 산출물이며
  저작권이 있는 원본 데이터이므로 공개 서버에 올리지 마세요.
- 저장 파일은 브라우저 메모리에만 있고 새로고침하면 사라집니다.
- URL 파라미터가 환경 변수가 됩니다: `?input=6:esc,8:return` → `WAR_INPUT`, `?trace=1` → `WAR_TRACE`.
- `make wasm-test`: 같은 wasm을 Node.js에서 창 없이 실행(`build/web/war-node.js`, 실제 파일 시스템 사용).
  네이티브와 같은 입력 스크립트를 주면 화면이 픽셀 단위로 같은지 비교할 수 있습니다.

## 지금 되는 것 / 안 되는 것

확인한 흐름(창 없이 입력 스크립트로 재현, 아래 "자동 실행" 참고):

- 인트로 동영상과 자막 → 메인 메뉴 → 싱글 플레이 → 캠페인 선택 → 오크 1번 임무 브리핑 → **맵 로드, 유닛 선택, Move 명령으로 유닛 이동**
- wasm(Node)과 네이티브에 같은 스크립트를 주었을 때 맵 화면 10장(1초 간격)이 픽셀 단위로 같음. 브라우저에서 키보드·마우스로 같은 흐름 확인.

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
| Move 목적지를 찍으면 "call to 2885c (no lifted function)" | 함수 포인터 슬롯에 저장되는 핸들러(`mov [0x5921c], 0x2885c` 등 15개)가 이미 다른 경로로 디코딩돼 함수 시작으로 표시되지 않음 | 즉치값으로 주소가 쓰이는 디코딩된 명령은 함수 진입점으로 등록 |
| 스크립트 클릭이 한 박자 늦게, 엉뚱한 곳에 반영 | 게임은 버튼 이벤트에 콜백 좌표가 아니라 마지막으로 그린 커서 좌표(`0x617ea`)를 기록 | 스크립트 클릭은 이동 → 100ms 뒤 누름 → 100ms 뒤 뗌. 너무 짧은 클릭의 뗌은 100ms까지 보류 |

## 자동 실행 · 디버깅

```bash
# 창 없이, 정해진 시각에 입력을 넣고 화면을 저장 (초:동작, 시각 순서대로; click@/rclick@ 좌표는 320x200)
# 그런트 선택 → Move 버튼 → 목적지 클릭
SDL_VIDEODRIVER=dummy WAR_INPUT="6:esc,8:return,10:return,12:return,15:click@160,100,18:space,21:return,25:click@130,130,27.5:click@18,127,29.5:click@200,150,33:snap" \
  WAR_SNAPSHOT=34 ./build/war          # build/screen_33.ppm, build/screen.ppm

# 디버그 빌드: 그림자 호출 스택, 함수 진입 덤프, 메모리 쓰기 감시
make war GAME_DEFS=-DRECOMP_TRACE
WAR_DUMP_AT=318a0 ./build/war && python3 tools/ckdiff.py build/dump_318a0.bin
WAR_WATCH=64ee4,8 ./build/war
WAR_TRACE=1 ./build/war                # 모든 인터럽트 기록
```

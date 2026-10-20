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

- 조작: 원본 조작(명령 버튼 → 대상 클릭, Shift+클릭으로 최대 4명 선택)에 요즘 RTS 조작을 더했습니다. 창 크기는 960×600(3배)입니다.
  - **드래그 선택**: 맵에서 왼쪽 버튼으로 상자를 그리면 상자 안의 내 유닛을 최대 4명 선택합니다(Shift+드래그는 추가).
  - **우클릭 명령**: 내 유닛을 선택하고 우클릭하면 대상에 따라 적 유닛 → 공격, 금광·나무 → 수확(일꾼), 그 밖 → 이동.
    유닛이 선택되지 않았거나 건물·적을 보고 있을 때의 우클릭은 원본처럼 그 지점으로 화면을 옮깁니다.
  - 원본에는 이런 조작이 없어서 런타임이 게임 자신의 선택·명령 함수를 불러 구현합니다(아래 "요즘 RTS 조작").
- 인트로는 ESC로 건너뜁니다. CD 검사는 런타임이 D: 드라이브를 CD-ROM처럼 흉내 내서 통과시킵니다.
- 설정·저장 파일은 `work/game/`에 생깁니다.
- 소리: 효과음·음성과 음악(AdLib)이 나옵니다(아래 "소리"). `WAR_MUTE=1`이면 끄고, `SDL_VIDEODRIVER=dummy`(창 없는 실행)에서는 자동으로 꺼집니다.

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
  저작권이 있는 원본 데이터이므로 공개 서버에 올리지 마세요(`make deploy`가 비밀번호를 거는 이유).
- 저장 파일은 브라우저 메모리에만 있고 새로고침하면 사라집니다.
- 소리는 브라우저 정책 때문에 화면을 처음 클릭(또는 키 입력)할 때 켜집니다. 워커가 만든 소리를 `SharedArrayBuffer` 링으로
  `web/audio.js`(AudioWorklet)에 넘깁니다.
- URL 파라미터가 환경 변수가 됩니다: `?input=6:esc,8:return` → `WAR_INPUT`, `?trace=1` → `WAR_TRACE`.
- `make deploy`: `build/web`을 AWS에 올립니다(AWS CLI의 현재 자격 증명·리전 사용, `tools/deploy_aws.py`).
  모든 공개 접근을 막은 S3 버킷 ← CloudFront(Origin Access Control). CloudFront Function이 HTTP 기본 인증을 검사하고,
  응답 헤더 정책이 COOP/COEP를 붙입니다(S3 정적 웹사이트 호스팅만으로는 이 헤더를 붙일 수 없음). `war.data`는 gzip으로 올려 74MB → 49MB.
  주소·사용자·비밀번호와 리소스 ID는 `work/deploy.json`(git 제외)에 저장됩니다. 다시 실행하면 바뀐 파일만 올리고(객체 메타데이터의
  sha256과 비교) 그 경로만 캐시 무효화합니다. 비밀번호 교체는 `python3 tools/deploy_aws.py --new-password`.
- `make hooks`: master를 푸시할 때마다 `make deploy`가 자동으로 돕니다(`tools/git-hooks/pre-push`, `git config core.hooksPath`).
  git에는 푸시 뒤 훅이 없어 푸시 직전에 배포하고, 배포가 실패하면 푸시를 멈춥니다. 배포는 작업 트리로 빌드하므로
  `recomp/`에 커밋 안 된 변경이 있거나 푸시하는 커밋이 체크아웃된 커밋이 아니면 거부합니다.
  배포 없이 푸시: `SKIP_DEPLOY=1 git push`(또는 `git push --no-verify`). 훅 설정은 clone마다 `make hooks`로 한 번 해야 합니다.
- `make wasm-test`: 같은 wasm을 Node.js에서 창 없이 실행(`build/web/war-node.js`, 실제 파일 시스템 사용).
  네이티브와 같은 입력 스크립트를 주면 화면이 픽셀 단위로 같은지 비교할 수 있습니다.

## 지금 되는 것 / 안 되는 것

확인한 흐름(창 없이 입력 스크립트로 재현, 아래 "자동 실행" 참고):

- 인트로 동영상과 자막 → 메인 메뉴 → 싱글 플레이 → 캠페인 선택 → 오크 1번 임무 브리핑 → **맵 로드, 유닛 선택, Move 명령으로 유닛 이동**
- 드래그로 4명 선택 → 우클릭 이동, 일꾼 우클릭으로 금광 채굴(금 1000 → 1300)·숲으로 이동, 그런트 우클릭으로 적 풋맨 공격.
  네이티브 스크립트와 브라우저(실제 마우스 드래그·우클릭)에서 확인.
- wasm(Node)과 네이티브에 같은 스크립트를 주었을 때 맵 화면 10장(1초 간격)이 픽셀 단위로 같음. 브라우저에서 키보드·마우스로 같은 흐름 확인.

아직 확인하지 않았거나 지원하지 않는 것:

- 음악의 보이스 9개가 모자랄 때 어느 음을 끊을지는 원본 드라이버와 다릅니다(비교한 30초 동안 517음 중 오래 끄는 음 3개가 더 일찍 끊김).
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
| `runtime/game.c` | DOS/DOS4GW/DPMI/VGA/키보드/마우스 대체 구현, SDL2 창·오디오, 사운드 래퍼 대체 |
| `runtime/sound.c` | 효과음 믹서, XMIDI 재생, AIL AdLib 드라이버 동작, OPL2 모델 |
| `tools/soundtest.c`, `tools/soundcmp.py` | 소리 검증: 곡·레지스터 기록을 WAV로 렌더, DOSBox-X 녹음과 비교 |
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

## 소리

원본은 Blizzard 사운드 래퍼 → Miles AIL 3 → 실모드 사운드 카드 드라이버(.DIG/.MDI)로 소리를 냅니다. 래퍼 함수 15개
(lift.py `HLE`, 효과음 재생·반복·정지, 음악 등록·시작·정지·페이드, 볼륨 등)를 런타임이 대신하므로 AIL과 DOS 드라이버는 돌지 않고,
`runtime/sound.c`가 직접 소리를 만듭니다.

- **설정**: 게임은 `config.war`(SETUP.EXE가 씀)가 없으면 소리를 끕니다. 런타임이 Sound Blaster + AdLib으로 된 가상 `config.war`를 줍니다.
- **효과음·음성**: 게임이 넘기는 WAV/Creative VOC 이미지(8비트 11kHz)를 디코딩해 4채널로 섞습니다(원본처럼 4개, 넘치면 차례로 교체).
  게임은 "재생 중인 효과음 수"로 음성이 끝나길 기다리므로 재생은 실제 시간에 맞춰 끝납니다.
- **음악**: 게임의 XMIDI(OPL2용 곡) → AIL의 AdLib 드라이버가 하던 일(게임 음색 은행 `DRIVERS/WARCRAFT.AD`, 9보이스, 타악기는 bank 127,
  세기 감도 표, 120Hz 틱, FOR/NEXT 반복) → 직접 작성한 OPL2(YM3812) 모델(2연산자 FM, 파형 4종, 매뉴얼 표 기준 엔벌로프, KSL,
  트레몰로·비브라토, 피드백)을 49716Hz로 돌려 48kHz로 리샘플링.

### 원본과 비교

DOSBox-X로 원본 게임을 실행해(`DX-CAPTURE /A /O WAR.EXE`, `oplemu=nuked`) 인트로 음악을 녹음하고, 원본 AIL 드라이버가 쓴
OPL 레지스터 기록(.dro)과 비교했습니다(`tools/soundcmp.py`, `tools/soundtest.c`, `make build/soundtest`).

| 비교 | 결과 |
|---|---|
| key-on 517개: 음 높이(fnum/block)·음색 레지스터 10개·시각 | 517개 모두 일치(60ms 이내) |
| 음량 레지스터(0x40) | 515개 일치, 2개 1단위(0.75dB) 차이 |
| 음 길이(key-on → key-off) | 514개 중 508개 50ms 이내. 다른 6개는 보이스 부족 시 끊는 음 선택 차이 |
| 원본 레지스터 기록을 우리 OPL로 재생 vs Nuked OPL 녹음 | 스펙트럼 프레임 유사도 0.83, 대역별 균형 차이 ±1dB 이내 |
| 우리 드라이버 + OPL vs 원본 녹음 | 유사도 0.80, 음량 비 1.02, 대역별 ±1dB(250–500Hz만 -3.6dB) |

음악 음량은 DOSBox-X의 AdLib 믹스 레벨에 맞췄고, 효과음 피크도 같은 녹음의 음성 피크와 비슷합니다.

## 요즘 RTS 조작

원본 코드는 그대로 두고, lift.py `WRAP`으로 지정한 두 함수만 런타임이 먼저 처리합니다(처리하지 않으면 원본 실행).
둘 다 게임이 입력을 처리하는 자리(메인 루프)에서 불리므로 게임 상태를 원본과 같은 시점에 바꿉니다.

| 가로챈 함수 | 원본 동작 | 추가한 동작 |
|---|---|---|
| `0x1B468` 맵 우클릭 | 그 지점으로 화면 이동 | 내 유닛이 선택돼 있으면 명령 ID(`[0x5A4D4]`: 3 이동, 4 공격, 10 수확)를 정하고 게임의 명령 함수 `0x2E384(타일x, 타일y, 대상)` 호출 — 명령 버튼 뒤 대상 클릭과 같은 경로 |
| `0x1A2B0` 왼쪽 버튼 뗌 | 입력 핸들러 재설정 | 드래그가 끝났으면 상자 안 유닛으로 게임의 선택 함수 `0x25C50(개수, 배열)` 호출 — 클릭·Shift+클릭이 끝내 부르는 함수 |

판정에 쓰는 게임 데이터(메모리 덤프 비교와 그 값을 쓰는 코드로 확인): 선택 배열 `0x59E00`, 커서 아래 유닛 `0x5A4CC`,
살아 있는 유닛 목록 `0x5A1A0`, 뷰포트 타일 `0x500D0`, 타일 플래그 `[0x5828C]`(0x80 숲, 0x40 물, 0x1000 건물),
유닛 구조체(0x5C바이트: `+0` 픽셀 좌표, `+0x1B` 종류, `+0x1E` 소유자), 진영 관계 `0x5008C`.

게임은 버튼 이벤트를 마지막으로 그린 커서 위치에 기록하므로, 마우스를 옮기자마자 누르면 이전 위치가 쓰입니다.
런타임은 누름 이벤트를 게임 커서가 따라올 때까지(최대 100ms) 잠깐 붙잡아 둡니다.

## 자동 실행 · 디버깅

```bash
# 창 없이, 정해진 시각에 입력을 넣고 화면을 저장 (초:동작, 시각 순서대로; 좌표는 320x200)
#   click@x,y rclick@x,y shift+click@x,y move@x,y drag@x1,y1,x2,y2 fastdrag@... 키 이름(esc, return, ...)
#   snap(화면 저장) dump(게스트 메모리 64MB를 build/mem_<0.1초>.bin으로) quit
# 그런트 선택 → Move 버튼 → 목적지 클릭
SDL_VIDEODRIVER=dummy WAR_INPUT="6:esc,8:return,10:return,12:return,15:click@160,100,18:space,21:return,25:click@130,130,27.5:click@18,127,29.5:click@200,150,33:snap" \
  WAR_SNAPSHOT=34 ./build/war          # build/screen_33.ppm, build/screen.ppm

# 디버그 빌드: 그림자 호출 스택, 함수 진입 덤프, 메모리 쓰기 감시
make war GAME_DEFS=-DRECOMP_TRACE
WAR_DUMP_AT=318a0 ./build/war && python3 tools/ckdiff.py build/dump_318a0.bin
WAR_WATCH=64ee4,8 ./build/war
WAR_TRACE=1 ./build/war                # 모든 인터럽트 기록
WAR_WAV=build/audio.wav ./build/war    # 나온 소리를 WAV로도 저장
```

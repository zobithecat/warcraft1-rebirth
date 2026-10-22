# Worms (DOS, 1995) — 네이티브 arm64 재컴파일

[../recomp](../recomp)의 변환기와 CPU 코어를 그대로 쓰고, 게임별 부분(프로필, 런타임)만 여기 있습니다.
게임 파일은 들어 있지 않습니다. 직접 가진 CD 이미지가 필요합니다.

## 실행

```bash
python3 tools/extract.py /path/to/CDWORMS.cue   # work/cd(D:), work/game(C:), work/audio.json (.bin은 .cue 옆)
make                                           # build/game.c, build/image.bin, build/worms
make run
```

## 지금 되는 것 / 안 되는 것

- 부팅 → 메인 메뉴 → 팀 선택 → 지형 생성 → 대전(이동, 조준, 발사, 폭발, 지형 파괴)까지 돕니다.
- 마우스는 창 안의 포인터 위치로 게임 커서를 맞춥니다(게임은 매 프레임 드라이버 위치를 가운데로 되돌리는 상대 입력을 씀).
- 아직 없음: 소리(Sound Blaster 효과음, CD 오디오 음악은 무음), 오프닝 FMV(외부 플레이어 실행은 건너뜀), 브라우저 빌드.

## WarCraft와 다른 점

| 항목 | 내용 |
|---|---|
| x87 | 탄도·CRT가 FPU를 씀. `tools/profile.py`의 `FPU = True`로 lift.py가 x87을 변환(`recomp/tools/x87test.py`로 검증) |
| 자기 수정 코드 | 믹서·배경 루틴이 자기 명령의 변위/즉치를 고침(1432개). `PATCH_OPERANDS`로 실행 시 메모리에서 읽음. 펼친 루프의 복사본(`[edi + 0x3A9FE]`, 0x84 간격 80개)은 첫 복사본과 같은 바이트를 찾아 함께 처리 |
| 메모리 배치 | 데이터 오브젝트(2.1MB)가 원래 기준 주소 0x50000에서는 VGA 창(0xA0000)을 덮어, 화면 복사가 게임 데이터를 망가뜨림. `--bases 2=0x110000`으로 1MB 위로 옮김 |
| VGA | 모드 13h와 모드 X(평면 메모리, 쓰기 모드, 래치, CRTC 시작 주소) |
| 타이머 | PIT를 ~72Hz로 설정하고 IRQ0 핸들러로 진행. 루프 안에서도 돌도록 분기 예산이 다 되면(`Hooks.budget`) 별도 스택에서 핸들러 실행 |
| CD | D:는 데이터 트랙 폴더. MSCDEX(DPMI 0300h → int 2Fh 1510h) 요청에 오디오 트랙 표·재생 위치를 답함 |
| 드라이브 | `WORMS.EXE`가 CD에서 `WRMS.EXE`를 띄우므로 현재 드라이브는 D: |

## 자동 실행

```bash
# 메뉴에서 PLAY GAME → 팀 둘 선택 → START, 대전 중 발사
WAR_MUTE=1 WAR_INPUT="36:click@160,64,39:hold@24,44,400,41:hold@24,52,400,43:rclick@24,60,45:click@205,154,97:keyhold@space,700,99:snap,100:quit" build/worms
```

WarCraft 런타임의 스크립트 명령(`click@`, `hold@`, `snap`, `dump`, ...)에 `keyhold@키,ms`가 더해졌습니다.

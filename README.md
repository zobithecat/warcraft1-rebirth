# warcraft1-rebirth

WarCraft: Orcs & Humans(DOS, 1994, v1.12)의 실행 파일을 x86 기계어에서 C로 정적 재컴파일해
맥 arm64 네이티브와 WebAssembly로 돌려 보는 **개인 연구·실험 프로젝트**입니다.
변환기, 런타임(DOS/DPMI/VGA/입력/사운드 대체), 검증 도구가 들어 있습니다. 자세한 내용은 [recomp/README.md](recomp/README.md).
같은 변환기로 Worms(DOS, 1995, Team17)도 옮기는 중입니다: [worms/README.md](worms/README.md).
Worms의 이름과 게임 코드·데이터는 Team17의 것이고, 이 프로젝트는 Team17과 관계가 없습니다.

> **이 저장소에는 게임이 들어 있지 않습니다.** 게임 실행 파일, 데이터, 그리고 그것에서 만들어지는 결과물은
> 포함하지 않고, 구할 곳도 안내하지 않습니다. 돌려 보려면 직접 정당하게 가진 원본이 필요합니다.

## 필요한 원본

- 미국판 CD-ROM, 버전 1.12. 디스크 식별: [redump.org disc 84852](http://redump.org/disc/84852/)
  (다운로드가 없는 보존 데이터베이스로, 체크섬만 확인할 수 있습니다).
- 본인 CD를 이미지로 떠서 `CD_DIC/WARCRAFT.bin`에 두면 빌드가 실행 파일을 꺼냅니다.
  꺼낸 `war.exe`의 SHA-256: `de7d38ed9b00d5bc849dbf45189fe4674185064dd538d95f156e1b60f70514db`

## 하면 안 되는 것

- **빌드 결과물을 배포하지 마세요.** `recomp/build/`와 `recomp/work/`(변환된 게임 코드 `game.c`, `image.bin`,
  `war.wasm`, `war.data`, 꺼낸 게임 파일)는 원본 게임에서 나온 것이라 Blizzard의 저작물입니다.
  `.gitignore`가 커밋을 막고, 웹 빌드(`make deploy`)는 비밀번호를 걸어 본인만 쓰도록 되어 있습니다.
- **상업적으로 쓰지 마세요.** 이 저장소의 라이선스는 비상업 목적만 허용합니다.

## 라이선스

- 이 저장소의 코드와 문서: [PolyForm Noncommercial License 1.0.0](LICENSE).
  개인 사용, 연구, 실험, 시험, 취미 같은 비상업 목적에 한해 사용·수정·배포할 수 있습니다.
  상업적 사용은 허용하지 않습니다.
- WarCraft, Orcs & Humans의 이름·상표와 게임의 코드·데이터·그래픽·소리는 Blizzard Entertainment의 것입니다.
  이 프로젝트는 Blizzard와 관계가 없고, Blizzard가 승인하거나 지원하지 않습니다.
- 소리 부분은 게임의 Miles AIL 동작을 관찰해 다시 구현한 것이고 AIL 코드나 드라이버를 포함하지 않습니다.
  OPL2 모델은 이 프로젝트에서 새로 작성했습니다.
- 보증 없음: 라이선스의 "No Liability" 조항대로 있는 그대로 제공합니다.

---

**English.** A personal research project that statically recompiles the DOS executable of
WarCraft: Orcs & Humans (1994, v1.12) from x86 to C and runs it natively on arm64 macOS and in
WebAssembly. **No game files are included or linked**; you need your own legitimately obtained
original (US CD-ROM v1.12, [redump 84852](http://redump.org/disc/84852/)). Do not distribute build
output: it is derived from Blizzard's copyrighted game. The code in this repository is licensed under
the [PolyForm Noncommercial License 1.0.0](LICENSE) (noncommercial use only). WarCraft is a trademark of
Blizzard Entertainment; this project is not affiliated with or endorsed by Blizzard.

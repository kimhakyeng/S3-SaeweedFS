#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""테스트 이미지 대량 생성기.

100KB 더미 JPG 를 지정 폴더들에 채운다 (기본: khktest 100GB + 루미너스 3개 폴더 합계 100GB).
- 폴더당 파일 수천~수십만 개가 되면 NTFS/탐색기가 힘들어지므로 part_0001, part_0002 ...
  하위 폴더에 1,000개씩 나눠 담는다. (수집 필터에는 영향 없음 — 경로 중 한 폴더만 패턴에 맞으면 됨)
- 중간에 끊겨도 다시 실행하면 이어서 생성한다 (완성된 하위 폴더는 통째로 스킵).
- 시작 전에 디스크 여유 공간을 확인하고 부족하면 중단한다.

용량을 바꾸려면 아래 TARGETS 의 GB 숫자만 수정.
"""
import os
import shutil
import sys
import time

FILE_KB = 100        # 파일 1장 크기 (KB)
PER_SUB = 1000       # 하위 폴더(part_XXXX)당 파일 수

# (경로, GB) — 필요하면 숫자만 바꿔서 사용
TARGETS = [
    (r"C:\khktest\S3test", 50.0),
    (r"C:\S3_TEST\루미너스\2026-07-01", 50.0),
    (r"C:\S3_TEST\루미너스\2026-07-02", 50.0),
    (r"C:\S3_TEST\루미너스\2026-07-03", 50.0),
]


def build_payload(kb: int) -> bytes:
    """JPEG 시그니처로 감싼 100KB 더미 (내용은 랜덤 1회 생성 후 전 파일 공유 — 생성 속도 최우선)."""
    body = os.urandom(kb * 1024 - 6)
    return b"\xff\xd8\xff\xe0" + body + b"\xff\xd9"


def main() -> int:
    files_per_gb = int(1024 * 1024 / FILE_KB)          # 10,485개/GB
    plan = [(root, gb, int(gb * files_per_gb)) for root, gb in TARGETS]
    total_gb = sum(gb for _, gb, _ in plan)
    total_files = sum(n for _, _, n in plan)

    free_gb = shutil.disk_usage("C:\\").free / (1024 ** 3)
    print("=" * 60)
    print(f"생성 계획: 총 {total_gb:.0f}GB / {total_files:,}개 (개당 {FILE_KB}KB)")
    for root, gb, n in plan:
        print(f"  - {root}  →  {gb}GB, {n:,}개")
    print(f"C: 드라이브 여유 공간: {free_gb:.0f}GB (필요: {total_gb + 10:.0f}GB 이상)")
    print("=" * 60)
    if free_gb < total_gb + 10:
        print("!! 여유 공간 부족 — 중단합니다. TARGETS 의 GB 를 줄이거나 공간을 확보하세요.")
        return 1
    if input("진행할까요? (y 입력 시 시작): ").strip().lower() != "y":
        print("취소했습니다.")
        return 0

    payload = build_payload(FILE_KB)
    t0 = time.time()
    made = 0

    for root, gb, count in plan:
        subs = (count + PER_SUB - 1) // PER_SUB
        print(f"\n[{root}] {count:,}개 생성 (part_0001 ~ part_{subs:04d})")
        for si in range(subs):
            sub = os.path.join(root, f"part_{si + 1:04d}")
            os.makedirs(sub, exist_ok=True)
            n_here = min(PER_SUB, count - si * PER_SUB)
            try:
                existing = len(os.listdir(sub))
            except OSError:
                existing = 0
            if existing >= n_here:      # 이미 완성된 폴더 — 통째로 스킵 (재개 지원)
                made += n_here
                continue
            partial = existing > 0
            for fi in range(n_here):
                fp = os.path.join(sub, f"IMG_{si + 1:04d}_{fi + 1:04d}.jpg")
                if partial and os.path.exists(fp):
                    made += 1
                    continue
                with open(fp, "wb") as f:
                    f.write(payload)
                made += 1
                if made % 20000 == 0:
                    el = time.time() - t0
                    rate = made / el if el > 0 else 0
                    eta_min = (total_files - made) / rate / 60 if rate > 0 else 0
                    print(f"  진행 {made:,}/{total_files:,}  ({rate:,.0f}개/초, 남은 예상 {eta_min:,.0f}분)")

    el = time.time() - t0
    print(f"\n완료: {made:,}개 생성, {el / 60:,.1f}분 소요")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n중단됨 — 다시 실행하면 이어서 생성합니다.")
        sys.exit(130)

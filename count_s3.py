"""
count_s3.py
SeaweedFS(S3 호환) 버킷의 객체 개수를 세는 유틸. 노드 GUI의 count 와 비교용.
백엔드와 동일하게 listObjectsV2 페이지네이션으로 전수 카운트한다.

필요: pip install boto3

사용 예 (Windows):
    set AWS_ACCESS_KEY_ID=b0e220d8d7baa08c48b2
    set AWS_SECRET_ACCESS_KEY=<your-secret>
    python count_s3.py --bucket khk
    python count_s3.py --bucket khk --prefix 2026-06-23/
    python count_s3.py --bucket khktest --endpoint http://10.1.55.225:28333

키를 인자로 직접 줄 수도 있음:
    python count_s3.py --bucket khk --access-key XXX --secret-key YYY
"""

import argparse
import os
import sys

try:
    import boto3
    from botocore.config import Config
except ImportError:
    print("boto3 가 필요합니다:  pip install boto3")
    sys.exit(1)


def main() -> int:
    ap = argparse.ArgumentParser(description="SeaweedFS/S3 버킷 객체 수 카운트")
    ap.add_argument("--endpoint", default="http://10.1.55.225:28333", help="S3 엔드포인트")
    ap.add_argument("--bucket", required=True, help="버킷명 (예: khk, khktest)")
    ap.add_argument("--prefix", default="", help="접두사(폴더). 예: 2026-06-23/")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--access-key", default=os.environ.get("AWS_ACCESS_KEY_ID", ""))
    ap.add_argument("--secret-key", default=os.environ.get("AWS_SECRET_ACCESS_KEY", ""))
    ap.add_argument("--no-path-style", action="store_true", help="path-style 끄기(기본 켜짐)")
    args = ap.parse_args()

    if not args.access_key or not args.secret_key:
        print("키가 없습니다. 환경변수 AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY 를 설정하거나")
        print("--access-key / --secret-key 로 전달하세요.")
        return 1

    s3 = boto3.client(
        "s3",
        endpoint_url=args.endpoint,
        aws_access_key_id=args.access_key,
        aws_secret_access_key=args.secret_key,
        region_name=args.region,
        config=Config(s3={"addressing_style": "path" if not args.no_path_style else "virtual"}),
    )

    print(f"[대상] {args.endpoint}  bucket={args.bucket}  prefix='{args.prefix}'")
    print("[진행] 카운트 중... (객체가 많으면 시간이 걸립니다)\n")

    total = 0
    total_bytes = 0
    by_top = {}          # 최상위 폴더별 개수 (날짜 폴더 비교용)
    token = None
    while True:
        kw = dict(Bucket=args.bucket, Prefix=args.prefix, MaxKeys=1000)
        if token:
            kw["ContinuationToken"] = token
        resp = s3.list_objects_v2(**kw)
        for obj in resp.get("Contents", []):
            total += 1
            total_bytes += obj.get("Size", 0)
            key = obj["Key"]
            top = key.split("/", 1)[0] if "/" in key else "(root)"
            by_top[top] = by_top.get(top, 0) + 1
        if total and total % 50000 == 0:
            print(f"  ...{total:,}개")
        if resp.get("IsTruncated"):
            token = resp.get("NextContinuationToken")
        else:
            break

    print("\n================ 결과 ================")
    print(f"총 객체 수 : {total:,} 개")
    print(f"총 용량    : {total_bytes/1048576:,.1f} MB ({total_bytes/1073741824:,.2f} GB)")
    if len(by_top) > 1 or (by_top and args.prefix == ""):
        print("\n[최상위 폴더별]")
        for k in sorted(by_top):
            print(f"  {k:<20} {by_top[k]:,} 개")
    print("=====================================")
    print("\n→ 이 '총 객체 수'를 노드 GUI 의 count 와 비교하세요.")
    print("  (GUI count 는 PathPrefix 가 비어있으면 버킷 전체 기준입니다.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

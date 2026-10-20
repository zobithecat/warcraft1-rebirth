#!/usr/bin/env python3
"""Deploy build/web to a private S3 bucket behind CloudFront, password protected.

  S3 bucket (all public access blocked) <- CloudFront (origin access control)
    viewer-request: CloudFront Function checking HTTP basic auth
    response headers policy: COOP/COEP, which SharedArrayBuffer needs

war.data is the original, copyrighted game data, hence the password.  The
password and the resource ids live in work/deploy.json (not in git); rerunning
reuses them and uploads only the files that changed (by a sha256 kept in each
object's metadata).  Uses the AWS CLI's current credentials and region.

Usage: deploy_aws.py [--new-password] [--no-wait]
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import pathlib
import secrets
import shutil
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
WEB = ROOT / "build" / "web"
STATE = ROOT / "work" / "deploy.json"
STAGE = ROOT / "build" / "web-deploy"
NAME = "warcraft1-rebirth"
USER = "war"
CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"   # AWS managed cache policy

# published name -> (content type, pre-gzip)
FILES = {
    "index.html": ("text/html; charset=utf-8", False),
    "worker.js": ("text/javascript", False),
    "audio.js": ("text/javascript", False),
    "war.js": ("text/javascript", False),
    "war.wasm": ("application/wasm", False),          # CloudFront compresses it (< 10MB)
    "war.data": ("application/octet-stream", True),   # too big for CloudFront compression
}


def aws(*args: str, check: bool = True) -> dict:
    r = subprocess.run(["aws", *args, "--output", "json"], capture_output=True, text=True)
    if r.returncode != 0:
        if check:
            sys.exit(f"aws {' '.join(args[:2])}: {r.stderr.strip()}")
        return {"_error": r.stderr}
    return json.loads(r.stdout) if r.stdout.strip() else {}


def auth_function(password: str) -> str:
    token = base64.b64encode(f"{USER}:{password}".encode()).decode()
    return f"""function handler(event) {{
  var h = event.request.headers.authorization;
  if (h && h.value === "Basic {token}") return event.request;
  return {{
    statusCode: 401,
    statusDescription: "Unauthorized",
    headers: {{ "www-authenticate": {{ value: 'Basic realm="WarCraft", charset="UTF-8"' }} }}
  }};
}}
"""


def ensure_bucket(st: dict, account: str, region: str) -> None:
    st.setdefault("bucket", f"{NAME}-{account}")
    b = st["bucket"]
    if "_error" in aws("s3api", "head-bucket", "--bucket", b, check=False):
        args = ["s3api", "create-bucket", "--bucket", b]
        if region != "us-east-1":
            args += ["--create-bucket-configuration", f"LocationConstraint={region}"]
        aws(*args)
        print(f"created bucket {b}")
    aws("s3api", "put-public-access-block", "--bucket", b, "--public-access-block-configuration",
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true")
    aws("s3api", "put-bucket-tagging", "--bucket", b, "--tagging", f"TagSet=[{{Key=Project,Value={NAME}}}]")


def ensure_oac(st: dict) -> None:
    if st.get("oac"):
        return
    for item in aws("cloudfront", "list-origin-access-controls")["OriginAccessControlList"].get("Items", []):
        if item["Name"] == NAME:
            st["oac"] = item["Id"]
            return
    cfg = {"Name": NAME, "Description": NAME, "SigningProtocol": "sigv4", "SigningBehavior": "always",
           "OriginAccessControlOriginType": "s3"}
    st["oac"] = aws("cloudfront", "create-origin-access-control", "--origin-access-control-config",
                    json.dumps(cfg))["OriginAccessControl"]["Id"]
    print("created origin access control")


def ensure_headers_policy(st: dict) -> None:
    if st.get("headers_policy"):
        return
    name = f"{NAME}-coop-coep"
    for item in aws("cloudfront", "list-response-headers-policies", "--type", "custom")["ResponseHeadersPolicyList"].get("Items", []):
        if item["ResponseHeadersPolicy"]["ResponseHeadersPolicyConfig"]["Name"] == name:
            st["headers_policy"] = item["ResponseHeadersPolicy"]["Id"]
            return
    cfg = {"Name": name, "Comment": "cross-origin isolation for SharedArrayBuffer",
           "CustomHeadersConfig": {"Quantity": 2, "Items": [
               {"Header": "Cross-Origin-Opener-Policy", "Value": "same-origin", "Override": True},
               {"Header": "Cross-Origin-Embedder-Policy", "Value": "require-corp", "Override": True}]}}
    st["headers_policy"] = aws("cloudfront", "create-response-headers-policy", "--response-headers-policy-config",
                               json.dumps(cfg))["ResponseHeadersPolicy"]["Id"]
    print("created response headers policy")


def ensure_function(st: dict) -> None:
    name = f"{NAME}-basic-auth"
    code = STAGE / "auth.js"
    code.write_text(auth_function(st["password"]))
    cfg = json.dumps({"Comment": "basic auth", "Runtime": "cloudfront-js-2.0"})
    cur = aws("cloudfront", "describe-function", "--name", name, "--stage", "DEVELOPMENT", check=False)
    if "_error" in cur:
        etag = aws("cloudfront", "create-function", "--name", name, "--function-config", cfg,
                   "--function-code", f"fileb://{code}")["ETag"]
        print("created auth function")
    else:
        etag = aws("cloudfront", "update-function", "--name", name, "--if-match", cur["ETag"],
                   "--function-config", cfg, "--function-code", f"fileb://{code}")["ETag"]
    st["function_arn"] = aws("cloudfront", "publish-function", "--name", name,
                             "--if-match", etag)["FunctionSummary"]["FunctionMetadata"]["FunctionARN"]
    code.unlink()


def ensure_distribution(st: dict, region: str) -> None:
    if st.get("distribution"):
        return
    origin = f"{st['bucket']}.s3.{region}.amazonaws.com"
    cfg = {
        "CallerReference": f"{NAME}-{int(time.time())}",
        "Comment": NAME,
        "Enabled": True,
        "DefaultRootObject": "index.html",
        "PriceClass": "PriceClass_200",
        "HttpVersion": "http2and3",
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3", "DomainName": origin, "OriginAccessControlId": st["oac"],
            "S3OriginConfig": {"OriginAccessIdentity": ""}}]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3",
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": CACHING_OPTIMIZED,
            "ResponseHeadersPolicyId": st["headers_policy"],
            "Compress": True,
            "AllowedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"],
                               "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}},
            "FunctionAssociations": {"Quantity": 1, "Items": [
                {"FunctionARN": st["function_arn"], "EventType": "viewer-request"}]},
        },
    }
    d = aws("cloudfront", "create-distribution-with-tags", "--distribution-config-with-tags",
            json.dumps({"DistributionConfig": cfg, "Tags": {"Items": [{"Key": "Project", "Value": NAME}]}}))
    st["distribution"] = d["Distribution"]["Id"]
    st["domain"] = d["Distribution"]["DomainName"]
    print(f"created distribution {st['distribution']}")


def ensure_bucket_policy(st: dict, account: str) -> None:
    policy = {"Version": "2012-10-17", "Statement": [{
        "Sid": "CloudFrontRead", "Effect": "Allow",
        "Principal": {"Service": "cloudfront.amazonaws.com"},
        "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{st['bucket']}/*",
        "Condition": {"StringEquals": {"AWS:SourceArn": f"arn:aws:cloudfront::{account}:distribution/{st['distribution']}"}}}]}
    aws("s3api", "put-bucket-policy", "--bucket", st["bucket"], "--policy", json.dumps(policy))


def upload(st: dict) -> list[str]:
    """Upload what changed since the last deploy; returns the published paths."""
    changed = []
    for name, (ctype, gz) in FILES.items():
        src = WEB / name
        if not src.exists():
            sys.exit(f"{src} missing: run make wasm first")
        digest = hashlib.sha256(src.read_bytes()).hexdigest()
        head = aws("s3api", "head-object", "--bucket", st["bucket"], "--key", name, check=False)
        if head.get("Metadata", {}).get("source-sha256") == digest:
            continue
        args = ["s3", "cp", str(src), f"s3://{st['bucket']}/{name}", "--content-type", ctype,
                "--cache-control", "no-cache", "--metadata", f"source-sha256={digest}", "--only-show-errors"]
        if gz:
            packed = STAGE / name
            with open(src, "rb") as fi, gzip.open(packed, "wb", compresslevel=6) as fo:
                shutil.copyfileobj(fi, fo)
            args[2] = str(packed)
            args += ["--content-encoding", "gzip"]
        aws(*args)
        print(f"uploaded {name}")
        changed.append("/" + name)
        if name == "index.html":
            changed.append("/")
    if changed:
        aws("cloudfront", "create-invalidation", "--distribution-id", st["distribution"], "--paths", *changed)
    else:
        print("nothing changed since the last deploy")
    return changed


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--new-password", action="store_true")
    ap.add_argument("--no-wait", action="store_true")
    args = ap.parse_args()
    account = aws("sts", "get-caller-identity")["Account"]
    region = subprocess.run(["aws", "configure", "get", "region"], capture_output=True, text=True).stdout.strip() or "us-east-1"
    st = json.loads(STATE.read_text()) if STATE.exists() else {}
    if args.new_password or not st.get("password"):
        st["password"] = secrets.token_urlsafe(12)
    STAGE.mkdir(parents=True, exist_ok=True)

    def save() -> None:
        STATE.parent.mkdir(parents=True, exist_ok=True)
        STATE.write_text(json.dumps(st, indent=2))
        STATE.chmod(0o600)

    ensure_bucket(st, account, region); save()
    ensure_oac(st); save()
    ensure_headers_policy(st); save()
    ensure_function(st); save()
    ensure_distribution(st, region); save()
    ensure_bucket_policy(st, account)
    if upload(st) and not args.no_wait:
        print("waiting for CloudFront to deploy (several minutes)...")
        subprocess.run(["aws", "cloudfront", "wait", "distribution-deployed", "--id", st["distribution"]], check=True)
    print(f"https://{st['domain']}/  user: {USER}  password: see {STATE.relative_to(ROOT)}")


if __name__ == "__main__":
    main()

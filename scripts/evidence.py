"""Collect reproducible lab evidence; each run gets a fresh immutable directory."""
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]


def docker_path():
    found = shutil.which("docker")
    if found:
        return found
    candidate = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/DockerDesktop/resources/bin/docker.exe"
    if candidate.is_file():
        return str(candidate)
    raise SystemExit("Docker CLI not found. Install/start Docker Desktop first.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=("auto", "vulnerable", "hardened", "network"), default="auto")
    parser.add_argument("--no-build", action="store_true")
    args = parser.parse_args()
    os.chdir(ROOT)
    env = os.environ.copy()
    docker = docker_path()
    scenario = args.scenario
    if scenario == "auto":
        with urlopen("http://127.0.0.1:8080/health", timeout=3) as response:
            health = json.load(response)
        scenario = "network" if health["mode"] == "vulnerable" and health.get("egress") else health["mode"]
    else:
        env["VULNERABLE"] = "0" if scenario == "hardened" else "1"
        env["ENABLE_EGRESS"] = "1" if scenario == "network" else "0"
    compose = [docker, "compose", "-f", "docker-compose.yml"]
    if scenario == "network":
        compose += ["-f", "hardening/docker-compose.hardened.yml"]

    def call(parameters, *, capture=False, check=True):
        return subprocess.run(compose + parameters, env=env, text=True, encoding="utf-8",
                              errors="replace", stdout=subprocess.PIPE if capture else None,
                              stderr=subprocess.STDOUT if capture else None, check=check)

    if not args.no_build:
        call(["--profile", "test", "build"])
    if args.scenario != "auto":
        call(["up", "-d", "--wait", "--wait-timeout", "90"])
    started = datetime.now(timezone.utc).isoformat()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]
    relative = Path("evidence") / scenario / run_id
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    container_out = "/" + relative.as_posix()
    print("Evidence directory:", relative, flush=True)
    (out / "compose-resolved.yml").write_text(call(["config"], capture=True).stdout, encoding="utf-8")
    (out / "containers.txt").write_text(call(["ps"], capture=True).stdout, encoding="utf-8")
    test = call(["run", "--rm", "--no-deps", "-e", "EVIDENCE_DIR=" + container_out,
                 "tests", "python", "-m", "pytest", "-q", "--junitxml=" + container_out + "/pytest.xml"],
                capture=True, check=False)
    (out / "pytest.txt").write_text(test.stdout, encoding="utf-8")
    print(test.stdout, flush=True)
    for service in ("app", "dns", "rebinder", "fixture", "internal-api", "metadata-mock"):
        result = call(["logs", "--no-color", "--timestamps", "--since", started, service], capture=True, check=False)
        (out / (service + ".log")).write_text(result.stdout, encoding="utf-8")
    if scenario == "network":
        for command in ("iptables", "ip6tables"):
            result = call(["exec", "-T", "--user", "0", "app", command, "-S"], capture=True, check=False)
            (out / (command + ".txt")).write_text(result.stdout, encoding="utf-8")
            if result.returncode:
                raise SystemExit("Cannot verify active network rules")
    sources = {}
    for folder in ("app", "lab", "tests", "hardening", "scripts"):
        for source in sorted((ROOT / folder).rglob("*")):
            if source.is_file() and "__pycache__" not in source.parts:
                sources[source.relative_to(ROOT).as_posix()] = hashlib.sha256(source.read_bytes()).hexdigest()
    for name in ("docker-compose.yml", "pytest.ini"):
        sources[name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    manifest = dict(scenario=scenario, run=run_id, started_utc=started,
                    finished_utc=datetime.now(timezone.utc).isoformat(),
                    pytest_exit_code=test.returncode, host=platform.platform(), source_sha256=sources)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.iterdir()) if p.is_file()}
    (out / "SHA256SUMS.json").write_text(json.dumps(files, indent=2), encoding="utf-8")
    (ROOT / "evidence" / ("latest-" + scenario + ".txt")).write_text(relative.as_posix() + "\n", encoding="utf-8")
    print("Saved:", relative, flush=True)
    return test.returncode


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Run the checked-in authz fixtures against the pinned OpenFGA HTTP API."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "authz"
PINNED_VERSION = "v1.21.0"
PINNED_IMAGE = "openfga/openfga:v1.21.0"
PINNED_COMMIT = "ab557c5592670c899de35297e7aa067015f06502"
FIXTURES = ("relationships.json", "conditions.json", "branch_errors.json")


def docker(command: list[str], env: dict[str, str]) -> str:
    completed = subprocess.run(
        ["docker", *command],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    return completed.stdout.strip()


def http_json(base_url: str, path: str, payload: dict | None = None) -> tuple[int, dict | str]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=data,
        headers={"content-type": "application/json"} if data is not None else {},
        method="GET" if data is None else "POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", errors="replace")
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            body = raw
        return error.code, body


def body_text(body: dict | str) -> str:
    if isinstance(body, str):
        return body
    return json.dumps(body, sort_keys=True)


def wait_for_server(base_url: str) -> None:
    deadline = time.monotonic() + 45
    last_error: Exception | str = "not attempted"
    while time.monotonic() < deadline:
        try:
            status, body = http_json(base_url, "/healthz")
            if status == 200:
                return
            last_error = f"HTTP {status}: {body_text(body)}"
        except (OSError, urllib.error.URLError) as error:
            last_error = error
        time.sleep(0.25)
    raise RuntimeError(f"OpenFGA health check timed out: {last_error}")


def start_pinned_server(env: dict[str, str]) -> tuple[str, str]:
    docker(["pull", PINNED_IMAGE], env)
    image_details = json.loads(
        docker(
            ["image", "inspect", PINNED_IMAGE, "--format", "{{json .RepoDigests}}"],
            env,
        )
    )
    name = f"relgraph-authz-differential-{os.getpid()}"
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    container_id = docker(
        [
            "run",
            "--detach",
            "--rm",
            "--name",
            name,
            "--publish",
            f"127.0.0.1:{port}:8080",
            PINNED_IMAGE,
            "run",
            "--datastore-engine",
            "memory",
            "--playground-enabled=false",
        ],
        env,
    ).splitlines()[-1]
    try:
        version = docker(["exec", container_id, "/openfga", "version"], env)
        if PINNED_VERSION not in version or PINNED_COMMIT not in version:
            raise RuntimeError(
                f"expected OpenFGA {PINNED_VERSION} ({PINNED_COMMIT}), got: {version}"
            )
        base_url = f"http://127.0.0.1:{port}"
        wait_for_server(base_url)
        print(f"OpenFGA server: {version}")
        print(f"Image digest(s): {', '.join(image_details)}")
        return container_id, base_url
    except Exception:
        docker(["stop", container_id], env)
        raise


def execute_fixtures(base_url: str) -> int:
    passed = 0
    for fixture_name in FIXTURES:
        fixture_path = FIXTURE_DIR / fixture_name
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        server = fixture["server"]
        if server["version"] != PINNED_VERSION or server["image"] != PINNED_IMAGE:
            raise RuntimeError(f"{fixture_name} is not pinned to {PINNED_VERSION}")

        status, store_body = http_json(base_url, "/stores", {"name": f"authz-{fixture_name}"})
        if status != 201:
            raise RuntimeError(f"could not create store for {fixture_name}: {status} {store_body}")
        store_id = store_body["id"]

        status, model_body = http_json(
            base_url,
            f"/stores/{store_id}/authorization-models",
            fixture["model"],
        )
        if status != 201:
            raise RuntimeError(f"could not create model for {fixture_name}: {status} {model_body}")
        model_id = model_body["authorization_model_id"]

        if fixture["tuples"]:
            status, tuple_body = http_json(
                base_url,
                f"/stores/{store_id}/write",
                {
                    "authorization_model_id": model_id,
                    "writes": {"tuple_keys": fixture["tuples"]},
                },
            )
            if status != 200:
                raise RuntimeError(f"could not write tuples for {fixture_name}: {status} {tuple_body}")

        for case in fixture["cases"]:
            request = case["request"]
            body = {
                "authorization_model_id": model_id,
                "tuple_key": {
                    "user": request["user"],
                    "relation": request["relation"],
                    "object": request["object"],
                },
            }
            if "context" in request:
                body["context"] = request["context"]
            if "contextual_tuples" in request:
                body["contextual_tuples"] = {"tuple_keys": request["contextual_tuples"]}

            status, response = http_json(base_url, f"/stores/{store_id}/check", body)
            expected = case["expected"]
            label = f"{fixture_name}/{case['id']}"
            if "server_error_contains" in expected:
                expected_text = expected["server_error_contains"].lower()
                actual_text = body_text(response).lower()
                if status < 400 or expected_text not in actual_text:
                    raise AssertionError(
                        f"{label}: expected HTTP error containing {expected_text!r}, "
                        f"got HTTP {status}: {body_text(response)}"
                    )
            else:
                wanted = expected["server"] == "allow"
                if status != 200 or response.get("allowed") is not wanted:
                    raise AssertionError(
                        f"{label}: expected allowed={wanted}, got HTTP {status}: {body_text(response)}"
                    )
            passed += 1
            print(f"PASS {label}")
    return passed


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] in {"-h", "--help"}:
        print("Run offline fixtures against a temporary Docker OpenFGA v1.21.0 server.")
        print("Usage: python3 relgraph-authz/tools/openfga-differential.py")
        return 0

    container_id = None
    with tempfile.TemporaryDirectory(prefix="openfga-docker-config-") as docker_config:
        env = os.environ.copy()
        # The public image needs no credentials. An empty config keeps stale or
        # interactive credential helpers from blocking a reproducible pull.
        env["DOCKER_CONFIG"] = docker_config
        try:
            container_id, base_url = start_pinned_server(env)
            count = execute_fixtures(base_url)
            print(f"Passed {count} differential cases against {PINNED_VERSION}.")
            return 0
        finally:
            if container_id is not None:
                docker(["stop", container_id], env)


if __name__ == "__main__":
    raise SystemExit(main())

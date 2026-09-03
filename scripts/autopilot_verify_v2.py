#!/usr/bin/env python3
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
import urllib.request

REPO = "https://github.com/RARgames/4gaBoards"
PROFILE = "4gaboards-compose-v1"
POSTGRES_PASSWORD = "notpassword"


def run(cmd, cwd=None, timeout=600, check=True, input_text=None):
    result = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    print(result.stdout, flush=True)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command_failed:{result.returncode}:{cmd[0]}"
        )
    return result


def dimension(status, summary):
    return {
        "status": status,
        "summary": str(summary)[:500],
    }


def compose(cwd, *args, timeout=600, check=True):
    return run(
        ["docker", "compose", *args],
        cwd=cwd,
        timeout=timeout,
        check=check,
    )


def inspect_security(cwd):
    rendered = run(
        ["docker", "compose", "config", "--format", "json"],
        cwd=cwd,
        timeout=60,
    )
    data = json.loads(rendered.stdout)
    services = data.get("services", {})
    dangerous = []

    for name, service in services.items():
        if service.get("privileged") is True:
            dangerous.append(f"{name}:privileged")
        if service.get("network_mode") == "host":
            dangerous.append(f"{name}:host_network")
        if service.get("pid") == "host":
            dangerous.append(f"{name}:host_pid")

        caps = [
            str(value).upper()
            for value in service.get("cap_add", [])
        ]
        if "ALL" in caps or "SYS_ADMIN" in caps:
            dangerous.append(f"{name}:dangerous_caps")

        for volume in service.get("volumes", []):
            if not isinstance(volume, dict):
                continue
            source = volume.get("source")
            target = volume.get("target")
            if source in ("/", "/var/run/docker.sock"):
                dangerous.append(
                    f"{name}:dangerous_mount:{source}"
                )
            if target == "/var/run/docker.sock":
                dangerous.append(
                    f"{name}:docker_socket_target"
                )

    if dangerous:
        raise RuntimeError(
            "unsafe_compose:" + ",".join(dangerous)
        )

    return len(services)


def db_query(cwd, sql):
    result = compose(
        cwd,
        "exec", "-T",
        "-e", f"PGPASSWORD={POSTGRES_PASSWORD}",
        "db",
        "psql", "-U", "postgres",
        "-d", "4gaBoards",
        "-v", "ON_ERROR_STOP=1",
        "-tA", "-c", sql,
        timeout=60,
    )
    lines = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    ]
    return lines[-1] if lines else ""


def get_container_id(cwd, service):
    result = compose(
        cwd,
        "ps", "-q", service,
        timeout=30,
    )
    ids = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    ]
    if not ids:
        raise RuntimeError(
            f"container_id_missing:{service}"
        )
    return ids[-1]


def main():
    candidate_id = os.environ["DOKPI_CANDIDATE_ID"]
    repository_url = os.environ["DOKPI_REPOSITORY_URL"]
    profile = os.environ["DOKPI_PROFILE"]
    github_run_id = os.environ["GITHUB_RUN_ID"]
    github_run_url = (
        "https://github.com/"
        + os.environ["GITHUB_REPOSITORY"]
        + "/actions/runs/"
        + github_run_id
    )

    if repository_url != REPO or profile != PROFILE:
        raise SystemExit("unsupported_target")

    result = {
        "schema_version": 1,
        "candidate_id": candidate_id,
        "repository_url": repository_url,
        "profile": profile,
        "source_commit_sha": "",
        "github_run_id": github_run_id,
        "github_run_url": github_run_url,
        "observed_at": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(),
        ),
        "dimensions": {
            "install_start": dimension(
                "unknown", "not attempted"
            ),
            "persistence": dimension(
                "unknown", "not attempted"
            ),
            "backup_restore": dimension(
                "unknown", "not attempted"
            ),
            "security": dimension(
                "unknown", "not attempted"
            ),
            "upgrade": dimension(
                "unknown",
                "version-to-version upgrade profile not yet proven",
            ),
        },
    }

    work = pathlib.Path(
        tempfile.mkdtemp(prefix="dokpi-autopilot-")
    )
    candidate = work / "candidate"

    try:
        run(
            [
                "git", "-c", "credential.helper=",
                "clone", "--depth", "1",
                repository_url,
                str(candidate),
            ],
            timeout=120,
        )

        sha = run(
            ["git", "rev-parse", "HEAD"],
            cwd=candidate,
            timeout=30,
        ).stdout.strip().splitlines()[-1]

        if (
            len(sha) != 40
            or any(
                char not in "0123456789abcdef"
                for char in sha
            )
        ):
            raise RuntimeError("invalid_source_sha")

        result["source_commit_sha"] = sha

        try:
            services = inspect_security(candidate)
            result["dimensions"]["security"] = dimension(
                "passed",
                f"compose baseline passed; services={services}; "
                "no privileged/host-network/host-pid/"
                "dangerous-cap/docker-socket settings detected",
            )
        except Exception as exc:
            result["dimensions"]["security"] = dimension(
                "failed", exc
            )

        try:
            compose(
                candidate,
                "up", "-d", "--wait",
                timeout=600,
            )

            with urllib.request.urlopen(
                "http://127.0.0.1:3000/",
                timeout=20,
            ) as response:
                status = response.status

            if status < 200 or status >= 500:
                raise RuntimeError(
                    f"unexpected_http_status:{status}"
                )

            result["dimensions"]["install_start"] = dimension(
                "passed",
                f"official Compose deployment started and HTTP responded {status}",
            )
        except Exception as exc:
            result["dimensions"]["install_start"] = dimension(
                "failed", exc
            )

        if (
            result["dimensions"]["install_start"]["status"]
            == "passed"
        ):
            try:
                db_query(
                    candidate,
                    "CREATE TABLE IF NOT EXISTS "
                    "dokpi_autopilot_probe("
                    "id integer primary key, value text);"
                    "INSERT INTO dokpi_autopilot_probe(id,value) "
                    "VALUES(1,'persisted') "
                    "ON CONFLICT(id) DO UPDATE "
                    "SET value='persisted';",
                )

                compose(
                    candidate,
                    "down",
                    timeout=120,
                )
                compose(
                    candidate,
                    "up", "-d", "--wait",
                    timeout=600,
                )

                value = db_query(
                    candidate,
                    "SELECT value FROM "
                    "dokpi_autopilot_probe WHERE id=1;",
                )

                if value != "persisted":
                    raise RuntimeError(
                        f"persistence_mismatch:{value}"
                    )

                result["dimensions"]["persistence"] = dimension(
                    "passed",
                    "PostgreSQL sentinel survived full Compose down/up using declared named volumes",
                )
            except Exception as exc:
                result["dimensions"]["persistence"] = dimension(
                    "failed", exc
                )

            try:
                db_query(
                    candidate,
                    "CREATE TABLE IF NOT EXISTS "
                    "dokpi_autopilot_backup("
                    "id integer primary key, value text);"
                    "INSERT INTO dokpi_autopilot_backup(id,value) "
                    "VALUES(1,'before-backup') "
                    "ON CONFLICT(id) DO UPDATE "
                    "SET value='before-backup';",
                )

                backup_dir = work / "backup"
                backup_dir.mkdir()
                db_dump = backup_dir / "probe.sql"

                db_id = get_container_id(candidate, "db")
                app_id = get_container_id(
                    candidate, "4gaBoards"
                )

                dump = run(
                    [
                        "docker", "exec",
                        "-e", f"PGPASSWORD={POSTGRES_PASSWORD}",
                        db_id,
                        "pg_dump", "-U", "postgres",
                        "-d", "4gaBoards",
                        "--clean", "--if-exists",
                        "--table=dokpi_autopilot_backup",
                    ],
                    timeout=90,
                )
                db_dump.write_text(dump.stdout)

                file_probe = (
                    "/app/private/attachments/"
                    "dokpi-autopilot-probe.txt"
                )

                run(
                    [
                        "docker", "exec", app_id,
                        "sh", "-c",
                        "mkdir -p /app/private/attachments "
                        "&& printf before-backup > "
                        + file_probe,
                    ],
                    timeout=30,
                )

                files_backup = backup_dir / "attachments"
                files_backup.mkdir()

                run(
                    [
                        "docker", "cp",
                        f"{app_id}:/app/private/attachments/.",
                        str(files_backup),
                    ],
                    timeout=60,
                )

                db_query(
                    candidate,
                    "UPDATE dokpi_autopilot_backup "
                    "SET value='after-backup' WHERE id=1;",
                )

                run(
                    [
                        "docker", "exec", app_id,
                        "sh", "-c",
                        "printf after-backup > "
                        + file_probe,
                    ],
                    timeout=30,
                )

                restore = run(
                    [
                        "docker", "exec", "-i",
                        "-e", f"PGPASSWORD={POSTGRES_PASSWORD}",
                        db_id,
                        "psql", "-U", "postgres",
                        "-d", "4gaBoards",
                        "-v", "ON_ERROR_STOP=1",
                    ],
                    timeout=90,
                    input_text=db_dump.read_text(),
                )

                run(
                    [
                        "docker", "cp",
                        str(files_backup) + "/.",
                        f"{app_id}:/app/private/attachments/",
                    ],
                    timeout=60,
                )

                db_value = db_query(
                    candidate,
                    "SELECT value FROM "
                    "dokpi_autopilot_backup WHERE id=1;",
                )

                file_value = run(
                    [
                        "docker", "exec", app_id,
                        "cat", file_probe,
                    ],
                    timeout=30,
                ).stdout.strip().splitlines()[-1].strip()

                if (
                    db_value != "before-backup"
                    or file_value != "before-backup"
                ):
                    raise RuntimeError(
                        "backup_restore_sentinel_mismatch"
                    )

                result["dimensions"]["backup_restore"] = dimension(
                    "passed",
                    "isolated PostgreSQL and attachment-volume sentinels were backed up, mutated, restored, and matched original values",
                )
            except Exception as exc:
                result["dimensions"]["backup_restore"] = dimension(
                    "failed", exc
                )

    except Exception as exc:
        if not result["source_commit_sha"]:
            result["source_commit_sha"] = "0" * 40

        if (
            result["dimensions"]["install_start"]["status"]
            == "unknown"
        ):
            result["dimensions"]["install_start"] = dimension(
                "failed", exc
            )
    finally:
        try:
            if candidate.exists():
                compose(
                    candidate,
                    "down", "-v",
                    timeout=120,
                    check=False,
                )
        finally:
            output = pathlib.Path(
                os.environ["DOKPI_RESULT_PATH"]
            )
            output.write_text(
                json.dumps(
                    result,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()

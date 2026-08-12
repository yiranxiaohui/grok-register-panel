from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def run() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/docker-publish.yml").read_text(encoding="utf-8")
    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()

    assert "USER app" in dockerfile
    assert "python -m camoufox fetch" in dockerfile
    assert 'ENTRYPOINT ["/usr/bin/tini", "--"]' in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert "packages: write" in workflow
    assert "${{ secrets.GITHUB_TOKEN }}" in workflow
    assert "docker/build-push-action@v6" in workflow
    assert "push: true" in workflow
    for sensitive in ("config.json", "accounts", "cpa_auth", "grok2api_auth", "log"):
        assert sensitive in ignored, f"{sensitive} missing from .dockerignore"


if __name__ == "__main__":
    run()
    print("OK docker packaging")

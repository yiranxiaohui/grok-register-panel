FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    MONITOR_HOST=0.0.0.0 \
    MONITOR_PORT=8787 \
    PANEL_INCLUDE_TAIL=0 \
    GROK_USE_XVFB=auto

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt \
    && apt-get update \
    && apt-get install -y --no-install-recommends tini \
    && python -m playwright install-deps firefox \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin app \
    && chown app:app /app

COPY --chown=app:app . .

USER app
RUN python -m camoufox fetch \
    && mkdir -p accounts cpa_auth grok2api_auth log

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('MONITOR_PORT', '8787') + '/api/health', timeout=3).read()"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-u", "webui/monitor.py"]

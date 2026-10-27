# syntax=docker/dockerfile:1.7

# ---- build: resolve dependências com uv a partir do uv.lock ----
FROM python:3.13-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

# ---- runtime: imagem enxuta, usuário sem privilégios ----
FROM python:3.13-slim AS runtime
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LINHAMESTRE_DB_PATH=/data/linhamestre.db
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app \
    && mkdir -p /data && chown app:app /data
WORKDIR /app
COPY --from=build /opt/venv /opt/venv
COPY --chown=app:app .streamlit ./.streamlit
COPY --chown=app:app linhamestre_app.py seed_db.py ./
USER app
VOLUME ["/data"]
EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=4).status == 200 else 1)"
# exec form: o Streamlit recebe SIGTERM diretamente e encerra de forma graciosa.
ENTRYPOINT ["streamlit", "run", "linhamestre_app.py", "--server.port=8501", "--server.address=0.0.0.0"]

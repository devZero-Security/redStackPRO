# The canvas in one container: FastAPI plus the built frontend on :8000.
# No terraform/ansible/cloud SDKs by design; the export zip is the handoff (ADR 0001).

# Debian (glibc), not Alpine: vite's native deps ship glibc builds.
FROM node:24-slim AS canvas
WORKDIR /canvas
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# schema/ now lives inside the package (src/redstackpro/schema) and is resolved
# from the package, not the CWD, so the install carries it and there is nothing to
# copy alongside. The postgres extra ships psycopg + alembic so one image runs on
# either backend.
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install -e ".[postgres]" "uvicorn[standard]"

COPY --from=canvas /canvas/dist ./frontend/dist
ENV REDSTACKPRO_STATIC_DIR=/app/frontend/dist

# DB on a volume; point REDSTACKPRO_DATABASE_URL at Postgres to switch backends.
ENV REDSTACKPRO_DATABASE_URL=sqlite+pysqlite:////data/redstackpro.db
RUN mkdir -p /data

RUN useradd --system --create-home --uid 10001 redstackpro \
    && chown -R redstackpro:redstackpro /app /data
USER redstackpro

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health').status==200 else 1)"

CMD ["redstackpro", "serve", "--host", "0.0.0.0", "--port", "8000"]

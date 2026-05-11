FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libffi-dev libgmp-dev libmpfr-dev libmpc-dev && rm -rf /var/lib/apt/lists/*
    
WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen
COPY . .
ENV PATH="/app/.venv/bin:$PATH"
ENTRYPOINT ["/bin/bash"]
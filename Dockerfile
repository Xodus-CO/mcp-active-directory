FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    libldap2-dev \
    libsasl2-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.in pyproject.toml ./

RUN pip install uv && \
    uv venv && \
    . .venv/bin/activate && \
    uv pip install -r requirements.in

COPY src/ ./src/
COPY setup.py ./

RUN . .venv/bin/activate && uv pip install -e .

RUN useradd -m -u 1000 aduser && chown -R aduser:aduser /app
USER aduser

ENV PYTHONPATH=/app/src
ENV AD_READONLY=true
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8000

EXPOSE 8000

CMD ["/bin/bash", "-c", ". .venv/bin/activate && python -m active_directory_mcp.server_http"]

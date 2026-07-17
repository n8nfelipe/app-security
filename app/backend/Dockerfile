FROM python:3.11-slim

WORKDIR /srv/app

COPY pyproject.toml README.md requirements.txt ./
COPY app ./app
COPY tests ./tests

ARG BASE_OS=debian
RUN if [ "$BASE_OS" = "fedora" ]; then \
        dnf install -y nmap python3-pip curl && dnf clean all; \
    else \
        apt-get update && apt-get install -y --no-install-recommends nmap python3-pip curl \
        && rm -rf /var/lib/apt/lists/*; \
    fi \
    && pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

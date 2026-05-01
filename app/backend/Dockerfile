FROM python:3.11-slim

WORKDIR /srv/app

COPY pyproject.toml README.md requirements.txt ./
COPY app ./app
COPY tests ./tests

ARG BASE_OS=debian
RUN if [ "$BASE_OS" = "fedora" ]; then \
        dnf install -y nmap python3-pip curl; \
    else \
        apt-get update && apt-get install -y nmap python3-pip curl; \
    fi \
    && pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

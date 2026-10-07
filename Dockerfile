FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 SSF_HOST=0.0.0.0 SSF_PORT=8080 SSF_DB_PATH=/app/data/ssf.db SSF_SCAN_ROOT=/scan
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ssf ./ssf
COPY config ./config
RUN useradd -r ssf && mkdir -p /app/data /scan && chown ssf /app/data
USER ssf
EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/api/health')"
CMD ["gunicorn", "-b", "0.0.0.0:8080", "-w", "1", "--threads", "4", "ssf.app:create_app()"]

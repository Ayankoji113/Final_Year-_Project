# Build context is src/ (not src/gateway) so the shared `common` package is
# available to both the gateway and the ML pipeline without duplication.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY gateway/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY common/ ./common/
COPY gateway/ ./gateway/

# Run unprivileged: a proxy that terminates untrusted input should not be root.
RUN useradd --create-home --uid 10001 guard && \
    mkdir -p /app/data && chown -R guard:guard /app
USER guard

EXPOSE 5000

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/__guard/health',timeout=2).status==200 else 1)"

CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "5000", \
     "--workers", "1", "--no-server-header", "--proxy-headers"]

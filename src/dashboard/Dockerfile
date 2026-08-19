# Build context is src/ so the dashboard can import the shared `common` package.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY dashboard/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY common/ ./common/
COPY dashboard/ ./dashboard/

RUN useradd --create-home --uid 10003 viewer && chown -R viewer:viewer /app
USER viewer

EXPOSE 8501

CMD ["streamlit", "run", "dashboard/app.py", \
     "--server.address=0.0.0.0", "--server.port=8501", \
     "--server.headless=true", "--browser.gatherUsageStats=false"]

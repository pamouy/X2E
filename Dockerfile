# Entra Migration Workbench: one container, one volume.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    WORKBENCH_DATA=/data WORKBENCH_HOST=0.0.0.0 WORKBENCH_PORT=8080

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY workbench ./workbench

RUN useradd --system --uid 10001 --home /app workbench && mkdir /data && chown workbench /data
USER workbench
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:'+os.environ['WORKBENCH_PORT']+'/healthz')" || exit 1
CMD ["python", "-m", "workbench"]

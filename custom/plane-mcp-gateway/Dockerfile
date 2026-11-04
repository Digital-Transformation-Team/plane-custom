FROM python:3.12-slim
WORKDIR /app
RUN useradd --system --uid 10001 mcp && mkdir /data && chown mcp /data
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY gateway ./gateway
USER mcp
ENV PORT=8080 GATEWAY_DB=/data/gateway.db
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s CMD python -c "import urllib.request,sys;urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3)" || exit 1
CMD ["python", "-m", "gateway.main"]

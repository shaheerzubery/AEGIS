# Build context must be the repo root (see demo/docker-compose.yml) so this
# can reach packages/sdk, which lives outside packages/dashboard.
FROM python:3.12-slim
RUN pip install httpx
COPY packages/sdk/aegis_sdk /app/aegis_sdk
COPY packages/dashboard/api/dashboard_api.py /app/dashboard_api.py
WORKDIR /app
CMD ["python", "dashboard_api.py"]

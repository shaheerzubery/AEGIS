FROM python:3.12-slim
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY circuit_breaker.py /app/circuit_breaker.py
WORKDIR /app
CMD ["python", "circuit_breaker.py"]

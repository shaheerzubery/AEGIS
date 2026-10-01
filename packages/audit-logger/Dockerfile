FROM python:3.12-slim
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY audit_logger.py /app/audit_logger.py
WORKDIR /app
CMD ["python", "audit_logger.py"]

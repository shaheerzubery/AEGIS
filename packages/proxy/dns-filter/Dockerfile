FROM python:3.12-slim
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY dns_filter.py /app/dns_filter.py
WORKDIR /app
CMD ["python", "dns_filter.py"]

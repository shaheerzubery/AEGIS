FROM python:3.12-slim
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY features.py anomaly_detector.py model.joblib /app/
WORKDIR /app
CMD ["python", "anomaly_detector.py"]

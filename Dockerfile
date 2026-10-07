# Image for the Flask app (used by both the vuln and the secure service).
# Only the Python dependencies are baked in; the code itself is mounted from the
# project folder by docker-compose.yml, so edits on the host apply on restart.
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

ENV PYTHONUNBUFFERED=1
CMD ["python3", "app.py"]

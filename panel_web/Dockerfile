FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .

# Solo instalamos lo necesario, sin docker.io
RUN apt-get update && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "app.py"]

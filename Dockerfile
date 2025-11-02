FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create data dir and ensure it's writable
RUN mkdir -p /app/data

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]

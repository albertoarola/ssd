FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=1000 -r requirements.txt

COPY . .

CMD ["python", "auth.py"]

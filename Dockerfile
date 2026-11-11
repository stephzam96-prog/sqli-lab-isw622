FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Carpeta para la base de datos SQLite
RUN mkdir -p db

EXPOSE 5000

CMD ["python", "app.py"]

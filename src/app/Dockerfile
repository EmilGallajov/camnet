FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MPLBACKEND=Agg \
    MPLCONFIGDIR=/tmp/mpl \
    TOPO_DIR=/app/topologies \
    UPLOAD_DIR=/app/uploads \
    DATA_DIR=/app/data

WORKDIR /app

# System libs for WeasyPrint (Pango/Cairo) so Jinja2 HTML templates render to PDF.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
        libcairo2 libffi-dev libjpeg62-turbo fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/topologies /app/uploads /app/data /tmp/mpl

EXPOSE 8080

CMD ["gunicorn", "-b", "0.0.0.0:8080", "--workers", "1", "--threads", "8", \
     "--timeout", "600", "--access-logfile", "-", "app:app"]

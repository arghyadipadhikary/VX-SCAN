FROM python:3.11-alpine

RUN apk add --no-cache \
    build-base \
    pango \
    pango-dev \
    libffi-dev \
    jpeg-dev \
    openjpeg-dev \
    yara \
    yara-dev \
    fontconfig \
    ttf-dejavu \
    cairo \
    cairo-dev \
    gdk-pixbuf

RUN adduser -D scanner

WORKDIR /app

# Create empty directories so FastAPI doesn't crash before Podman mounts your Kali folders
RUN mkdir -p /app/frontend /app/reports /app/temp_uploads /app/yara_rules

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chown -R scanner:scanner /app

USER scanner
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
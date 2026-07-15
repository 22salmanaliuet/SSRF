FROM python:3.11-slim

LABEL maintainer="SEDF FYP - Educational Use Only"
LABEL description="Intentionally vulnerable SSRF lab application"

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir flask==3.0.0

COPY app.py .

# Expose app port
EXPOSE 5000

# Run with a non-root user for safety
RUN useradd -m labuser
USER labuser

ENV PORT=5000
ENV FLASK_ENV=development

CMD ["python", "app.py"]

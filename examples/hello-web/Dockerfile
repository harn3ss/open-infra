# Minimal example app — a tiny static HTTP server on :8080.
FROM python:3.12-alpine
WORKDIR /app
COPY app.py .
ENV PORT=8080
EXPOSE 8080
CMD ["python", "app.py"]

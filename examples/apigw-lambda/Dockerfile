# The canonical API Gateway (HTTP API v2) → Lambda example for open-infra. A tiny stdlib HTTP server that
# speaks the API Gateway v2 proxy contract (see app.py). No dependencies; distroless-small via alpine.
FROM python:3.12-alpine
WORKDIR /app
COPY app.py .
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["python", "app.py"]

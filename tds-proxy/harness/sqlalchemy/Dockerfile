# SQLAlchemy (ORM) over pyodbc + Microsoft ODBC Driver 18, for the #3 driver-coverage grid. Built + run
# against the throwaway backend, then removed — never point it at a real database.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl gnupg ca-certificates unixodbc-dev gcc \
 && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" > /etc/apt/sources.list.d/mssql-release.list \
 && apt-get update \
 && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 \
 && pip install --no-cache-dir pyodbc sqlalchemy \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY Run.py /Run.py
ENTRYPOINT ["python", "/Run.py"]

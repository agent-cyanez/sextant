FROM python:3.12-alpine
WORKDIR /app
COPY sextant.py .
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "sextant.py"]

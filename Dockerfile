FROM python:3.12-alpine
WORKDIR /app
COPY sextant.py .
ENV PYTHONUNBUFFERED=1
HEALTHCHECK --interval=60s --timeout=5s CMD pgrep -f sextant.py || exit 1
ENTRYPOINT ["python3", "sextant.py"]

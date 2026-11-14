FROM python:3.12-slim
WORKDIR /app
COPY scanner_core.py cloud_server.py ./
ENV PYTHONUNBUFFERED=1 PORT=8080 DATA_DIR=/data
EXPOSE 8080
CMD ["python", "cloud_server.py"]

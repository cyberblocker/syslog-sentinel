FROM python:3.12-slim
WORKDIR /app
COPY sentinel.py inventory.json ./
RUN useradd --uid 10001 --create-home sentinel && mkdir /app/data /app/reports && chown -R sentinel:sentinel /app
USER sentinel
EXPOSE 5514/tcp 5514/udp
CMD ["python", "sentinel.py", "collect", "--bind", "0.0.0.0"]

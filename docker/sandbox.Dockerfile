FROM python:3.12-slim
RUN useradd --uid 65534 --no-create-home --shell /usr/sbin/nologin sandbox \
    && mkdir -p /synthetic/logs /synthetic/db \
    && echo "dummy-not-a-secret" > /synthetic/dummy_credentials \
    && chown -R 65534:65534 /synthetic
COPY sandbox/probe.py /probe.py
USER 65534:65534
WORKDIR /tmp
ENTRYPOINT ["python", "/probe.py"]

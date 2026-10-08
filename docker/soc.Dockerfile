FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.115.6 uvicorn==0.34.0 pydantic==2.10.4
COPY mcp_servers /app/mcp_servers
EXPOSE 9001
CMD ["uvicorn", "mcp_servers.soc_server:app", "--host", "0.0.0.0", "--port", "9001"]

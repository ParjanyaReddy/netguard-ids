FROM python:3.11-slim

WORKDIR /app

# Install packet capture dependencies and net tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    iputils-ping \
    net-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "netguard.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

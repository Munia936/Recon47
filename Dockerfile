FROM python:3.11-slim

# Install system tools
RUN apt-get update && apt-get install -y \
    nikto \
    dnsutils \
    nmap \
    curl \
    wget \
    git \
    --no-install-recommends && rm -rf /var/lib/apt/lists/*

# Install Go + Nuclei
RUN curl -fsSL https://go.dev/dl/go1.22.0.linux-amd64.tar.gz | tar -C /usr/local -xzf -
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin"
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install -e .

# Output directory
RUN mkdir -p /reports
VOLUME ["/reports"]

ENTRYPOINT ["recon47"]
CMD ["--help"]

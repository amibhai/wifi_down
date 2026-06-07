FROM kalilinux/kali-rolling:latest

LABEL maintainer="wifi-auditor" \
      description="WiFi Security Auditing Framework" \
      version="2.0.0"

# Avoid interactive prompts during package install
ENV DEBIAN_FRONTEND=noninteractive

# System packages
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        aircrack-ng \
        hcxdumptool \
        hcxtools \
        hashcat \
        crunch \
        macchanger \
        iw \
        iproute2 \
        wireless-tools \
        python3 \
        python3-pip \
        python3-venv \
        libpcap-dev \
        usbutils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Working directory
WORKDIR /opt/wifi-auditor

# Install Python dependencies first (layer-cache friendly)
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy full source
COPY . .

# Install the package itself
RUN pip3 install --no-cache-dir -e . 2>/dev/null || true

# Persistent data directories (will be volume-mounted)
RUN mkdir -p captures wordlists results /root/.wifi-auditor/sessions

# Default entry point
ENTRYPOINT ["python3", "-m", "wifi_auditor.cli"]
CMD ["--help"]

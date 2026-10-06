FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    hydra \
    sqlmap \
    tcpdump \
    curl \
    python3 \
    iproute2 \
    net-tools \
    iputils-ping \
    ca-certificates \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root/attacks

# Ensure output directories exist
RUN mkdir -p /logs /captures /root/attacks/scripts

COPY passwords.txt /root/attacks/passwords.txt
COPY run_attacks.sh /root/attacks/run_attacks.sh
RUN chmod +x /root/attacks/run_attacks.sh

ENTRYPOINT ["/bin/bash"]

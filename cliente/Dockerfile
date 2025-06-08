FROM debian:stable-slim

# Instalar dependencias necesarias
RUN apt-get update && \
    apt-get install -y \
        openssh-client \
        curl \
        nmap \
        iproute2 \
        iputils-ping \
        build-essential \
        libssl-dev \
        libssh-dev \
        git \
        make \
        gcc && \
    apt-get clean

# Descargar y compilar Hydra desde el código fuente (THC-Hydra)
RUN git clone https://github.com/vanhauser-thc/thc-hydra.git /tmp/hydra && \
    cd /tmp/hydra && \
    ./configure && \
    make && \
    make install && \
    cd / && \
    rm -rf /tmp/hydra

COPY ../rockyou.txt /usr/share/wordlists/rockyou.txt
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]

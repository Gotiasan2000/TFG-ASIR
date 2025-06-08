FROM debian:stable-slim

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        vsftpd \
        postfix \
        apache2 \
        iproute2 \
        iputils-ping && \
    apt-get clean

RUN mkdir /var/run/sshd

# Usuario para SSH
RUN useradd -m usuario && echo 'usuario:clase' | chpasswd

# Config SSH
RUN sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Activar servicios al inicio
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY vsftpd.conf /etc/vsftpd.conf

EXPOSE 21 22 23 25 80

CMD ["/entrypoint.sh"]

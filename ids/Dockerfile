FROM debian:stable-slim

RUN apt-get update && \
    apt-get install -y suricata iproute2 iptables tcpdump curl iputils-ping nano cron python3 python3-pip python3-venv && \
    apt-get clean

COPY analizar_alertas.py /root/analizar_alertas.py
COPY ejecutar_ids.sh /root/ejecutar_ids.sh
COPY ids_cron /etc/cron.d/ids_cron

COPY reglas /etc/suricata/rules

RUN chmod +x /root/ejecutar_ids.sh && \
    chmod 0644 /etc/cron.d/ids_cron && \
    crontab /etc/cron.d/ids_cron

RUN pip3 install --no-cache-dir --break-system-packages python-nmap mysql-connector-python

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
CMD ["/entrypoint.sh"]


FROM debian:stable-slim

RUN apt-get update && \
    apt-get install -y iproute2 iputils-ping nano nmap cron python3 python3-pip python3-venv && \
    apt-get clean

COPY escaner.py /root/escaner.py
COPY ejecutar_escaner.sh /root/ejecutar_escaner.sh
COPY escaner_cron /etc/cron.d/escaner_cron

RUN chmod +x /root/ejecutar_escaner.sh && \
    chmod 0644 /etc/cron.d/escaner_cron && \
    crontab /etc/cron.d/escaner_cron

RUN pip3 install --no-cache-dir --break-system-packages python-nmap mysql-connector-python

CMD ["cron", "-f"]

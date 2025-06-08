#!/bin/bash

# Habilitar reenvío de paquetes
echo 1 > /proc/sys/net/ipv4/ip_forward

# Detectar interfaz externa automáticamente
IFACE=$(ip route show default | awk '/default/ {print $5}')
echo "Interfaz externa detectada: $IFACE"

# Asignar interfaces (usa la detectada y asume eth1 como interna)
EXT_IFACE=$IFACE
INT_IFACE=eth1

# Configurar NAT y reglas de reenvío con iptables
echo "Configurando iptables..."
iptables -t nat -A POSTROUTING -o $INT_IFACE -j MASQUERADE
iptables -A FORWARD -i $EXT_IFACE -o $INT_IFACE -j ACCEPT
iptables -A FORWARD -i $INT_IFACE -o $EXT_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT

# Iniciar Suricata en segundo plano en ambas interfaces
echo "Iniciando Suricata..."
suricata -i $EXT_IFACE -i $INT_IFACE -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/mis_reglas.rules &

# Darle unos segundos para que inicie y cree eve.json
sleep 5

# Iniciar cron en primer plano (mantiene el contenedor vivo)
echo "Iniciando cron..."
cron -f

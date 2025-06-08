#!/bin/bash

# Cambiar la ruta por defecto al IDS
ip route del default
ip route add default via 172.20.0.10

# Iniciar servicios necesarios
service ssh start
service postfix start


echo "Iniciando vsftpd..."
service vsftpd start || echo "Error al iniciar vsftpd"


service apache2 start

# Mantener el contenedor activo
tail -f /dev/null

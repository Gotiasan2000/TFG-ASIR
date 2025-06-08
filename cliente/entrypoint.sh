#!/bin/bash

# Establecer el contenedor IDS como puerta de enlace
ip route del default
ip route add default via 172.21.0.10

# Mantener el contenedor en ejecución
exec sleep infinity

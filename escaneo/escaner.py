import nmap
import json
import datetime
import mysql.connector

# Diccionario de recomendaciones básicas por servicio
recomendaciones = {
    "ftp": "Evita usar FTP. Usa SFTP o FTPS y desactiva el acceso anónimo.",
    "ssh": "Cambia el puerto por defecto, usa autenticacion con clave publica y desactiva root login.",
    "http": "Implementa HTTPS. Revisa headers de seguridad y evita métodos como PUT o DELETE.",
    "https": "Asegurate de usar certificados válidos y configuraciones modernas.",
    "mysql": "Cambia la contraseña por defecto. Asegura el acceso remoto o desactivalo.",
    "telnet": "Evita usar Telnet. Usa SSH en su lugar.",
    "smtp": "Usa autenticación y cifrado. Filtra IPs autorizadas para evitar spam.",
    "dns": "Evita respuestas recursivas abiertas. Usa registros DNS seguros.",
    "rdp": "Limita accesos, usa VPN, activa autenticacion a nivel de red."
}

# Función para escanear IP o red
def escanear_red(rango_ip):
    escaner = nmap.PortScanner()
    print(f"[+] Escaneando: {rango_ip}")

    # Mejora 3: argumentos mas completos para Nmap
    escaner.scan(hosts=rango_ip, arguments='-sS -sV -T4 --open')

    resultados = {}

    for host in escaner.all_hosts():
        print(f"[+] Analizando {host}")  # Mejora 4: progreso por IP

        info_host = {
            'estado': escaner[host].state(),
            'protocolos': {}
        }

        for protocolo in escaner[host].all_protocols():
            puertos = escaner[host][protocolo].keys()
            info_puertos = []

            for puerto in puertos:
                servicio = escaner[host][protocolo][puerto]
                nombre_servicio = servicio.get('name', '').lower()
                recomendacion = recomendaciones.get(nombre_servicio, "No hay recomendación específica.")

                info_puerto = {
                    'puerto': puerto,
                    'estado': servicio['state'],
                    'nombre_servicio': nombre_servicio,
                    'producto': servicio.get('product'),
                    'version': servicio.get('version'),
                    'recomendacion': recomendacion
                }
                info_puertos.append(info_puerto)

            info_host['protocolos'][protocolo] = info_puertos

        resultados[host] = info_host

    return resultados

# Funcion para guardar resultados en JSON
def guardar_resultados(resultados, archivo_salida):
    with open(archivo_salida, 'w') as archivo:
        json.dump(resultados, archivo, indent=4)
    print(f"[+] Resultados guardados en {archivo_salida}")

# Funcion para guardar resultados en MySQL
def guardar_en_mysql(resultados):
    try:
        conexion = mysql.connector.connect(
            host='172.20.0.60',
            user='root',
            password='root123',
            database='seguridad_red'
        )
        cursor = conexion.cursor()
        now = datetime.datetime.now()

        # Eliminar datos anteriores solo de IPs escaneadas
        ips_escaneadas = list(resultados.keys())
        formato = ','.join(['%s'] * len(ips_escaneadas))
        cursor.execute(f"DELETE FROM vulnerabilidades WHERE ip IN ({formato})", ips_escaneadas)

        for ip, datos_host in resultados.items():
            for protocolo, puertos in datos_host['protocolos'].items():
                for puerto in puertos:
                    cursor.execute("""
                        INSERT INTO vulnerabilidades (
                            ip, puerto, protocolo, estado, servicio,
                            producto, version, recomendacion, fecha_escaneo
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        ip,
                        puerto['puerto'],
                        protocolo,
                        puerto['estado'],
                        puerto['nombre_servicio'],
                        puerto['producto'],
                        puerto['version'],
                        puerto['recomendacion'],
                        now
                    ))

        conexion.commit()
        print("[+] Resultados guardados en MySQL correctamente.")
    except mysql.connector.Error as error:
        print(f"[!] Error al guardar en MySQL: {error}")
    finally:
        if conexion.is_connected():
            cursor.close()
            conexion.close()

# ---------- USO ------------
if __name__ == "__main__":
    rango = input("Introduce el rango IP a escanear (ej. 192.168.1.0/24): ")
    resultados = escanear_red(rango)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    nombre_archivo = f"vulnerabilidades_{timestamp}.json"

    guardar_resultados(resultados, nombre_archivo)
    guardar_en_mysql(resultados)

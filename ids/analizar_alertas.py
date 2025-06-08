import json
from datetime import datetime, timedelta
from collections import defaultdict
import mysql.connector

# Parámetros
TIEMPO_SESION = timedelta(seconds=10)

SIDS = {
    "icmp": 1000001,
    "ssh": 1000002,
    "http": 1000003,
    "nmap": 1000004,
    "fuerza_bruta": 1000005
}

TIPOS = {
    1000001: "icmp",
    1000002: "ssh",
    1000003: "http",
    1000004: "nmap",
    1000005: "fuerza_bruta"
}

# --- CONEXIÓN DB ---
def conectar_db():
    return mysql.connector.connect(
        host="db",  # nombre del servicio en docker-compose
        user="root",
        password="root123",
        database="seguridad_red"
    )

def crear_tabla_si_no_existe(conn):
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alertas_detectadas (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_origen VARCHAR(45),
            tipo_alerta VARCHAR(50),
            intentos INT,
            hora_inicio DATETIME,
            hora_fin DATETIME
        );
    """)
    conn.commit()
    cursor.close()

def guardar_alerta(conn, ip, tipo, intentos, inicio, fin):
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alertas_detectadas (ip_origen, tipo_alerta, intentos, hora_inicio, hora_fin)
        VALUES (%s, %s, %s, %s, %s)
    """, (ip, tipo, intentos, inicio, fin))
    conn.commit()
    cursor.close()

# --- CARGA Y AGRUPADO ---
def cargar_alertas():
    with open("/var/log/suricata/eve.json", "r") as archivo:
        return [json.loads(linea) for linea in archivo if '"alert"' in linea]

def filtrar_alertas(alertas):
    alertas_filtradas = []
    for alerta in alertas:
        if alerta.get("event_type") != "alert":
            continue

        sid = alerta.get("alert", {}).get("signature_id")
        if sid not in SIDS.values():
            continue

        ip = alerta.get("src_ip", "")
        if ":" in ip or ip.startswith("172.20."):
            continue

        try:
            alerta["timestamp"] = datetime.fromisoformat(alerta["timestamp"].replace("Z", "+00:00"))
        except Exception:
            continue

        alerta["tipo"] = TIPOS[sid]
        alertas_filtradas.append(alerta)
    return alertas_filtradas

def contar_y_mostrar_por_tipo(alertas, conn):
    # Diccionario: {(ip, tipo): [lista_de_timestamps]}
    agrupadas = defaultdict(list)

    for alerta in alertas:
        ip = alerta["src_ip"]
        tipo = alerta["tipo"]
        agrupadas[(ip, tipo)].append(alerta["timestamp"])

    for (ip, tipo), tiempos in agrupadas.items():
        tiempos.sort()
        inicio = tiempos[0]
        fin = tiempos[-1]
        intentos = len(tiempos)

        print(f"== ALERTA: {tipo.upper()} ==")
        print(f"IP: {ip}")
        print(f"De: {inicio} a {fin}")
        print(f"Intentos: {intentos}")
        print("-----------------------------")

        guardar_alerta(conn, ip, tipo, intentos, inicio, fin)

# --- MAIN ---
if __name__ == "__main__":
    conn = conectar_db()
    crear_tabla_si_no_existe(conn)

    cursor = conn.cursor()
    cursor.execute("DELETE FROM alertas_detectadas")
    conn.commit()
    cursor.close()

    alertas = cargar_alertas()
    alertas = filtrar_alertas(alertas)
    contar_y_mostrar_por_tipo(alertas, conn)

    conn.close()

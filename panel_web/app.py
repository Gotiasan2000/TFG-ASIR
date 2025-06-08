from flask import Flask, render_template
import mysql.connector

app = Flask(__name__)

# Conexión a la base de datos
def obtener_conexion():
    return mysql.connector.connect(
        host="db",
        user="root",
        password="root123",
        database="seguridad_red"
    )

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/vulnerabilidades")
def vulnerabilidades():
    conn = obtener_conexion()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vulnerabilidades ORDER BY fecha_escaneo DESC")
    datos = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("vulnerabilidades.html", datos=datos)

@app.route("/alertas")
def alertas():
    conn = obtener_conexion()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alertas_detectadas ORDER BY hora_inicio DESC")
    datos = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("alertas.html", datos=datos)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

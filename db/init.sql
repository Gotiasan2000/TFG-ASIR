CREATE TABLE IF NOT EXISTS vulnerabilidades (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45),
    puerto INT,
    protocolo VARCHAR(10),
    estado VARCHAR(10),
    servicio VARCHAR(100),
    producto VARCHAR(100),
    version VARCHAR(100),
    recomendacion TEXT,
    fecha_escaneo DATETIME
);

CREATE TABLE alertas_detectadas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_origen VARCHAR(45),
    tipo_alerta VARCHAR(50),
    intentos INT,
    hora_inicio DATETIME,
    hora_fin DATETIME
);

from flask import Flask, request, jsonify
from routes import register_routes
import os
import logging
import subprocess
import time

# Configuración del archivo de logs
log_path = "../logs/audit_logs.log"  # Ubicación de los logs fuera de src
os.makedirs(os.path.dirname(log_path), exist_ok=True)

logging.basicConfig(
    filename=log_path,
    level=logging.DEBUG,  # Cambiar a DEBUG para mayor detalle en el log
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Configuración del logger de consola
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
console.setFormatter(formatter)
logging.getLogger("").addHandler(console)

# Inicialización de la aplicación Flask
app = Flask(
    __name__,
    template_folder=os.path.abspath('templates'),  # Ruta absoluta para evitar conflictos
    static_folder=os.path.abspath('static')        # Ruta absoluta para recursos estáticos
)

# Registro de rutas desde el módulo de rutas
register_routes(app)

# Manejo de error 404
@app.errorhandler(404)
def not_found_error(error):
    """Manejo de error 404 - Recurso no encontrado."""
    logging.warning("Ruta no encontrada")
    return jsonify({"error": "Recurso no encontrado"}), 404

# Manejo de error 500
@app.errorhandler(500)
def internal_error(error):
    """Manejo de error 500 - Error interno del servidor."""
    logging.error("Error interno del servidor")
    return jsonify({"error": "Error interno del servidor"}), 500

# Ruta para capturar el handshake
@app.route('/capture_handshake', methods=['POST'])
def capture_handshake_route():
    """Ruta para capturar el handshake WiFi."""
    interface = request.form.get('interface')
    bssid = request.form.get('bssid')
    channel = request.form.get('channel')

    if not interface or not bssid or not channel:
        logging.warning("Faltan parámetros: interface, bssid o channel")
        return jsonify({"error": "Todos los campos son obligatorios."}), 400

    # Crear el directorio 'captures' si no existe
    os.makedirs('captures', exist_ok=True)

    # Generar un nombre único para el archivo .cap asegurando que empiece en cap6
    base_filename = f'handshake-{bssid}'
    cap_number = 6  # Empezar desde cap6

    # Buscar el siguiente número de archivo disponible
    while os.path.exists(f'captures/{base_filename}-{cap_number}.cap'):
        cap_number += 1

    output_file = os.path.join('captures', f'{base_filename}-{cap_number}.cap')

    try:
        # Asegurar que la interfaz esté en modo monitor
        subprocess.run(['sudo', 'ifconfig', interface, 'down'], check=True)  # Apagar la interfaz
        subprocess.run(['sudo', 'iw', interface, 'set', 'type', 'monitor'], check=True)  # Cambiar a monitor
        subprocess.run(['sudo', 'ifconfig', interface, 'up'], check=True)  # Volver a encender la interfaz

        # Crear el comando para airodump-ng
        command = [
            'sudo', 'airodump-ng', '--bssid', bssid, '--channel', channel, '--write', output_file, interface
        ]

        # Ejecutar el comando en segundo plano
        subprocess.Popen(command)
        logging.info(f"Captura de handshake iniciada para BSSID {bssid} en el archivo {output_file}")
        return jsonify({"message": f"Captura de handshake iniciada. El archivo se guardará como {output_file}."}), 200
    except subprocess.CalledProcessError as e:
        logging.error(f"Error al configurar la interfaz o ejecutar airodump-ng: {e.stderr}")
        return jsonify({"error": f"Error al configurar la interfaz o ejecutar airodump-ng: {e.stderr}"}), 500
    except Exception as e:
        logging.error(f"Error inesperado al capturar handshake: {str(e)}")
        return jsonify({"error": f"Error inesperado: {str(e)}"}), 500

# Ruta para crackear la contraseña
@app.route('/crack_password', methods=['POST'])
def crack_password_route():
    """Ruta para crackear contraseñas usando un archivo de diccionario."""
    # Obtener los archivos del formulario
    handshake_file = request.files.get('handshakeFile')
    dict_file = request.files.get('dictFile')

    if not handshake_file or not dict_file:
        logging.warning("Faltan archivos: handshake o diccionario")
        return jsonify({"error": "Ambos archivos son necesarios (handshake y diccionario)."}), 400

    # Guardar los archivos de forma temporal
    uploads_dir = os.path.join(os.path.dirname(__file__), 'uploads')
    os.makedirs(uploads_dir, exist_ok=True)
    
    handshake_path = os.path.join(uploads_dir, handshake_file.filename)
    dict_path = os.path.join(uploads_dir, dict_file.filename)
    handshake_file.save(handshake_path)
    dict_file.save(dict_path)

    try:
        # Comando para usar aircrack-ng
        command = [
            'sudo', 'aircrack-ng', handshake_path, '-w', dict_path
        ]
        logging.info(f"Iniciando crackeo con {command}")
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        # Buscar la contraseña en la salida
        output = result.stdout
        if "KEY FOUND" in output:
            password = output.split("KEY FOUND! [")[1].split("]")[0]
            logging.info(f"Contraseña encontrada: {password}")
            return jsonify({"message": "Contraseña encontrada", "password": password}), 200
        else:
            logging.info("No se encontró la contraseña")
            return jsonify({"message": "No se encontró la contraseña con este diccionario"}), 404
    except subprocess.CalledProcessError as e:
        logging.error(f"Error al crackear contraseña: {e.stderr}")
        return jsonify({"error": f"Error al crackear contraseña: {e.stderr}"}), 500
    except Exception as e:
        logging.error(f"Error inesperado al crackear contraseña: {str(e)}")
        return jsonify({"error": f"Error inesperado: {str(e)}"}), 500

# Ruta para listar interfaces
@app.route('/list_interfaces', methods=['GET'])
def list_interfaces_route():
    """Ruta para listar interfaces de red disponibles."""
    from services import list_interfaces  # Importar dentro de la ruta para evitar referencias cruzadas
    try:
        interfaces = list_interfaces()
        if not interfaces:
            logging.warning("No se encontraron interfaces disponibles")
            return jsonify({"error": "No se encontraron interfaces disponibles"}), 404
        return jsonify({"interfaces": interfaces}), 200
    except Exception as e:
        logging.error(f"Error al listar interfaces: {e}")
        return jsonify({"error": "Error al listar interfaces"}), 500

# Ruta para escanear redes Wi-Fi
@app.route('/scan_wifi', methods=['GET'])
def scan_wifi_route():
    """Ruta para escanear redes Wi-Fi."""
    from services import scan_wifi, save_scan_results_to_csv
    interface = request.args.get('interface')
    if not interface:
        logging.warning("Interfaz no proporcionada en /scan_wifi")
        return jsonify({"error": "Interfaz no proporcionada"}), 400

    logging.info(f"Escaneando redes con la interfaz: {interface}")
    try:
        networks, status_code = scan_wifi(interface)
        if status_code != 200:
            return jsonify(networks), status_code

        # Guardar resultados en CSV y JSON
        from services import save_scan_results_to_json
        save_scan_results_to_csv(networks)
        save_scan_results_to_json(networks)

        return jsonify({"networks": networks}), 200
    except Exception as e:
        logging.error(f"Error al escanear redes Wi-Fi: {e}")
        return jsonify({"error": "Error al escanear redes Wi-Fi"}), 500

if __name__ == "__main__":
    print(f"Template folder: {os.path.abspath(app.template_folder)}")
    logging.info("Servidor Flask iniciado")
    app.run(debug=True, host="0.0.0.0", port=5000)

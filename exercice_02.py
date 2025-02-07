import socket
import threading
import datetime
import os

PORTS_TO_MONITOR = [22, 23, 80, 443, 3306, 8080]  # SSH, Telnet, HTTP, HTTPS, MySQL, HTTP proxy
LOG_FILE = "honeypot_logs.txt"

def log_connection(client_ip: str, port: int, data: str | None = None):
    """Ce code est exécuté lorsqu'un client se connecte à notre programme."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] Tentative de connexion de {client_ip} sur le port {port}"
    
    if data:
        log_entry += f" - Données reçues: {data.strip()}"
    
    print(log_entry)  # Affichage en temps réel
    with open(LOG_FILE, "a") as log_file:
        log_file.write(log_entry + "\n")


def handle_connection(client_socket: socket.socket, client_address: tuple, port: int):
    # Ce code est exécuté lorsqu'un client se connecte à notre programme. 
    # Il est exécuté dans un thread de la fonction 'listen_on_port'.
    client_ip, _ = client_address
    log_connection(client_ip, port)
    
    try:
        client_socket.send(b"Bienvenue sur le serveur!\n")

        data = client_socket.recv(1024).decode().strip()
        if data:
            log_connection(client_ip, port, data)
        
    
        client_socket.send(b"Acces refuse!\n")
    except Exception as e:
        print(f"Erreur avec {client_ip}: {e}")
    finally:
        client_socket.close()

def listen_on_port(port: int):
    """Cette fonction est exécutée dans un thread. Elle écoute sur le port spécifié."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", port))
    server_socket.listen(5)
    print(f"🛡️  Écoute sur le port {port}...")
    
    while True:
        client_socket, client_address = server_socket.accept()
        threading.Thread(target=handle_connection, args=(client_socket, client_address, port), daemon=True).start()

def start_honeypot():
    print("🛡️  Honeypot en cours d'exécution...")
    
    # Lancer un thread par port surveillé
    for port in PORTS_TO_MONITOR:
        threading.Thread(target=listen_on_port, args=(port,), daemon=True).start()
    
    # Garde le programme en exécution
    while True:
        pass

if __name__ == "__main__":
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()  # Créer un fichier de logs s'il n'existe pas
    
    start_honeypot()
    # On lance le code dans un terminal et dans un autre terminal on lance le fichier 'client.py'


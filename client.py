import socket

host = "192.168.1.161"
port = 23  # Port du honeypot

# Se connecter au honeypot
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((host, port))

# Recevoir la réponse du honeypot
response = client_socket.recv(1024).decode()
print("[📡 Réponse du serveur]:", response)

# Envoyer un test de connexion (ex : "admin")
client_socket.send(b"admin\n")

# Lire la réponse et fermer la connexion
response = client_socket.recv(1024).decode()
print("[📡 Réponse après envoi]:", response)

client_socket.close()
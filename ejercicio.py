import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Obtener la ruta del directorio actual
current_directory = os.path.dirname(os.path.abspath(__file__))

# Rutas de los archivos en la misma carpeta que el script
original_file = os.path.join(current_directory, "Original.txt")
damage_file = os.path.join(current_directory, "Prueba.enc")
key_file = os.path.join(current_directory, "Clave.txt")
iv_file = os.path.join(current_directory, "IV.txt")

def generate_key_iv():
    key = os.urandom(32)  # 32 bytes para AES-256
    iv = os.urandom(16)   # 16 bytes para el IV
    return key, iv

def save_to_file(filename, data):
    with open(filename, 'wb') as file:
        file.write(data)

def load_from_file(filename):
    with open(filename, 'rb') as file:
        return file.read()

def encrypt_file(key, iv):
    with open(original_file, 'rb') as infile, open(damage_file, 'wb') as outfile:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        while True:
            chunk = infile.read(1024)
            if not chunk:
                break
            # Rellenar el chunk si no es múltiplo de 16
            if len(chunk) % 16 != 0:
                chunk += b'\x00' * (16 - len(chunk) % 16)
            outfile.write(encryptor.update(chunk))
        outfile.write(encryptor.finalize())

def decrypt_file(key, iv):
    with open(damage_file, 'rb') as infile, open(original_file, 'wb') as outfile:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        while True:
            chunk = infile.read(1024)
            if not chunk:
                break
            outfile.write(decryptor.update(chunk))
        outfile.write(decryptor.finalize())

if __name__ == "__main__":
    if os.path.exists(key_file) and os.path.exists(iv_file):
        # Cargar clave y IV de los archivos
        key = load_from_file(key_file)
        iv = load_from_file(iv_file)
        
        # Descifrar archivo
        decrypt_file(key, iv)

        # Eliminar archivos de clave e IV
        os.remove(key_file)
        os.remove(iv_file)
        os.remove(damage_file)
    else:
        # Generar nueva clave y IV
        key, iv = generate_key_iv()

        # Guardar clave y IV en archivos
        save_to_file(key_file, key)
        save_to_file(iv_file, iv)

        # Cifrar archivo
        encrypt_file(key, iv)

        # Eliminar archivo original
        os.remove(original_file)

       
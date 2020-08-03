""" from Crypto import Random
from Crypto.Cipher import AES """

from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
from os import listdir, system
from os.path import isfile, join

clear = lambda: os.system('clear')

# Default cipher key
key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'

menu = """
    1. Presiona '1' para cifrar el archivo.
    2. Presiona '2' para descifrar.
    3. Presiona '3' para cifrar todos los archivos .pdf en esta carpeta.
    4. Presiona '4' para descifrar todos los archivos .pdf de esta carpeta.
    5. Presiona '5' para salir."
"""

class Encryptor:
    def __init__(self, key):
        self.key = key

    # Padding is used in a block cipher where we fill up the blocks with padding bytes. 
    # AES uses 128-bits (16 bytes)
    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    # Encrypt phase, with message and key as params
    def encrypt(self, message, key, key_size=256):
        # Applying padding on received message
        message = self.pad(message)
        # The important thing about an IV is you must never use the same IV for two messages.
        iv = Random.new().read(AES.block_size)
        # Encrypting message with key and initialization vector
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    # Encrypts any file on same directory
    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        encryptor = self.encrypt(plaintext, self.key)
        with open(file_name + ".enc", 'wb') as fo:
            fo.write(encryptor)
        os.remove(file_name)

    # Decrypt phase, with cipher message and key as params
    def decrypt(self, ciphertext, key):
        # Sets initialization vector with default AES block size
        iv = ciphertext[:AES.block_size]
        # Decrypting message with key and initialization vector
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # Retrieving cipher text based on block size, and then decrypts message
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    # Decrypts any file with filename as param
    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, self.key)
        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)

    # It gets all files on same folder as array
    def getAllFiles(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        dirs = []
        for dirName, subdirList, fileList in os.walk(dir_path):
            for fname in fileList:
                if (fname != 'aes.py' and fname != 'data.txt.enc' and (".pdf" in  fname or ".txt" in fname or ".docx" in fname or ".odt" in fname)):
                    dirs.append(dirName + "/" + fname)
                    print(fname)
        return dirs

    # Encrypts all files on same directory
    def encrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.encrypt_file(file_name)

    # Decrypts all files on same directory
    def decrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.decrypt_file(file_name)

# Simple AES
encryptor = Encryptor(key)

# If password has been saved before...
if os.path.isfile('data.txt.enc'):

    while True:
        password = str(input("Ingresa contraseña: "))
        encryptor.decrypt_file("data.txt.enc")
        p = ''
        with open("data.txt", "r") as f:
            p = f.readlines()
        if p[0] == password:
            encryptor.encrypt_file("data.txt")
            break

    while True:
        clear()
        choice = int(input(menu))
        clear()
        if choice == 1:
            encryptor.encrypt_file(str(input("Ingresa el nombre del archivo a cifrar: ")))
        elif choice == 2:
            encryptor.decrypt_file(str(input("Ingresa el nombre del archivo a descifrar: ")))
        elif choice == 3:
            encryptor.encrypt_all_files()
        elif choice == 4:
            encryptor.decrypt_all_files()
        elif choice == 5:
            exit()
        else:
            print("Por favor, selecciona una opcion valida...")
else:
    # Initial phase if password does not exists.     
    correct_password = False
    while not correct_password:
        clear()
        password = str(input("Implementando AES Simple. Ingresa la contraseña que servirá para descifrar: "))
        confirm_password = str(input("Confirmar contrasena: "))
        if password == confirm_password:
            correct_password = True
        else:
            print("La contraseña no concuerda, intente de nuevo...")
    # Saving password
    f = open("data.txt", "w+")
    f.write(password)
    f.close()
    # Encrypts password
    encryptor.encrypt_file("data.txt")
    print("Vuelve a correr el programa de nuevo para aplicar los cambios...")
    exit()


#####################################
#   Lab Answers
#####################################

"""
PART I

i.  ¿Tuvo que usar “encode” de algo? ¿Sobre que variables?
    El encode es aplicado en la contraseña, y el texto plano

ii. ¿Que modo de AES uso? ¿Por que? 
    Es un modo simple usando CBC (Cipher clock chaining), debido a que
    es muy poco probable que haya patrones en el output cifrado. Otra ventaja es 
    que el descifrado se puede hacer en paralelo para acelerar las cosas.

iii. ¿Que parámetros tuvo que hacer llegar desde su funcion de Encrypt la Decrypt? ¿Porque?
    Initializing Vector (IV), key, el texto cifrado y modo (CBC)

    El vector de inicializacion permite comenzar a cifrar el primer bloque (dado a que no se cuenta con un bloque anterior) 
    de texto, se debe pasar del encrypt al decrypt para poder decifrar
"""


"""
PART II

i. ¿Que modo de AES uso? ¿Por que? 
    Igual, usando CBC (Cipher clock chaining). En comparacion con otros metodos, 
    algunos pueden ser inseguros: bloques de texto sin formato identicos darán como resultado texto cifrado identico. 
    Esto significa que un atacante puede detectar fácilmente la repeticion. 
    Con CBC, seresuelve esto mediante la introduccion de un vector, que altera el primer bloque de texto 
    sin formato antes de encriptarlo.

ii. ¿Que parámetros tuvo que hacer llegar desde su funcion de Encrypt la Decrypt? ¿Porque?
    Initializing Vector (IV), key, el texto cifrado y modo (CBC)
    Se usaron los mismos parámetros, 

iii.¿Que variables considera las mas importantes dentro de su implementacion? ¿Por que?
    IV: lo importante de implementarlo es que nunca se va a usar el mismo IV para dos 
    mensajes, generando seguridad en el cifrado y una clave aleatoria.
    Password: esta se debe establecer antes del cifrado, es la mas importante ya que
    tanto el encriptar como desencriptar dependen de ella.

"""



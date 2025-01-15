# RSW_Beta

Este programa simula un ransomware que encripta y desencripta archivos de texto en la carpeta Archivos dentro de la víctima. 

Tambien tiene la carpeta Atacante que simula ser la maquina del atacante para ver todo el proceso de interaccion con la victima

A continuación, se describen las opciones del menú y las funciones utilizadas en cada punto.

## Opciones del Menú

1. **Preparación de la infección**
   - Función: `Infeccion()`
   - Descripción: Genera las claves pública y privada del atacante y las guarda en la carpeta `Atacante`.

2. **Transmisión a la víctima del ransomware**
   - Función: `Transmision()`
   - Descripción: Copia la clave pública del atacante a la carpeta `Victima` y guarda el hash de la clave pública en la carpeta `Atacante`, cuando realiza el envio de la clave publica recibe el hash de la clave publica como confirmacion de la infeccion.

3. **Encriptación de los archivos**
   - Funciones: `generacion()`, `encriptacion_files()`, `limpieza()`
   - Descripción:
     - `generacion()`: Genera las claves pública y privada de la víctima y un código aleatorio KS.
     - `encriptacion_files()`: Encripta los archivos `.txt` en la carpeta `Victima/Archivos` usando AES-CBC.
     - `limpieza()`: Encripta el código KS con la clave pública de la víctima y la clave privada de la víctima con la clave pública del atacante, luego elimina los archivos originales.

4. **Pago de rescate - Desencriptación**
   - Funciones: `Pago()`, `desencriptacion()`
   - Descripción:
     - `Pago()`: Desencripta la clave privada de la víctima usando la clave privada del atacante y la copia de vuelta a la carpeta `Victima`, cuando realiza el envio de la clave privada, recibe el hash de la clave privada enviada como confirmacion de la infeccion.
     - `desencriptacion()`: Desencripta el código KS y los archivos `.txt` en la carpeta `Victima/Archivos` usando la clave privada de la víctima.

9. **Puesta en Cero del escenario**
   - Función: `Clean()`
   - Descripción: Elimina todos los archivos en la carpeta `Victima` excepto la carpeta `Archivos`, mueve los archivos `.txt` a la carpeta `Archivos`, y elimina todos los archivos en la carpeta `Atacante`.

0. **Salir**
   - Descripción: Sale del programa.

## Ejecución del Programa

Para ejecutar el programa, simplemente corre el archivo `RSW_Beta.py` y sigue las instrucciones del menú.

```bash
python RSW_Beta.py
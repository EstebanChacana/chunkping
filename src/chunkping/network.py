#importar librerias
import socket
import struct
import time
from typing import Iterator

ICMP_ECHO_REQUEST = 8
HEADER_FORMAT = "!BBHHH"  # tipo, codigo, checksum, id, seq
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)



def calcular_checksum(data: bytes) -> int: #<-- calcula el cheksum que exige el estandar del ICMP
    if len(data) % 2:
        data += b"\x00"  

    total = 0
    for i in range(0, len(data), 2): #<-- toma bloques de 2 bytes  
        word = (data[i] << 8) + data[i + 1]
        total += word

    
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16 #<-- suma de vuelta el acarreo que se paso de 16 bits
    return ~total & 0xFFFF #<-- devuelve un bloque de 16 bits


def construir_paquete_icmp(payload: bytes, packet_id: int, seq: int) -> bytes:
    header = struct.pack(HEADER_FORMAT, ICMP_ECHO_REQUEST, 0, 0, packet_id, seq)
    checksum = calcular_checksum(header + payload) #<-- calcula el checksum(es como digito verificador)
    header = struct.pack(HEADER_FORMAT, ICMP_ECHO_REQUEST, 0, checksum, packet_id, seq)
    return header + payload #<-- el header en simples palabras es la direccion el payload es el mensaje



def crear_socket_envio() -> socket.socket: #<-- crear un socket(es como pedirle al sistema que cree una linea telefonica para comunicarse)
    #la linea de abajo se encarga de crear un socket de ipv4 mediante "af_inet" tambien pide un socket crudo osea nosotros lo armamos no es udp ni tcp 
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) #<-- el tercer agurmento se encarga de especificar el protocolo osea icmp  
    return sock #<-- devuelve el socket listo para enviar poder comunicarse


def enviar_bloque(sock: socket.socket, ip_destino: str, payload: bytes, packet_id: int, seq: int) -> None: #<-- prepara un solo bloque osea un solo ping
    paquete = construir_paquete_icmp(payload, packet_id, seq) #construye el paquete a enviar
    sock.sendto(paquete, (ip_destino, 0)) #envia el paquete a la ip destino al puerto 0. porque ICMP no ocupa puertos


def enviar_chunks(ip_destino: str, chunks: Iterator[bytes], packet_id: int = 1, delay: float = 0.05) -> int: #<-- recorre todos los chunks y los manda uno por uno
    
    sock = crear_socket_envio() #<-- abre un socket para poder enviar los pings
    seq = 0 
    try:
        for chunk in chunks: #<-- va por partes de chunk en chunk 
            enviar_bloque(sock, ip_destino, chunk, packet_id, seq)
            seq += 1
            time.sleep(delay)  # evita saturar la red para que no se pierdan paquetes
    finally: #<-- se asegura de cerrar el socket siempre.  
        sock.close()
    return seq
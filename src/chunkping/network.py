"""
network.py
Envio y recepcion de datos sobre ICMP (ping) en una red local.
Proyecto academico de ciberseguridad - uso exclusivo en red local supervisada.

Requiere privilegios de root en Linux porque usa raw sockets:
    sudo python3 cli.py send --file archivo.txt --ip 192.168.1.50
    sudo python3 cli.py receive --output salida.txt --count 10
"""

import socket
import struct
import select
import time
from typing import Iterator, Optional

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
HEADER_FORMAT = "!BBHHH"  # tipo, codigo, checksum, id, seq
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


def calcular_checksum(data: bytes) -> int:
    """Checksum estandar de ICMP (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"  # padding si es impar

    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word

    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def construir_paquete_icmp(payload: bytes, packet_id: int, seq: int) -> bytes:
    """
    Arma un paquete ICMP Echo Request con el payload (el bloque de 16 bytes
    que viene de core.py) metido en el campo de datos.
    """
    # header provisional con checksum en 0 para poder calcularlo
    header = struct.pack(HEADER_FORMAT, ICMP_ECHO_REQUEST, 0, 0, packet_id, seq)
    checksum = calcular_checksum(header + payload)
    header = struct.pack(HEADER_FORMAT, ICMP_ECHO_REQUEST, 0, checksum, packet_id, seq)
    return header + payload


def crear_socket_envio() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    return sock


def crear_socket_escucha(timeout: float = 5.0) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.settimeout(timeout)
    return sock


def enviar_bloque(sock: socket.socket, ip_destino: str, payload: bytes,
                   packet_id: int, seq: int) -> None:
    """Envia un unico bloque como paquete ICMP."""
    paquete = construir_paquete_icmp(payload, packet_id, seq)
    sock.sendto(paquete, (ip_destino, 0))


def enviar_chunks(ip_destino: str, chunks: Iterator[bytes],
                   packet_id: int = 1, delay: float = 0.05) -> int:
    """
    Recorre los chunks que entrega core.py (read_chunks) y los va mandando
    por ICMP, uno por paquete, con numero de secuencia creciente.
    Devuelve la cantidad de paquetes enviados.
    """
    sock = crear_socket_envio()
    seq = 0
    try:
        for chunk in chunks:
            enviar_bloque(sock, ip_destino, chunk, packet_id, seq)
            seq += 1
            time.sleep(delay)  # evita saturar la red / que se pierdan paquetes
    finally:
        sock.close()
    return seq


def _extraer_payload_icmp(paquete_ip: bytes) -> Optional[tuple[int, int, bytes]]:
    """
    paquete_ip viene con el header IP incluido (asi llega en raw socket).
    Devuelve (tipo_icmp, seq, payload) o None si no es un echo request/reply valido.
    """
    ip_header_len = (paquete_ip[0] & 0x0F) * 4  # IHL en el primer byte
    icmp_segment = paquete_ip[ip_header_len:]

    if len(icmp_segment) < HEADER_SIZE:
        return None

    tipo, codigo, checksum, packet_id, seq = struct.unpack(
        HEADER_FORMAT, icmp_segment[:HEADER_SIZE]
    )
    payload = icmp_segment[HEADER_SIZE:]
    return tipo, seq, payload


def escuchar_bloques(cantidad_esperada: int, timeout: float = 10.0,
                      ip_origen: Optional[str] = None) -> dict[int, bytes]:
    """
    Escucha paquetes ICMP entrantes y va guardando los payloads indexados
    por numero de secuencia, para poder reordenarlos despues.

    Se queda escuchando hasta juntar 'cantidad_esperada' paquetes o hasta
    que se agote el timeout total.
    """
    sock = crear_socket_escucha(timeout=timeout)
    recibidos: dict[int, bytes] = {}
    tiempo_limite = time.time() + timeout

    try:
        while len(recibidos) < cantidad_esperada and time.time() < tiempo_limite:
            restante = tiempo_limite - time.time()
            if restante <= 0:
                break

            listos, _, _ = select.select([sock], [], [], restante)
            if not listos:
                break  # se acabo el timeout sin nada nuevo

            paquete_ip, addr = sock.recvfrom(65535)

            if ip_origen and addr[0] != ip_origen:
                continue  # ignora trafico de otras IPs

            datos = _extraer_payload_icmp(paquete_ip)
            if datos is None:
                continue

            tipo, seq, payload = datos
            if tipo != ICMP_ECHO_REQUEST:
                continue  # solo nos interesan los echo request (los que enviamos nosotros)

            if seq not in recibidos:
                recibidos[seq] = payload
    finally:
        sock.close()

    return recibidos


def reconstruir_bloques(recibidos: dict[int, bytes]) -> bytes:
    """
    Ordena los payloads recibidos por numero de secuencia y los concatena
    para reconstruir el archivo original en binario.
    """
    secuencias_ordenadas = sorted(recibidos.keys())
    return b"".join(recibidos[seq] for seq in secuencias_ordenadas)
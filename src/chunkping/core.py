#LOGICA PRINCIPAL 
#LECTURA POR BLOQUES POR BYTES Y CONVIERTE A HEXADECIMAL 

#importar librerias
from __future__ import annotations 
from pathlib import Path
from typing import Iterator

#establecer de cuantos bytes seran los bloques
DEFAULT_CHUNK_SIZE = 16

#funcion para validar que el tamaño del chunk(bloque) sea entero positivo
def _validate_chunk_size(chunk_size : int) -> None:
    if not isinstance(chunk_size, int) or chunk_size <= 0:
        raise ValueError("el tamaño de bloque debe ser un entero mayor que 0.")
    
#funcion para abrir el archivo y leerlo en chunks
def read_chunks(ruta_archivo: str | Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Iterator[bytes]:
    _validate_chunk_size(chunk_size)
    with open(ruta_archivo , "rb") as archivo: #<-- lee el archivo en binario 
        while chunk := archivo.read(chunk_size):
            yield chunk #<-- envia parte del archivo en bytes(no guarda lo que ya envio) 

#funcion para fraccionar datos binarios sin necesidad de abrir un archivo
def chunk_bytes(data: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Iterator[bytes]:
    _validate_chunk_size(chunk_size)
    for start in range(0, len(data), chunk_size):
        yield data[start : start + chunk_size] #<-- separa y entrega bloque del tamaño indicado 

#funcion para convertir bytes a hexadecimal
def to_hex(chunk: bytes, separator: str = "", uppercase: bool = False) -> str:
    result = chunk.hex(separator) if separator else chunk.hex()
    return result.upper() if uppercase else result 
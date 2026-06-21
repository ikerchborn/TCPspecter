# core/tarpit.py
"""
Deception Tarpit Server — neutraliza escáneres y atacantes reteniendo conexiones TCP.
"""
import asyncio
import logging
import threading

log = logging.getLogger(__name__)

_server = None
_loop = None
_thread = None

async def _tarpit_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    addr = writer.get_extra_info("peername")
    log.info("Tarpit: Conexión de atacante detectada y atrapada desde %s", addr)
    try:
        # Enviar bytes muy lentamente para mantener la conexión del atacante abierta indefinidamente
        while True:
            await asyncio.sleep(15.0)
            writer.write(b"\x00")
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log.debug("Excepción en tarpit handler: %s", e)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        log.info("Tarpit: Conexión cerrada con %s", addr)


def start_tarpit(port: int = 8000) -> bool:
    """Inicia el servidor Tarpit en un hilo de loop asyncio dedicado."""
    global _server, _loop, _thread
    if _server is not None:
        return True

    def run_loop():
        global _loop, _server
        _loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_loop)
        try:
            coro = asyncio.start_server(_tarpit_handler, "0.0.0.0", port)
            _server = _loop.run_until_complete(coro)
            log.info("Tarpit de Decepción escuchando en puerto %d", port)
            _loop.run_forever()
        except Exception as e:
            log.error("No se pudo iniciar el Tarpit: %s", e)

    _thread = threading.Thread(target=run_loop, name="tarpit-server", daemon=True)
    _thread.start()
    return True


def stop_tarpit() -> None:
    """Detiene el servidor Tarpit de forma segura."""
    global _server, _loop, _thread
    if _server is None:
        return

    try:
        _server.close()
        if _loop is not None:
            _loop.call_soon_threadsafe(_loop.stop)
    except Exception as e:
        log.error("Error al detener el Tarpit: %s", e)
    finally:
        _server = None
        _loop = None
        _thread = None
        log.info("Tarpit de Decepción detenido.")

# TCPspecter

**TCPspecter** es una plataforma de Network Traffic Analysis (NTA), NDR (Network Detection and Response) y análisis forense de procesos en tiempo real escrita en Python 3.11+ para sistemas GNU/Linux (como Debian, Ubuntu o Parrot Security OS). Inspirada en el clásico **TCPView de Sysinternals para Windows**, ofrece visualización interactiva de sockets y PIDs, auditoría de reputación VirusTotal, detección de malware fileless y capacidades de mitigación/respuesta activa integradas directamente desde la consola o su interfaz web.

---

## 📸 Capturas de Pantalla (Screenshots)

### 💻 Interfaz de Terminal (TUI)
Nuestra interfaz TUI ASCII premium con gráficos de rendimiento local, distribución de sockets y análisis zombie heurístico en tiempo real:
![TCPspecter TUI Interface](media/media__1782004737440.png)

### 🌐 Dashboard Web Gráfico (Glassmorphic)
El panel gráfico interactivo de control accesible en tu navegador local (`http://localhost:8050` o el puerto configurado en `config.json`):
![TCPspecter Web Dashboard](media/media__1782005073785.png)

### 🗺️ Mapa Geográfico & Traceroute (Web)
Visualización geográfica dinámica de tus conexiones IP activas y saltos de red intermediate en un mapa real de Apache ECharts:
![TCPspecter Web Cyber Map](media/media__1782000944472.png)

---

## Arquitectura y Visión del Proyecto: Plataforma NTA / NDR / NDR de Grado Empresarial

El objetivo principal de **TCPspecter** no es ser simplemente otro sniffer de red pasivo. El proyecto implementa una arquitectura desacoplada a través de un **Alert Bus asíncrono** y modular que separa los motores de detección del frontend y de la persistencia de datos.

### Motores de Seguridad y Flujo de Datos

```text
  [Snort IDS] ────┐
  [Scapy NTA] ────┼──→ alerts.publish() ──→ [ Alert Bus (Queue) ] ──→ [ Web Server / TUI ]
  [Proc Maps] ────┘                                |
                                                   └──→ Webhooks Firmados (SOAR)
                                                   └──→ Persistencia ECS JSON
```

1. **Separación de Privilegios y Desacoplamiento (SOLID)**: Los sniffers y analizadores (`traffic_analyzer`, `snort_manager`, `zombie_detector`) operan sin conocer al servidor web o la interfaz de usuario. Publican alertas de forma no bloqueante a una cola en [`core/alerts.py`](file:///home/kingsman/.gemini/antigravity/scratch/tcpspecter/core/alerts.py) para que un hilo dedicado las procese y persista en disco.
2. **Elastic Common Schema (ECS v1.12)**: Todas las alertas se serializan en formato estandarizado JSON ECS, listas para su ingesta inmediata en SIEMs como Splunk, Elasticsearch o Wazuh.
3. **Mapeo de Cumplimiento Normativo Integrado**: Cada alerta incluye etiquetas asociadas a controles de **NIST CSF** (ej. `PR.DS-5`, `DE.CM-7`) y de **ISO/IEC 27001** (ej. `A.12.6.1`, `A.13.1.1`), facilitando auditorías de cumplimiento continuas.

---

## Características Principales y Novedades del Sistema

*   **Detección de Malware Fileless (Memory Scanner)**: Escanea dinámicamente `/proc/[pid]/maps` buscando segmentos de memoria marcados como ejecutables (`x`) pero sin respaldo físico en disco (memoria anónima). Detecta shellcodes y payloads inyectados en memoria (MITRE ATT&CK `T1055` - Process Injection).
*   **Respuesta Activa y Cuarentena Host (SOAR)**: Permite aislar completamente el endpoint bajo sospecha vía `quarantine_host()`. Genera cadenas aisladas de `iptables` (`TCPSPECTER-Q-IN` y `TCPSPECTER-Q-OUT`) que bloquean todo el tráfico entrante/saliente excepto el loopback y las IPs de los analistas de incidentes configuradas.
*   **Tecnología de Engaño (Deception & Tarpitting)**: En lugar de simplemente descartar paquetes de IPs atacantes, TCPspecter puede redirigir los intentos de conexión de un atacante usando `PREROUTING DNAT` a un servidor Tarpit integrado ([`core/tarpit.py`](file:///home/kingsman/.gemini/antigravity/scratch/tcpspecter/core/tarpit.py)). El Tarpit responde a una velocidad extremadamente lenta (1 byte cada 15 segundos), agotando y bloqueando los escáneres automáticos.
*   **Webhooks Criptográficos**: Envía automáticamente payloads firmados mediante `HMAC-SHA256` a plataformas externas de orquestación de respuesta (SOAR). La firma va incluida en la cabecera `X-TCPspecter-Signature` usando el secreto definido en `config.json`.
*   **Análisis de Beaconing C2**: Identifica patrones regulares de comunicación C2 (Command and Control) analizando el coeficiente de variación de los intervalos de conexiones salientes por PID.
*   **Seguridad Web Endurecida**: Implementa protección contra ataques de inyección de comandos en las llamadas del firewall mediante sanitización estricta de IPs con el módulo `ipaddress`, tokens CSRF de un solo uso por cliente con TTL de 30 minutos, limitación de tasa (Rate Limiting de 30 peticiones/min) y cabeceras de seguridad estrictas (CSP, X-Frame-Options, HSTS).

---

## Instalación y Uso Rápido

### Requisitos Previos
*   Python 3.11+
*   Soporte de terminal mínimo de 80x24 caracteres
*   Paquete `python3-venv` instalado en el sistema
*   Privilegios de superusuario (`sudo`) para interactuar con `iptables`, `snort` y los sockets de otros usuarios.

```bash
# Clonar y entrar al repositorio
cd tcpspecter

# Dar permisos y ejecutar
chmod +x run.sh
./run.sh
```

El script `run.sh` se encarga de crear el entorno virtual, instalar las dependencias necesarias (`requirements.txt`) y ejecutar la aplicación elevando privilegios si así lo confirmas.

---

## 🌐 Servidor y Dashboard Web Gráfico

TCPspecter incluye un servidor web integrado que levanta automáticamente un dashboard gráfico en tiempo real al iniciar la aplicación.

*   **Dirección de Acceso**: Abre tu navegador e ingresa a:
    `http://localhost:8050` (o `http://127.0.0.1:8050`)
*   **Puerto por Defecto**: **`8050`**.
*   **Personalización de Puerto**: Si deseas cambiar el puerto de escucha o configurar webhooks, edita el archivo `config.json`:
    ```json
    {
      "virustotal_api_key": "TU_API_KEY_AQUI",
      "web_server_port": 8050,
      "webhook_url": "http://tu-plataforma-soar/endpoint",
      "webhook_secret": "clave_hmac_secreta"
    }
    ```

---

## Mapeo Completo de Teclas (Keybindings en TUI)

| Tecla | Acción | Descripción |
| :--- | :--- | :--- |
| `↑` / `k` | Cursor Arriba | Desplazar selección en la tabla activa |
| `↓` / `j` | Cursor Abajo | Desplazar selección en la tabla activa |
| `TAB` | Cambiar Foco | Alterna el foco entre los paneles del sistema |
| `a` | Analizar (Local) | Análisis offline del binario seleccionado (SUID, hashes, permisos) |
| `v` | Analizar (VirusTotal) | Consulta de reputación online en la API de VirusTotal |
| `x` | Terminar Proceso | Kill PID seleccionado con confirmación segura |
| `d` | Resolver DNS | Activa/Desactiva la resolución DNS inversa en segundo plano |
| `/` | Filtrar | Barra de búsqueda en tiempo real (IP, puerto, PID, proceso) |
| `p` | Filtro Protocolo | Filtra los sockets en la tabla: `ALL` → `TCP` → `UDP` → `LISTEN` |
| `s` | Ordenar Columna | Cambia la columna de ordenación de los procesos activos |
| `e` | Exportar Reporte | Genera reportes del sistema en formatos CSV o JSON |
| `z` | Analizar Zombie | Auditoría heurística detallada de amenazas C2 y Zombie en el sistema |
| `c` | Ver todas / Filtrar | Alterna entre ver todas las conexiones del sistema o solo del proceso |
| `m` | Mapa Global (Browser)| Abre el mapa geográfico en el navegador web local |
| `g` | Gráficos (TUI) | Modal de gráficos locales integrados en la terminal |
| `Shift+g` | Gráficos (Browser) | Abre el navegador web al Dashboard Gráfico |
| `i` | Interpretar | Abre el panel del Explanation Engine para traducir el socket a lenguaje humano |
| `S` | On/Off Analítica | Activa o desactiva las heurísticas de seguridad avanzadas en tiempo real |
| `f` | Cortafuegos | Abre el panel de control del Cortafuegos (Firewall) con el estado de reglas |
| `t` | On/Off Snort | Inicia o detiene el servicio pasivo de detección de intrusos Snort |
| `b` | Bloquear IP | Bloquea la IP externa de la conexión seleccionada en el cortafuegos |
| `ESC` | Cancelar / Cerrar | Cierra diálogos, modales o barra de búsqueda activa |
| `q` | Salir | Cierra la aplicación y detiene todos sus subprocesos de forma segura |

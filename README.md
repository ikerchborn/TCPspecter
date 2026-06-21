# TCPspecter

**TCPspecter** es una herramienta TUI (Terminal User Interface) interactiva y de alto rendimiento escrita en Python 3.11+ para sistemas GNU/Linux (como Debian, Ubuntu o Parrot Security OS). Está inspirada directamente en el clásico **TCPView de Sysinternals para Windows**, ofreciendo visualización y monitoreo en tiempo real de los procesos activos del sistema, sus conexiones de red asociadas, resolución DNS inversa bajo demanda y un motor avanzado de inspección local y remota (integrando la API de VirusTotal) para auditorías de seguridad rápidas desde la terminal.

---

## Arquitectura y Visión del Proyecto: Plataforma de Network Security Analytics

El objetivo principal de **TCPspecter** no es ser simplemente otro "sniffer" de red que arroja logs indescifrables. El proyecto evoluciona hacia una plataforma defensiva que combina capacidades de **DLP (Data Loss Prevention)**, **NDR (Network Detection and Response)** y **NTA (Network Traffic Analysis)** con una interfaz optimizada. El propósito es responder continuamente a preguntas clave: *¿Qué está pasando? ¿Por qué ocurre? ¿Es normal? ¿Qué riesgo tiene? ¿Qué debería hacer el administrador?*

En otras palabras, la filosofía central es:
`Capturar → Clasificar → Correlacionar → Explicar → Priorizar`

### La Arquitectura General (Motores)

```text
                +------------------------+
                | Captura de tráfico     |
                | AF_PACKET/libpcap      |
                +-----------+------------+
                            |
          +-----------------+-----------------+
          |                                   |
      Flow Engine                     Packet Engine
          |                                   |
          +-----------------+-----------------+
                            |
                     Correlation Engine
                            |
          +-----------------+----------------+
          |                                  |
      DLP Engine                      NDR Engine
          |                                  |
          +-----------------+----------------+
                            |
                    Risk Scoring Engine
                            |
                    Explanation Engine
                            |
                       Linux TUI
```

### Módulo 1 — Network Traffic Analysis (NTA)
El objetivo es **entender el tráfico**, analizando métricas de flujos (Flows) en lugar de almacenar paquetes completos. Se extraen metadatos cruciales como: Origen, Destino, Puertos, Protocolo, Bytes (enviados/recibidos), Duración, RTT, TTL, y Entropía. 
Esto permite perfilar el ancho de banda, frecuencias y persistencia de las conexiones reduciendo dramáticamente el consumo de recursos.

### Módulo 2 — DLP (Data Loss Prevention)
Enfocado en el **contenido** (no en el flujo). El sistema es capaz de realizar reconstrucción de archivos, detección MIME y revisión de **Magic Bytes** y **Entropía**. Esto ayuda a identificar clasificaciones inteligentes como documentos cifrados, bases de datos, backups SQL, llaves SSH o tokens exfiltrados de la red.

### Módulo 3 — NDR (Network Detection and Response)
Observa **comportamientos**, no solo paquetes. Detecta anomalías basadas en patrones habituales (ej. un empleado enviando 45 GB a un destino nunca antes visto a las 03:00 AM). Emite un *Exfiltration Score* sumando puntajes por el tamaño del archivo, uso de VPN/Tor, y horarios extraños.

### Correlation Engine & Explanation Engine
El diferenciador de TCPspecter es su capacidad para correlacionar eventos y explicarlos en lenguaje claro humano. En lugar de emitir una críptica `Alert 584: TCP 443 Entropy 7.3`, el sistema construye una narrativa:

> *"Se detectó una transferencia grande. El equipo nunca había enviado tantos datos a este destino desconocido. El archivo fue identificado como un respaldo SQL cifrado. La transferencia ocurrió a las 03:15 AM. Nivel de riesgo: Alto."*

El **Explanation Engine** contextualiza cada variable (como JA3, Entropía o ASN) brindando un modo educativo, convirtiendo al proyecto no solo en una herramienta de monitoreo, sino en un entorno de aprendizaje continuo para analistas.

---

## Características Principales

*   **Monitoreo en Tiempo Real**: Frecuencia de actualización dinámica del sistema, procesos y sockets activos.
*   **Visualización de Tráfico**: Dashboard superior que muestra el consumo acumulado de CPU (%) y RAM (%) en barras de progreso ASCII, junto con la velocidad de red en Mbps (RX/TX).
*   **Gráficos de Torta ASCII (Pie Charts)**: Gráficos de sectores circulares calculados matemáticamente que muestran la distribución de protocolos de red (TCP vs UDP vs LISTEN) y los procesos principales que consumen CPU.

*   **Filtros Interactivos**: Barra de búsqueda interactiva instantánea activada con `/` para buscar por IP, puerto, PID o nombre de proceso.
*   **Gestión de Conexiones Reactiva**: Selección de procesos en la tabla de la izquierda que actualiza instantáneamente para listar únicamente los sockets que pertenecen a ese PID.
*   **Transición Visual**: Resaltado temporal en azul (`#4A7A9D`) para nuevas conexiones y atenuación en gris (`#888888`) antes de su eliminación para una depuración dinámica de los flujos de red.
*   **Doble Modo de Inspección**:
    *   **Análisis Local (`a`)**: Obtiene de forma instantánea y offline la ruta absoluta, tamaño de archivo, propietario, permisos, detección de bit SUID de riesgo y el hash SHA-256 (calculado en bloques optimizados de 8KB).
    *   **Análisis VirusTotal (`v`)**: Ejecuta el análisis local y consulta de forma asíncrona la reputación del hash en la API de VirusTotal.
*    **Detección de Máquina Zombie / C2 (`z`)**: Evalúa de manera heurística las conexiones de red y procesos activos para alertar si la máquina está actuando como nodo zombie (C2). Analiza patrones de conexión externa masiva, uso de puertos clásicos de botnets/minería/RATs, ejecutables iniciados desde directorios volátiles (`/tmp`, `/dev/shm`), procesos que corren desde binarios que fueron eliminados de disco, firmas de reverse shell en argumentos y ejecutables con privilegios SUID en red.
*   **Resolución DNS Toggle (`d`)**: Resuelve direcciones IP a hostnames/dominios en un hilo secundario sin congelar o interrumpir la interfaz gráfica.
*   **Exportación de Reportes (`e`)**: Genera instantáneas en formatos CSV y JSON sobre el estado actual de los procesos, conexiones y auditorías.

---

## Requisitos Previos

*   Python 3.11+
*   Soporte de terminal mínimo de 80x24 caracteres
*   Paquete `python3-venv` instalado en el sistema

---

## Instalación en Debian y Derivados

Sigue estos pasos para clonar o copiar el proyecto y correrlo mediante el script automatizado:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip

# Entrar al directorio
cd tcpspecter

# Dar permisos de ejecucion y lanzar
chmod +x run.sh
./run.sh
```

El script `run.sh` se encargará de:
1. Crear el entorno virtual `venv` si no existe.
2. Instalar todas las dependencias en `requirements.txt` automáticamente.
3. Verificar si tienes privilegios elevados y ofrecerte iniciar automáticamente con `sudo` para un monitoreo completo.

---

## Ejecución y Privilegios Elevados (sudo/root)

La aplicación requiere privilegios de superusuario (`sudo`) para varias funciones críticas:
1.  **Sockets de otros usuarios**: Sin `sudo`, solo verás las conexiones de red de los procesos pertenecientes a tu propio usuario de terminal. Los procesos y sockets de red del sistema (como `systemd`, servidores web locales, etc.) no serán visibles.
2.  **Terminar Procesos (`x`)**: No podrás realizar `kill` en procesos de otros usuarios.
3.  **Inspección local (`a` / `v`)**: Sudo es necesario para leer ejecutables del sistema ubicados en directorios protegidos.

Por ello, el script `run.sh` te preguntará si deseas elevar la ejecución:
```bash
./run.sh
```
Si respondes **Sí (S/enter)**, solicitará tu contraseña de sudo e iniciará la aplicación con privilegios completos. Si respondes **No (n)**, la aplicación se ejecutará en modo usuario limitado.

---

## Filosofía de Mitigación y Whitelisting (DLP + NDR + NTA)

Para garantizar un monitoreo seguro y sin interrupciones accidentales en entornos reales, TCPspecter adopta un modelo de **Detección Pasiva con Respuesta Asistida**:

1. **Detección Pasiva sin Bloqueo Autónomo**:
   * Los motores de análisis (DLP/NDR/NTA) detectan amenazas en tiempo real pero **no bloquean conexiones ni terminan procesos automáticamente**. Esto evita la caída accidental de servicios legítimos del sistema (falsos positivos).
2. **Mitigación y Respuesta Manual**:
   * **Terminar Proceso (`x`)**: Si identificas un PID malicioso, puedes presionar `x` en la TUI para forzar su terminación (`kill -9`) con confirmación segura.
   * **Recomendaciones de Mitigación**: El panel de explicaciones de cada conexión te proporciona los comandos exactos para mitigar la amenaza manualmente (por ejemplo, cómo configurar `iptables` o `ufw` para bloquear las IPs atacantes o cómo desactivar servicios de persistencia).
3. **Lista de Confianza de Procesos (Whitelisting)**:
   * Para evitar ruidos y falsas alarmas, el motor NDR excluye automáticamente a los navegadores web comunes y clientes de red legítimos (como `firefox`, `chrome`, `brave`, `slack`, `discord`, `vscode`, etc.) del análisis de *"Conexiones Masivas"*. Esto permite centrar los reportes y las alertas de DDoS/escaneo únicamente en binarios y scripts desconocidos o no autorizados.

---

## Configuración de VirusTotal (API Key)

1.  Crea una cuenta gratuita en [virustotal.com](https://www.virustotal.com/).
2.  Inicia sesión y dirígete a tu perfil en la sección **API Key**. Copia tu clave pública.
3.  Copia la plantilla de configuración provista en el repositorio:
    ```bash
    cp config.json.template config.json
    ```
4.  Pega tu clave en `config.json` respetando la siguiente estructura exacta:

```json
{
  "virustotal_api_key": "TU_API_KEY_AQUI"
}
```

*Nota: Si no posees una clave de VirusTotal o el archivo `config.json` está vacío/ausente, el programa omitirá las llamadas web, pero seguirá ofreciendo de manera normal y completa la funcionalidad de inspección local nativa (`a`) y el análisis de comportamiento zombie (`z`).*

### Límite de la API Gratuita
La API gratuita de VirusTotal está limitada a **4 solicitudes por minuto**. Si excedes este límite en la TUI, se capturará el error de forma segura mostrando un mensaje indicando que el límite de tasa de solicitudes ha sido excedido (`HTTP 429`), sin congelar o tumbar la aplicación.

---

## Mapeo Completo de Teclas (Keybindings)

| Tecla | Acción | Descripción |
| :--- | :--- | :--- |
| `↑` / `k` | Cursor Arriba | Desplazar selección en la tabla activa |
| `↓` / `j` | Cursor Abajo | Desplazar selección en la tabla activa |
| `TAB` / `Shift+TAB` | Cambiar Panel | Alterna el foco entre la tabla de procesos y de conexiones |
| `ENTER` | Ver Conexiones | Enfoca y vincula conexiones al proceso seleccionado |
| `a` | Analizar (Local) | Ejecuta análisis offline del binario (SUID, hashes, permisos) |
| `v` | Analizar (VirusTotal) | Inspección local y consulta de reputación online en VirusTotal |
| `x` | Terminar Proceso | Solicita doble confirmación para terminar el proceso (Kill PID) |
| `d` | Resolver DNS | Activa/Desactiva resolución DNS inversa en segundo plano |
| `/` | Filtrar | Despliega u oculta la barra de búsqueda en tiempo real |
| `p` | Filtro Protocolo | Cicla los sockets mostrados: `ALL` → `TCP` → `UDP` → `LISTEN` |
| `s` | Ordenar Columna | Cicla el criterio de ordenación de la tabla de procesos |
| `e` | Exportar Reporte | Guarda instantáneas en CSV o JSON |
| `z` | Analizar Zombie | Auditoría heurística para detectar si la máquina actúa como zombie/C2 |
| `ESC` | Cancelar | Cierra diálogos de confirmación o barra de filtros |
| `q` | Salir | Cierra la aplicación de manera segura |

---

## Limitaciones Conocidas y Uso Responsable

*   **Uso de Red (DNS)**: La resolución DNS inversa realiza consultas externas que podrían ser registradas por servidores DNS externos. Si deseas máxima privacidad, mantén la resolución DNS desactivada (`d`).
*   **Auditoría y Monitoreo**: Esta aplicación está diseñada estrictamente para fines de diagnóstico, administración de sistemas y auditoría autorizada. Asegúrate de contar con el permiso explícito antes de inspeccionar o interactuar con procesos en entornos compartidos.

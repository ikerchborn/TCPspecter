import os
import psutil
from textual.screen import ModalScreen
from textual.widgets import Static, Input
from textual.containers import Vertical
from textual import work
from rich.text import Text

from core.executable_analysis import get_process_exe_path, analyze_executable
from core.virustotal_client import check_hash_vt


class BaseAsciiModal(ModalScreen):
    """
    Base dialog modal with standard ASCII formatting style boundaries.
    """
    def compose(self):
        raise NotImplementedError

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(None)


class ConfirmKillModal(BaseAsciiModal):
    """
    Double confirmation ASCII modal to terminate a process.
    """
    def __init__(self, pid: int, name: str):
        super().__init__()
        self.pid = pid
        self.proc_name = name

    def compose(self):
        body_text = (
            "+-----------------------------------------------------+\n"
            "|                CONFIRMAR TERMINACION                |\n"
            "+-----------------------------------------------------+\n"
            f" ¿Seguro que deseas terminar PID [{self.pid}] ({self.proc_name})?\n"
            " Esta accion no se puede deshacer.\n"
            "\n"
            " [ ENTER = Si, ESC = Cancelar ]\n"
            "+-----------------------------------------------------+"
        )
        yield Vertical(
            Static(body_text, id="confirm_kill_label"),
            id="modal_dialog"
        )

    def on_key(self, event) -> None:
        if event.key == "enter":
            try:
                proc = psutil.Process(self.pid)
                proc.kill()
                self.dismiss(True)
            except psutil.AccessDenied:
                # BUG #9 FIX: psutil.AccessDenied requires pid/name args in 5.9.x
                self.dismiss(psutil.AccessDenied(pid=self.pid, name=""))
            except psutil.NoSuchProcess:
                self.dismiss(psutil.NoSuchProcess(pid=self.pid, name=""))
            except Exception as e:
                self.dismiss(e)
        elif event.key == "escape":
            self.dismiss(False)


class LocalAnalysisModal(BaseAsciiModal):
    """
    ASCII modal showing local analysis details for confirmation.
    """
    def __init__(self, pid: int, name: str):
        super().__init__()
        self.pid = pid
        self.proc_name = name
        self._exe_path = None

    def compose(self):
        yield Vertical(
            Static("Cargando detalles de binario...", id="local_analysis_body"),
            id="modal_dialog_wide"
        )

    def on_mount(self) -> None:
        try:
            exe_path = get_process_exe_path(self.pid)
            self._exe_path = exe_path
            body = (
                "+-----------------------------------------------------+\n"
                "|             ANALISIS BINARIO LOCAL                  |\n"
                "+-----------------------------------------------------+\n"
                f" PID: {self.pid}\n"
                f" Proceso: {self.proc_name}\n"
                f" Ruta: {exe_path}\n"
                "\n"
                " ¿Proceder con analisis LOCAL de esta ruta?\n"
                " (ENTER = Si, ESC = Cancelar)\n"
                "+-----------------------------------------------------+"
            )
            self.query_one("#local_analysis_body", Static).update(body)
        except Exception as e:
            body = (
                "+-----------------------------------------------------+\n"
                "|             ANALISIS BINARIO LOCAL                  |\n"
                "+-----------------------------------------------------+\n"
                f" Error al acceder al binario del PID {self.pid}:\n"
                f" {str(e)}\n"
                "\n"
                " (ESC = Cerrar)\n"
                "+-----------------------------------------------------+"
            )
            self.query_one("#local_analysis_body", Static).update(body)

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(None)
        elif event.key == "enter":
            if self._exe_path is None:
                return
            try:
                results = analyze_executable(self._exe_path)
                self.show_results(results)
            except Exception as e:
                body = (
                    "+-----------------------------------------------------+\n"
                    "|             ERROR DE ANALISIS                       |\n"
                    "+-----------------------------------------------------+\n"
                    f" {str(e)}\n"
                    "\n"
                    " (ESC = Cerrar)\n"
                    "+-----------------------------------------------------+"
                )
                self.query_one("#local_analysis_body", Static).update(body)

    def show_results(self, results):
        suid_label = "SÍ (¡ADVERTENCIA!)" if results["is_suid"] else "NO"
        body = (
            "+----------------------------------------------------------------------+\n"
            "|                   RESULTADOS: ANALISIS LOCAL                         |\n"
            "+----------------------------------------------------------------------+\n"
            f" Ruta:         {results['path']}\n"
            f" Tamanio:      {results['size']} bytes\n"
            f" Propietario:  {results['owner']}\n"
            f" Permisos:     {results['permissions']}\n"
            f" SUID bit:     {suid_label}\n"
            f" SHA-256:      {results['sha256']}\n"
            "+----------------------------------------------------------------------+\n"
            " [ ESC = Cerrar ]"
        )
        self.query_one("#local_analysis_body", Static).update(body)


class VirusTotalAnalysisModal(BaseAsciiModal):
    """
    ASCII modal querying VT API and presenting results/loading.
    """
    def __init__(self, pid: int, name: str):
        super().__init__()
        self.pid = pid
        self.proc_name = name
        self._exe_path = None

    def compose(self):
        yield Vertical(
            Static("Cargando detalles de binario...", id="vt_analysis_body"),
            id="modal_dialog_wide"
        )

    def on_mount(self) -> None:
        try:
            exe_path = get_process_exe_path(self.pid)
            self._exe_path = exe_path
            body = (
                "+-----------------------------------------------------+\n"
                "|          ANALISIS BINARIO + VIRUSTOTAL              |\n"
                "+-----------------------------------------------------+\n"
                f" PID: {self.pid}\n"
                f" Proceso: {self.proc_name}\n"
                f" Ruta: {exe_path}\n"
                "\n"
                " ¿Proceder con analisis LOCAL + VIRUSTOTAL?\n"
                " (ENTER = Si, ESC = Cancelar)\n"
                "+-----------------------------------------------------+"
            )
            self.query_one("#vt_analysis_body", Static).update(body)
        except Exception as e:
            body = (
                "+-----------------------------------------------------+\n"
                "|          ANALISIS BINARIO + VIRUSTOTAL              |\n"
                "+-----------------------------------------------------+\n"
                f" Error al acceder al binario del PID {self.pid}:\n"
                f" {str(e)}\n"
                "\n"
                " (ESC = Cerrar)\n"
                "+-----------------------------------------------------+"
            )
            self.query_one("#vt_analysis_body", Static).update(body)

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(None)
        elif event.key == "enter":
            if self._exe_path is None:
                return
            try:
                results = analyze_executable(self._exe_path)
                self.query_one("#vt_analysis_body", Static).update(
                    "+-----------------------------------------------------+\n"
                    "|             VIRUSTOTAL: CONSULTANDO API             |\n"
                    "+-----------------------------------------------------+\n"
                    " Consultando hash en VirusTotal...\n"
                    " Por favor, espere.\n"
                    "+-----------------------------------------------------+"
                )
                self.run_vt_lookup(results)
            except Exception as e:
                self.query_one("#vt_analysis_body", Static).update(
                    f"+-----------------------------------------------------+\n"
                    f"|             ERROR DE ANALISIS                       |\n"
                    f"+-----------------------------------------------------+\n"
                    f" {str(e)}\n"
                    f"\n"
                    f" (ESC = Cerrar)\n"
                    f"+-----------------------------------------------------+"
                )

    @work(exclusive=True)
    async def run_vt_lookup(self, local_results: dict):
        try:
            h = local_results["sha256"]
            vt_res = await check_hash_vt(h)
            # In an async worker we are on the event loop — call directly
            self.show_combined_results(local_results, vt_res)
        except Exception as e:
            self.show_combined_results(local_results, {
                "status": "error",
                "message": f"Fallo al conectar con VirusTotal: {str(e)}"
            })

    def show_combined_results(self, local_results, vt_res):
        suid_label = "SÍ (¡ADVERTENCIA!)" if local_results["is_suid"] else "NO"

        vt_status = vt_res.get("status")
        if vt_status == "success":
            malicious_count = vt_res.get("malicious", 0)
            if malicious_count > 3:
                vt_info = f"PELIGROSO ({vt_res.get('detections')})"
            elif malicious_count > 0:
                vt_info = f"SOSPECHOSO ({vt_res.get('detections')})"
            else:
                vt_info = f"LIMPIO ({vt_res.get('detections')})"
        elif vt_status == "missing_key":
            vt_info = "Sin API Key en config.json (Solo datos locales)"
        elif vt_status == "not_found":
            vt_info = "Hash no encontrado en VirusTotal (Sin veredicto)"
        else:
            vt_info = f"Error: {vt_res.get('message', 'Desconocido')}"

        body = (
            "+----------------------------------------------------------------------+\n"
            "|               RESULTADOS: ANALISIS LOCAL + VIRUSTOTAL                |\n"
            "+----------------------------------------------------------------------+\n"
            f" Ruta:         {local_results['path']}\n"
            f" Tamanio:      {local_results['size']} bytes\n"
            f" Propietario:  {local_results['owner']}\n"
            f" Permisos:     {local_results['permissions']}\n"
            f" SUID bit:     {suid_label}\n"
            f" SHA-256:      {local_results['sha256']}\n"
            "+----------------------------------------------------------------------+\n"
            "|                        ESTADO VIRUSTOTAL                             |\n"
            "+----------------------------------------------------------------------+\n"
            f" Resultado:    {vt_info}\n"
            "+----------------------------------------------------------------------+\n"
            " [ ESC = Cerrar ]"
        )
        self.query_one("#vt_analysis_body", Static).update(body)


class ExportReportModal(BaseAsciiModal):
    """
    Modal to request export target and format.
    """
    def compose(self):
        body_text = (
            "+-----------------------------------------------------+\n"
            "|                  EXPORTAR REPORTE                   |\n"
            "+-----------------------------------------------------+\n"
            " Ingrese la ruta de destino:\n"
            " (.json = JSON, .csv = CSV)\n"
            "+-----------------------------------------------------+"
        )
        yield Vertical(
            Static(body_text),
            Input(
                value="reporte.json",
                placeholder="Ruta del archivo (e.g. reporte.json o reporte.csv)",
                id="export_path_input"
            ),
            Static(" [ ENTER = Confirmar, ESC = Cancelar ]"),
            id="modal_dialog"
        )

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(None)
        elif event.key == "enter":
            path = self.query_one("#export_path_input", Input).value.strip()
            fmt = "CSV" if path.lower().endswith(".csv") else "JSON"
            self.dismiss((path, fmt))


class ZombieAnalysisModal(BaseAsciiModal):
    """
    ASCII modal that scans the system for Zombie/C2 behavior and displays the report.
    """
    def compose(self):
        yield Vertical(
            Static("Iniciando análisis...", id="zombie_analysis_body"),
            id="zombie_dialog"
        )

    def on_mount(self) -> None:
        self.run_analysis()

    @work(exclusive=True)
    async def run_analysis(self):
        self.query_one("#zombie_analysis_body", Static).update(
            "+-----------------------------------------------------+\n"
            "|         ANALIZANDO COMPORTAMIENTO ZOMBIE            |\n"
            "|               (ESCANEO EN CURSO...)                 |\n"
            "+-----------------------------------------------------+\n"
            " Analizando conexiones y comportamiento de procesos...\n"
            " Por favor, espere.\n"
            "+-----------------------------------------------------+"
        )
        from core.zombie_detector import analyze_zombie_status
        import asyncio
        loop = asyncio.get_running_loop()
        # Run CPU-bound/blocking psutil logic in executor
        report = await loop.run_in_executor(None, analyze_zombie_status)
        self.show_report(report)

    def show_report(self, report):
        level = report["risk_level"]
        if level == "CRÍTICO":
            level_styled = "[bold red]CRÍTICO[/]"
        elif level == "ALTO":
            level_styled = "[bold yellow]ALTO[/]"
        elif level == "MEDIO":
            level_styled = "[bold #4A7A9D]MEDIO[/]"
        else:
            level_styled = "[bold green]BAJO[/]"

        score = report["score"]
        findings_lines = []
        risk_procs = []
        if not report["findings"]:
            findings_lines.append("  [green]✓ No se encontraron comportamientos anómalos o de C2.[/]")
        else:
            for f in report["findings"]:
                sev = f["severity"]
                desc = f["description"]
                pid_str = f"PID {f['pid']}" if f["pid"] is not None else "-"
                name_str = f"({f['proc_name']})" if f["proc_name"] else ""
                
                if sev in ("CRITICAL", "HIGH", "MEDIUM") and f["proc_name"]:
                    risk_procs.append(f"{f['proc_name']} (PID: {f['pid']})")
                
                if sev == "CRITICAL":
                    sev_styled = "[bold red]\\[CRITICO\\][/]"
                elif sev == "HIGH":
                    sev_styled = "[bold yellow]\\[ALTO\\][/]"
                elif sev == "MEDIUM":
                    sev_styled = "[bold #4A7A9D]\\[MEDIO\\][/]"
                elif sev == "WARNING":
                    sev_styled = "[bold gray]\\[ALERTA\\][/]"
                else:
                    sev_styled = f"[bold gray]\\[{sev}\\][/]"
                    
                findings_lines.append(f"  • {sev_styled} {pid_str} {name_str}: {desc}")

        unique_risk_procs = list(dict.fromkeys(risk_procs))
        risk_procs_str = ", ".join(unique_risk_procs) if unique_risk_procs else "Ninguno"
        findings_text = "\n".join(findings_lines)

        body = (
            "+----------------------------------------------------------------------+\n"
            "|                  ANALISIS DE SEGURIDAD: ZOMBIE / C2                  |\n"
            "+----------------------------------------------------------------------+\n"
            f" Nivel de Riesgo:       {level_styled} (Puntuación: {score}/100)\n"
            f" Proceso(s) de Riesgo:  [bold yellow]{risk_procs_str}[/]\n"
            f" Procesos Escaneados:   {report['scanned_processes']}\n"
            f" Conexiones Analizadas: {report['scanned_connections']}\n"
            "+----------------------------------------------------------------------+\n"
            " DETALLE DE LA PUNTUACIÓN Y FÓRMULA DE RIESGO:\n"
            "  • Hallazgo CRÍTICO = +40 pts (ej. Reverse Shell, binario borrado, puerto C2)\n"
            "  • Hallazgo ALTO     = +25 pts (ej. ejecución en /tmp, SUID con red, masivo)\n"
            "  • Hallazgo MEDIO    = +10 pts (ej. escucha abierta en interfaces externas)\n"
            "  • Advertencia/Bajo  = +5 pts\n"
            "  • La puntuación final se acota a un máximo de 100.\n"
            "+----------------------------------------------------------------------+\n"
            " HALLAZGOS Y DETECCIONES:\n"
            f"{findings_text}\n"
            "+----------------------------------------------------------------------+\n"
            " [ ESC = Cerrar | R = Volver a escanear ]"
        )
        self.query_one("#zombie_analysis_body", Static).update(body)

    def on_key(self, event) -> None:
        super().on_key(event)
        if event.key == "r":
            self.run_analysis()


class InterpretationModal(BaseAsciiModal):
    """
    ASCII modal that translates raw network metrics into human-readable details.
    """
    def __init__(self, conn_data: dict | None, proc_data: dict | None):
        super().__init__()
        self.conn_data = conn_data
        self.proc_data = proc_data

    def compose(self):
        yield Vertical(
            Static("Generando interpretación...", id="interpretation_body"),
            id="modal_dialog_wide"
        )

    def on_mount(self) -> None:
        from core.interpreter import interpret_connection
        
        # If we have a selected connection, interpret it.
        if self.conn_data:
            c = self.conn_data
            interp = interpret_connection(c)
            
            assessment_str = interp["assessment"]
            if "CRÍTICO" in assessment_str:
                eval_styled = f"[bold red]{assessment_str}[/]"
            elif "REVISAR" in assessment_str:
                eval_styled = f"[bold yellow]{assessment_str}[/]"
            else:
                eval_styled = f"[bold green]{assessment_str}[/]"
                
            body = (
                "+----------------------------------------------------------------------+\n"
                "|               TRADUCTOR E INTERPRETADOR DE RED (TUI)                 |\n"
                "+----------------------------------------------------------------------+\n"
                f" Proceso:       [bold]{c.get('name', '-')}[/] (PID: {c.get('pid', '-')})\n"
                f" Conexión:      {c['proto']} | {c['laddr_ip']}:{c['laddr_port']} -> {c['raddr_ip']}:{c['raddr_port']}\n"
                f" Estado actual: {c['status']}\n"
                "+----------------------------------------------------------------------+\n"
                f" EVALUACIÓN:    {eval_styled}\n"
                "+----------------------------------------------------------------------+\n"
                f" 1. ÁMBITO DE LA IP:\n"
                f"    {interp['ip_desc']}\n\n"
                f" 2. PROPÓSITO DEL PUERTO:\n"
                f"    {interp['port_desc']}\n\n"
                f" 3. EXPLICACIÓN DEL ESTADO:\n"
                f"    {interp['status_desc']}\n\n"
                f" 4. ANÁLISIS DE SEGURIDAD:\n"
                f"    {interp['explanation']}\n"
                "+----------------------------------------------------------------------+\n"
                " [ ESC = Cerrar ]"
            )
        elif self.proc_data:
            p = self.proc_data
            body = (
                "+----------------------------------------------------------------------+\n"
                "|               INTERPRETACIÓN DE PROCESO SELECCIONADO                 |\n"
                "+----------------------------------------------------------------------+\n"
                f" Nombre:      [bold]{p['name']}[/]\n"
                f" PID:         {p['pid']}\n"
                f" Usuario:     {p['user']}\n"
                f" CPU/Memoria: CPU: {p['cpu']}% | RAM: {p['ram']}%\n"
                f" Estado:      {p['status']}\n"
                "+----------------------------------------------------------------------+\n"
                " GUÍA DE INTERPRETACIÓN GENERAL:\n"
                "  • Un proceso legítimo con CPU alta (ej. navegadores) es normal.\n"
                "  • Procesos extraños con CPU muy baja o constante que tienen sockets\n"
                "    abiertos son candidatos a revisión de virus (presione 'v').\n"
                "  • Compara si el binario del proceso ha sido eliminado o corre desde /tmp.\n"
                "+----------------------------------------------------------------------+\n"
                " [ ESC = Cerrar ]"
            )
        else:
            # General Guide
            body = (
                "+----------------------------------------------------------------------+\n"
                "|                  GUÍA GENERAL: ¿CÓMO ENTENDER LA RED?                |\n"
                "+----------------------------------------------------------------------+\n"
                " ¿Qué significan los estados de conexión?\n"
                "  • ESTABLISHED: Conectado activamente. Se transmiten datos ahora mismo.\n"
                "  • LISTEN: Tu máquina espera conexiones entrantes (como un servidor web).\n"
                "  • CLOSE_WAIT / TIME_WAIT: Conexiones en proceso de cierre limpio.\n"
                "\n"
                " ¿Cómo identificar conexiones sospechosas?\n"
                "  • Conexiones a IPs públicas (externas) desde scripts (python, sh) o\n"
                "    herramientas de comandos (nc, bash) son sospechosas de Reverse Shell.\n"
                "  • Puertos no comunes (como 4444, 5555, o puertos altos aleatorios)\n"
                "    que se mantengan en ESTABLISHED hacia IPs de internet deben investigarse.\n"
                "  • Usa 'z' para realizar un escaneo completo de C2 en el sistema.\n"
                "+----------------------------------------------------------------------+\n"
                " [ ESC = Cerrar ]"
            )
            
        self.query_one("#interpretation_body", Static).update(body)


class TuiGraphicsModal(BaseAsciiModal):
    """
    Modal presenting advanced TUI-based ASCII charts.
    Does not require a browser to operate.
    """
    def __init__(self, rx_history: list, tx_history: list, proto_dist: list, top_procs: list, security_score: int, security_level: str):
        super().__init__()
        self.rx_history = rx_history
        self.tx_history = tx_history
        self.proto_dist = proto_dist
        self.top_procs = top_procs
        self.security_score = security_score
        self.security_level = security_level

    def compose(self):
        yield Vertical(
            Static("Cargando gráficos TUI...", id="tui_graphics_body"),
            id="modal_dialog_wide"
        )

    def on_mount(self) -> None:
        self.render_charts()

    def render_charts(self):
        # 1. Bandwidth line charts
        rx_chart = draw_ascii_sparkline(self.rx_history, width=50, height=4, color="#34d399")
        tx_chart = draw_ascii_sparkline(self.tx_history, width=50, height=4, color="#4a7a9d")
        
        # 2. Sockets horizontal bar charts
        total_sockets = sum(v for l, v in self.proto_dist if l != "NO_ROOT") or 1
        socket_lines = []
        colors = {"TCP": "#4A7A9D", "UDP": "#F2E8C9", "LISTEN": "#888888"}
        for label, val in self.proto_dist:
            if label == "NO_ROOT":
                continue
            pct = (val / total_sockets) * 100.0
            bar_len = int(pct / 5) # 20 blocks max
            bar = f"[{colors.get(label, '#888888')}]" + "█" * bar_len + "░" * (20 - bar_len) + "[/]"
            socket_lines.append(f"  {label:<6} : {bar} {pct:5.1f}% ({val})")
        sockets_chart = "\n".join(socket_lines)

        # 3. Top CPU processes
        proc_lines = []
        for name, cpu in self.top_procs:
            bar_len = int(min(100, cpu) / 5) # 20 blocks max
            bar = "[#4A7A9D]" + "█" * bar_len + "░" * (20 - bar_len) + "[/]"
            proc_lines.append(f"  {name[:10]:<10} : {bar} {cpu:5.1f}%")
        if not proc_lines:
            proc_lines.append("  [No hay procesos con consumo medible]")
        proc_chart = "\n".join(proc_lines)

        # 4. Security Score Gauge
        risk_color = "#34d399"
        if self.security_score >= 60:
            risk_color = "#ef4444"
        elif self.security_score >= 35:
            risk_color = "#fbbf24"
        elif self.security_score >= 15:
            risk_color = "#4a7a9d"
            
        gauge_len = int(self.security_score / 5) # 20 blocks max
        security_gauge = f"[{risk_color}]" + "█" * gauge_len + "░" * (20 - gauge_len) + f"[/] {self.security_score}/100 ([bold {risk_color}]{self.security_level}[/])"

        body = (
            "+----------------------------------------------------------------------+\n"
            "|                     PANELES Y GRÁFICOS TUI (ASCII)                   |\n"
            "+----------------------------------------------------------------------+\n"
            " ESTADO DE RIESGO DE SEGURIDAD (C2 / Máquina Zombie):\n"
            f"  Riesgo: {security_gauge}\n"
            "+----------------------------------------------------------------------+\n"
            " HISTORIAL DE TRÁFICO DE RED (BAJADA - RX):\n"
            f"{rx_chart}\n\n"
            " HISTORIAL DE TRÁFICO DE RED (SUBIDA - TX):\n"
            f"{tx_chart}\n"
            "+----------------------------------------------------------------------+\n"
            " DISTRIBUCIÓN DE PROTOCOLOS DE RED:\n"
            f"{sockets_chart}\n"
            "+----------------------------------------------------------------------+\n"
            " TOP CONSUMO CPU POR PROCESO:\n"
            f"{proc_chart}\n"
            "+----------------------------------------------------------------------+\n"
            " [ ESC = Cerrar ]"
        )
        self.query_one("#tui_graphics_body", Static).update(body)


def draw_ascii_sparkline(history, width=50, height=4, color="#34d399") -> str:
    if not history:
        return "  [No hay datos suficientes aún. Espera un par de ticks...]"
        
    max_val = max(history) if max(history) > 0 else 1.0
    min_val = min(history)
    
    grid = [[" " for _ in range(width)] for _ in range(height)]
    
    num_vals = len(history)
    for col_idx in range(min(width, num_vals)):
        val = history[num_vals - 1 - col_idx]
        col = width - 1 - col_idx
        
        pct = val / max_val
        row = int(pct * (height - 1))
        row = max(0, min(height - 1, row))
        grid_row = height - 1 - row
        
        grid[grid_row][col] = "•"
        
    lines = []
    for r in range(height):
        row_str = "".join(grid[r])
        row_str_colored = row_str.replace("•", f"[{color}]•[/]")
        if r == 0:
            lines.append(f"  {max_val:5.2f} Mbps | {row_str_colored}")
        elif r == height - 1:
            lines.append(f"  {min_val:5.2f} Mbps | {row_str_colored}")
        else:
            lines.append(f"              | {row_str_colored}")
            
    lines.append("              +" + "-" * width + " (tiempo ->)")
    return "\n".join(lines)


class ConfirmBlockModal(BaseAsciiModal):
    """
    ASCII confirmation modal to block an IP.
    """
    def __init__(self, ip: str):
        super().__init__()
        self.ip = ip

    def compose(self):
        body_text = (
            "+-----------------------------------------------------+\n"
            "|                  BLOQUEAR DIRECCION IP              |\n"
            "+-----------------------------------------------------+\n"
            f" ¿Seguro que deseas bloquear IP [{self.ip}]?\n"
            " Se creará una regla DROP para el tráfico entrante.\n"
            "\n"
            " [ ENTER = Sí (Bloquear), ESC = Cancelar ]\n"
            "+-----------------------------------------------------+"
        )
        yield Vertical(
            Static(body_text, id="confirm_block_label"),
            id="modal_dialog"
        )

    def on_key(self, event) -> None:
        if event.key == "enter":
            from core.firewall_manager import block_ip
            success = block_ip(self.ip)
            self.dismiss(success)
        elif event.key == "escape":
            self.dismiss(None)


class FirewallModal(BaseAsciiModal):
    """
    ASCII modal displaying active firewall rules and allowing block/unblock.
    """
    def compose(self):
        yield Vertical(
            Static("", id="firewall_body"),
            Input(placeholder="Escribe la IP a bloquear/desbloquear", id="firewall_input"),
            Static(
                " [ ENTER = Bloquear IP | U = Desbloquear IP | ESC = Cerrar ]\n"
                "+----------------------------------------------------------------------+"
            ),
            id="modal_dialog_wide"
        )

    def on_mount(self) -> None:
        self.refresh_rules()

    def refresh_rules(self):
        from core.firewall_manager import detect_backend, get_blocked_ips
        backend = detect_backend()
        blocked = get_blocked_ips()
        
        backend_label = backend.upper() if backend != "none" else "DESACTIVADO/NO DISPONIBLE"
        
        body_lines = [
            "+----------------------------------------------------------------------+",
            "|                     CONTROL DE CORTAFUEGOS (FIREWALL)                |",
            "+----------------------------------------------------------------------+",
            f" Backend detectado: [bold #F2E8C9]{backend_label}[/]",
            "",
            " Direcciones IP bloqueadas actualmente:",
        ]
        
        if not blocked:
            body_lines.append("  [green]✓ Ninguna IP bloqueada actualmente.[/]")
        else:
            for idx, b in enumerate(blocked, 1):
                body_lines.append(f"  {idx}. [bold red]{b['ip']}[/] ({b['backend']} - {b['target']})")
                
        body_lines.append("")
        body_lines.append(" Ingresa una IP en el campo inferior:")
        body_lines.append("   - Presiona ENTER para BLOQUEAR")
        body_lines.append("   - Presiona 'U' o 'u' para DESBLOQUEAR")
        body_lines.append("+----------------------------------------------------------------------+")
        
        self.query_one("#firewall_body", Static).update("\n".join(body_lines))

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(None)
        elif event.key == "enter":
            ip = self.query_one("#firewall_input", Input).value.strip()
            if ip:
                from core.firewall_manager import block_ip, validate_ip
                if validate_ip(ip):
                    block_ip(ip)
                    self.query_one("#firewall_input", Input).value = ""
                    self.refresh_rules()
        elif event.key in ("u", "U"):
            ip = self.query_one("#firewall_input", Input).value.strip()
            if ip:
                from core.firewall_manager import unblock_ip, validate_ip
                if validate_ip(ip):
                    unblock_ip(ip)
                    self.query_one("#firewall_input", Input).value = ""
                    self.refresh_rules()


class ConfirmInstallSnortModal(BaseAsciiModal):
    """
    Doble confirmación para instalar Snort vía apt-get.
    """
    def compose(self):
        from core.firewall_manager import detect_backend
        fw = detect_backend()
        fw_warning = ""
        if fw != "none":
            fw_warning = (
                "|  ⚠️ ADVERTENCIA: Se ha detectado un Firewall activo   |\n"
                f"|  ({fw.upper()}) en el sistema. La instalacion puede      |\n"
                "|  interferir con la captura de paquetes.           |\n"
                "+-----------------------------------------------------+\n"
            )
        
        body_text = (
            "+-----------------------------------------------------+\n"
            "|               INSTALACION DE SNORT                  |\n"
            "+-----------------------------------------------------+\n"
            "| Se instalara Snort de forma no interactiva          |\n"
            "| (apt-get install -y snort) y se configuraran        |\n"
            "| las reglas locales de seguridad de TCPspecter.      |\n"
            "+-----------------------------------------------------+\n"
            f"{fw_warning}"
            "| ¿Seguro que deseas proceder con la instalacion?     |\n"
            "|                                                     |\n"
            "| [ ENTER = Si, ESC = Cancelar ]                      |\n"
            "+-----------------------------------------------------+"
        )
        yield Vertical(
            Static(body_text, id="confirm_install_snort_label"),
            id="modal_dialog_wide"
        )

    def on_key(self, event) -> None:
        if event.key == "enter":
            self.dismiss(True)
        elif event.key == "escape":
            self.dismiss(False)


import time
import os
import psutil
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, DataTable
from textual.containers import Vertical, Horizontal
from textual.reactive import reactive
from textual import work, on

from widgets.ascii_bar import AsciiProgressBar
from widgets.process_table import ProcessTable
from widgets.connection_table import ConnectionTable
from widgets.filter_bar import FilterBar
from widgets.pie_chart import AsciiPieChart
from widgets.c2_security import C2SecurityWidget

from core.sysinfo import (
    get_system_stats, get_network_io, get_process_list,
    get_process_connections, check_privileges,
    get_system_protocol_distribution, get_top_processes_by_resource,
    get_all_connections
)
from core.dns_resolver import dns_resolver_instance
from core.report_exporter import export_report
from screens.modals import (
    ConfirmKillModal, LocalAnalysisModal,
    VirusTotalAnalysisModal, ExportReportModal,
    ZombieAnalysisModal
)
from widgets.analytics_panels import ExplanationPanel
from core import zombie_detector
from core.web_server import PORT


class MainScreen(Screen):
    """
    TCPspecter Central Screen.
    Coordinates stats updates, filtering, connection lists, and details.
    """

    BINDINGS = [
        ("k",           "cursor_up",         "Arriba"),
        ("j",           "cursor_down",       "Abajo"),
        ("tab",         "focus_next",        "Siguiente panel"),
        ("shift+tab",   "focus_previous",    "Panel anterior"),
        ("a",           "analyze_local",     "Analizar (local)"),
        ("v",           "analyze_with_vt",   "Analizar (local + VT)"),
        ("x",           "kill_process",      "Terminar proceso"),
        ("d",           "toggle_dns",        "Resolver DNS"),
        ("slash",       "toggle_filter",     "Filtrar"),
        ("p",           "cycle_protocol",    "Filtro protocolo"),
        ("s",           "cycle_sort",        "Ordenar columna"),
        ("e",           "export_report",     "Exportar reporte"),
        ("z",           "zombie_check",      "Analizar Zombie"),
        ("c",           "clear_selection",   "Ver todas / Filtrar"),
        ("m",           "open_maps",         "Mapa Global (Browser)"),
        ("g",           "show_tui_graphics", "Gráficos (TUI)"),
        ("shift+g",     "open_graphics",     "Gráficos (Browser)"),
        ("i",           "show_interpretation", "Interpretar"),
        ("S",           "toggle_security",   "On/Off Analítica"),
        ("escape",      "dismiss_modal",     "Cancelar"),
        ("q",           "quit",              "Salir"),
    ]

    current_protocol: reactive[str] = reactive("ALL")
    selected_pid: reactive[int | None] = reactive(None)
    selected_proc_name: reactive[str] = reactive("")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # BUG #11 FIX: dns_resolved_ips was a class-level mutable dict.
        # If MainScreen is push/popped multiple times the dict would be
        # shared across instances. Moved to instance level here.
        self.dns_resolved_ips: dict = {}
        self.last_net_io: dict = {}
        self.last_net_time: float = 0.0
        self.filter_by_process: bool = False
        self.rx_history: list = []
        self.tx_history: list = []

    def compose(self):
        yield Header(show_clock=True)

        # ── TOP DASHBOARD ──────────────────────────────────────────────────
        yield Vertical(
            Horizontal(
                Vertical(
                    AsciiProgressBar("CPU", 0.0, "cpu", id="cpu_bar"),
                    AsciiProgressBar("RAM", 0.0, "ram", id="ram_bar"),
                    Static(
                        "TRAFICO RED: RX: 0.00 Mbps | TX: 0.00 Mbps",
                        id="net_sparkline"
                    ),
                    id="stats_bars"
                ),
                AsciiPieChart("Sockets Sistema", id="proto_pie"),
                AsciiPieChart("Top Procesos CPU", id="proc_pie"),
                C2SecurityWidget(id="c2_security_widget"),
                id="dashboard_row"
            ),
            id="dashboard_panel"
        )

        # ── FILTER PANEL (hidden by default) ───────────────────────────────
        yield FilterBar(id="filter_panel")

        # ── SECURITY STATUS BAR ──────────────────────────────────────
        yield Static(
            "[#34d399]●[/] ANALÍTICA DE SEGURIDAD: [bold #34d399]ACTIVA[/]   "
            "[#888888]S=Activar/Desactivar  z=Análisis Zombie  a=Analizar  v=VT  x=Kill  s=Ordenar  /=Buscar  d=DNS[/]",
            id="security_status_bar",
            classes="sec-on"
        )

        # ── UNIFIED CONNECTIONS TABLE (full width, includes process info) ───
        yield Horizontal(
            # Hidden process table - kept for internal use (selection state, kill, analyze)
            Vertical(
                ProcessTable(id="process_table"),
                id="process_pane"
            ),
            # The main unified connection view
            Vertical(
                Static(
                    "[bold]CONEXIONES ACTIVAS DEL SISTEMA  "
                    "[#888888]c=Filtrar por proc  d=DNS  p=Protocolo[/][/]",
                    classes="panel_title",
                    id="connection_title"
                ),
                ConnectionTable(id="connection_table"),
                id="connection_pane"
            ),
            id="central_grids"
        )

        # ── EXPLANATION ENGINE PANEL ────────────────────────────────
        yield ExplanationPanel(id="explanation_panel")
        
        yield Static(
            "Detalles del proceso: Ninguno seleccionado. | DNS: APAGADO",
            id="details_drawer"
        )

        yield Footer()

    # ──────────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────────────────────────────────

    def on_mount(self) -> None:
        self.last_net_io = get_network_io()
        self.last_net_time = time.time()
        # No need to set visible=False as display: none is defined in CSS

        if not check_privileges():
            self.notify(
                "[!] Sin privilegios root (sudo). "
                "Algunos procesos/conexiones no son visibles.",
                severity="warning",
                timeout=6.0
            )

        # Warm up psutil cpu_percent counters (BUG #2 mitigation)
        get_process_list()

        # Populate tables immediately on startup
        self.update_tick()

        # Tick every 1.5 seconds
        self.set_interval(1.5, self.update_tick)
        self.update_details_drawer()

        # Start background web server for graphical dashboards
        try:
            from core.web_server import start_web_server
            start_web_server(port=PORT)
        except Exception:
            pass

        # Focus the connection table on startup
        self.query_one("#connection_table").focus()

    # ──────────────────────────────────────────────────────────────────────────
    # Periodic update
    # ──────────────────────────────────────────────────────────────────────────

    def update_tick(self) -> None:
        # 1. Stats bars
        stats = get_system_stats()
        self.query_one("#cpu_bar", AsciiProgressBar).percent = stats["cpu"]
        self.query_one("#ram_bar", AsciiProgressBar).percent = stats["ram"]

        # 2. Network bandwidth sparkline
        net_io = get_network_io()
        now = time.time()
        dt = now - self.last_net_time
        if dt > 0:
            sent_diff = max(0, net_io["bytes_sent"] - self.last_net_io["bytes_sent"])
            recv_diff = max(0, net_io["bytes_recv"] - self.last_net_io["bytes_recv"])
            tx_mbps = (sent_diff * 8) / (1024 * 1024 * dt)
            rx_mbps = (recv_diff * 8) / (1024 * 1024 * dt)
            self.last_net_io = net_io
            self.last_net_time = now

            self.query_one("#net_sparkline", Static).update(
                f"TRAFICO RED: "
                f"RX: [#F2E8C9]{rx_mbps:.2f} Mbps[/]  |  "
                f"TX: [#4A7A9D]{tx_mbps:.2f} Mbps[/]"
            )
            # Maintain rolling speed history
            self.rx_history.append(rx_mbps)
            self.tx_history.append(tx_mbps)
            if len(self.rx_history) > 20:
                self.rx_history.pop(0)
                self.tx_history.pop(0)

        # 3. Process list (BUG #2: second pass gives real cpu_percent values)
        proc_table = self.query_one("#process_table", ProcessTable)
        processes = get_process_list()
        proc_table.update_processes(processes)

        # 4. Protocol distribution pie chart
        proto_dist = get_system_protocol_distribution()
        # Filter out NO_ROOT marker before passing to pie chart
        pie_data = [(l, v) for l, v in proto_dist if l != "NO_ROOT" and v > 0]
        if not pie_data:
            # All zeros — likely no-root. Show placeholder
            pie_data = [("TCP", 1), ("UDP", 1), ("LISTEN", 1)]
        self.query_one("#proto_pie", AsciiPieChart).set_data(pie_data)

        # 5. Top CPU processes pie chart
        top_procs = get_top_processes_by_resource(processes, "cpu", limit=3)
        if top_procs:
            self.query_one("#proc_pie", AsciiPieChart).set_data(top_procs)

        # 6. Connection list for selected process
        self.refresh_connections()

        # 7. Update security status in the background
        self.update_c2_security_async()

    # ──────────────────────────────────────────────────────────────────────────
    # Connection refresh
    # ──────────────────────────────────────────────────────────────────────────

    def refresh_connections(self) -> None:
        conn_table = self.query_one("#connection_table", ConnectionTable)
        title_widget = self.query_one("#connection_title", Static)

        if self.filter_by_process and self.selected_pid:
            title_widget.update(
                f"[bold]CONEXIONES DEL PROCESO: {self.selected_proc_name} (PID: {self.selected_pid}) "
                f"[#888888]c=Ver todas  d=DNS  p=Protocolo[/][/]"
            )
            try:
                conns = get_process_connections(self.selected_pid, self.current_protocol)
                if conn_table.dns_active:
                    self.resolve_dns_for_connections(conns)
                conn_table.update_connections(conns, self.dns_resolved_ips)
            except psutil.NoSuchProcess:
                conn_table.clear()
                conn_table.add_row("-", "-", "!", "Proceso ya no existe", "-", "-", "-", "-", "-")
            except psutil.AccessDenied:
                conn_table.clear()
                conn_table.add_row("-", "-", "!", "Acceso Denegado (sudo requerido)", "-", "-", "-", "-", "-")
            except Exception as e:
                conn_table.clear()
                conn_table.add_row("-", "-", "!", str(e)[:30], "-", "-", "-", "-", "-")
        else:
            title_widget.update(
                f"[bold]TODAS LAS CONEXIONES DEL SISTEMA "
                f"[#888888]c=Filtrar por proc  d=DNS  p=Protocolo[/][/]"
            )
            try:
                conns = get_all_connections(self.current_protocol)
                if conn_table.dns_active:
                    self.resolve_dns_for_connections(conns)
                conn_table.update_connections(conns, self.dns_resolved_ips)
            except Exception as e:
                conn_table.clear()
                conn_table.add_row("-", "-", "!", str(e)[:30], "-", "-", "-", "-", "-")

    # ──────────────────────────────────────────────────────────────────────────
    # Async workers — BUG #3/#4 FIX:
    # These are async workers running on the asyncio event loop, NOT threads.
    # call_from_thread() is for sync threads only. In async workers, widget
    # methods can be called directly (they run on the same loop).
    # ──────────────────────────────────────────────────────────────────────────

    @work(exclusive=True)
    async def resolve_dns_for_connections(self, connections):
        for c in connections:
            raddr = c["raddr_ip"]
            if raddr and raddr not in ("-", "*", "127.0.0.1", "0.0.0.0", "::"):
                if raddr not in self.dns_resolved_ips:
                    host = await dns_resolver_instance.resolve(raddr)
                    self.dns_resolved_ips[raddr] = host

        # FIX: direct call — we are already on the asyncio event loop
        conn_table = self.query_one("#connection_table", ConnectionTable)
        conn_table.update_connections(conn_table.raw_connections, self.dns_resolved_ips)



    @work(exclusive=True)
    async def update_c2_security_async(self):
        from core.zombie_detector import analyze_zombie_status
        import asyncio
        loop = asyncio.get_running_loop()
        report = await loop.run_in_executor(None, analyze_zombie_status)
        try:
            widget = self.query_one("#c2_security_widget", C2SecurityWidget)
            widget.risk_level = report["risk_level"]
            widget.score = report["score"]
            widget.findings_count = len(report["findings"])

            risk_procs = []
            for f in report["findings"]:
                if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM") and f["proc_name"]:
                    risk_procs.append(f"{f['proc_name']} (PID: {f['pid']})")
            
            unique_risk_procs = list(dict.fromkeys(risk_procs))
            widget.risk_processes = ", ".join(unique_risk_procs) if unique_risk_procs else "Ninguno"
        except Exception:
            pass

    # ──────────────────────────────────────────────────────────────────────────
    # Event handlers
    # ──────────────────────────────────────────────────────────────────────────

    def on_process_table_process_selected(
        self, message: ProcessTable.ProcessSelected
    ) -> None:
        self.selected_pid = message.pid
        self.selected_proc_name = message.name
        # Only switch to filtered view if the process table is actually focused
        # (prevents automatic first-row selection at boot from filtering the view)
        try:
            pt = self.query_one("#process_table")
            if self.focused == pt:
                self.filter_by_process = True
        except Exception:
            pass
        self.refresh_connections()
        self.update_details_drawer()

    def on_filter_bar_filter_changed(self, message: FilterBar.FilterChanged) -> None:
        focused = self.focused
        if isinstance(focused, ProcessTable):
            focused.set_filter(message.query)
        elif isinstance(focused, ConnectionTable):
            focused.set_filter(message.query)
        else:
            self.query_one("#process_table", ProcessTable).set_filter(message.query)

    def on_filter_bar_protocol_changed(self, message: FilterBar.ProtocolChanged) -> None:
        self.current_protocol = message.protocol
        self.refresh_connections()



    # ──────────────────────────────────────────────────────────────────────────
    # Details drawer & Explanation Engine
    # ──────────────────────────────────────────────────────────────────────────

    @on(DataTable.RowHighlighted)
    def handle_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "process_table":
            self.selected_pid = int(event.row_key.value)
            for p in event.data_table.raw_processes:
                if p["pid"] == self.selected_pid:
                    self.selected_proc_name = p["name"]
                    break
            self.update_details_drawer()
        elif event.data_table.id == "connection_table":
            self.update_details_drawer()
            # Feed the selected connection into the Explanation Engine
            ct = event.data_table
            if ct.cursor_row is not None:
                try:
                    row_key = ct.coordinate_to_cell_key((ct.cursor_row, 0)).row_key
                    parts = row_key.value.split("_")
                    for c in ct.raw_connections:
                        if (str(c.get("pid", "-")) == parts[0] and
                            c["proto"] == parts[1] and
                            str(c["laddr_ip"]) == parts[2] and
                            str(c["laddr_port"]) == parts[3] and
                            str(c["raddr_ip"]) == parts[4] and
                            str(c["raddr_port"]) == parts[5]):
                            
                            from core.interpreter import interpret_connection
                            analysis = interpret_connection(c)
                            self.query_one("#explanation_panel", ExplanationPanel).update_explanation(
                                explanation=analysis.get("explanation", "-"),
                                recommendations=analysis.get("recommendations", []),
                                educational=analysis.get("educational", "-"),
                                level=analysis.get("assessment", "INFO")
                            )
                            break
                except Exception:
                    pass

    def update_details_drawer(self) -> None:
        ct = self.query_one("#connection_table", ConnectionTable)
        dns_status = "ACTIVADO" if ct.dns_active else "APAGADO"

        if self.selected_pid:
            try:
                proc = psutil.Process(self.selected_pid)
                try:
                    cmdline = " ".join(proc.cmdline()) or self.selected_proc_name
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cmdline = self.selected_proc_name

                created_time = proc.create_time()
                uptime = int(time.time() - created_time)
                h, rem = divmod(uptime, 3600)
                m, s = divmod(rem, 60)
                uptime_str = f"{h}h {m}m {s}s"

                text = (
                    f"Proceso: [bold]{self.selected_proc_name}[/] "
                    f"(PID: {self.selected_pid}) | "
                    f"Activo: {uptime_str} | "
                    f"CMD: [italic #888888]{cmdline[:60]}[/] | "
                    f"DNS: [bold]{dns_status}[/]"
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                text = (
                    f"Proceso: {self.selected_proc_name} "
                    f"(PID: {self.selected_pid}) | DNS: {dns_status}"
                )
        else:
            text = f"Detalles: Ninguno seleccionado | DNS: {dns_status}"

        self.query_one("#details_drawer", Static).update(text)

    # ──────────────────────────────────────────────────────────────────────────
    # Action handlers (bound in app.py BINDINGS)
    # ──────────────────────────────────────────────────────────────────────────

    def action_cursor_up(self) -> None:
        focused = self.focused
        if isinstance(focused, (ProcessTable, ConnectionTable)):
            focused.action_cursor_up()

    def action_cursor_down(self) -> None:
        focused = self.focused
        if isinstance(focused, (ProcessTable, ConnectionTable)):
            focused.action_cursor_down()

    def action_focus_next(self) -> None:
        # Process table is hidden; connection table is the primary focus
        ct = self.query_one("#connection_table", ConnectionTable)
        ct.focus()

    def action_focus_previous(self) -> None:
        self.action_focus_next()

    def action_select_process(self) -> None:
        pt = self.query_one("#process_table", ProcessTable)
        if self.focused == pt:
            pt._emit_selected_process()

    def _get_target_pid_for_action(self) -> tuple[int | None, str]:
        focused = self.focused
        ct = self.query_one("#connection_table", ConnectionTable)
        
        if focused == ct and ct.cursor_row is not None:
            try:
                row_key = ct.coordinate_to_cell_key((ct.cursor_row, 0)).row_key
                parts = row_key.value.split("_")
                if len(parts) >= 1:
                    pid = int(parts[0])
                    name = "-"
                    for c in ct.raw_connections:
                        if c.get("pid") == pid:
                            name = c.get("name", "-")
                            break
                    return pid, name
            except Exception:
                pass
                
        return self.selected_pid, self.selected_proc_name

    def action_kill_process(self) -> None:
        pid, name = self._get_target_pid_for_action()
        if not pid or pid == "-":
            self.notify("Ningún proceso o conexión seleccionada para terminar.")
            return

        def handle_kill_result(killed):
            if killed is True:
                self.notify(
                    f"Proceso PID {pid} terminado.",
                    severity="information"
                )
                if self.selected_pid == pid:
                    self.selected_pid = None
                    self.selected_proc_name = ""
                self.update_tick()
            elif isinstance(killed, Exception) and "AccessDenied" in type(killed).__name__:
                self.notify(
                    "Acceso denegado — ejecuta con sudo para terminar este proceso.",
                    severity="error"
                )
            elif isinstance(killed, Exception):
                self.notify(f"Error al terminar: {killed}", severity="error")

        self.app.push_screen(
            ConfirmKillModal(pid, name),
            handle_kill_result
        )

    def action_analyze_local(self) -> None:
        pid, name = self._get_target_pid_for_action()
        if not pid or pid == "-":
            self.notify("Ningún proceso o conexión seleccionada para analizar.")
            return
        self.app.push_screen(
            LocalAnalysisModal(pid, name)
        )

    def action_analyze_with_vt(self) -> None:
        pid, name = self._get_target_pid_for_action()
        if not pid or pid == "-":
            self.notify("Ningún proceso o conexión seleccionada para analizar.")
            return
        self.app.push_screen(
            VirusTotalAnalysisModal(pid, name)
        )

    def action_toggle_dns(self) -> None:
        ct = self.query_one("#connection_table", ConnectionTable)
        ct.dns_active = not ct.dns_active
        if not ct.dns_active:
            dns_resolver_instance.clear_cache()
            self.dns_resolved_ips.clear()
        self.refresh_connections()
        self.update_details_drawer()
        self.notify(f"Resolución DNS: {'ACTIVADO' if ct.dns_active else 'APAGADO'}")

    def action_toggle_filter(self) -> None:
        fp = self.query_one("#filter_panel", FilterBar)
        if fp.styles.display == "none":
            fp.styles.display = "block"
            fp.focus_input()
        else:
            fp.styles.display = "none"
            fp.clear_filter()
            # Clear table filters when filter panel is closed
            pt = self.query_one("#process_table", ProcessTable)
            ct = self.query_one("#connection_table", ConnectionTable)
            pt.set_filter("")
            ct.set_filter("")
            pt.focus()

    def action_cycle_protocol(self) -> None:
        proto = self.query_one("#filter_panel", FilterBar).cycle_protocol()
        self.notify(f"Filtrando por protocolo: {proto}")

    def action_cycle_sort(self) -> None:
        pt = self.query_one("#process_table", ProcessTable)
        label = pt.cycle_sort()
        self.notify(f"Ordenando procesos por: {label}")

    def action_export_report(self) -> None:
        def handle_export(result):
            if not result:
                return
            path, fmt = result
            pt = self.query_one("#process_table", ProcessTable)
            ct = self.query_one("#connection_table", ConnectionTable)

            snapshot_conns = []
            for c in ct.raw_connections:
                conn_copy = c.copy()
                conn_copy["pid"] = self.selected_pid
                conn_copy["name"] = self.selected_proc_name
                snapshot_conns.append(conn_copy)

            try:
                export_report(path, fmt, pt.raw_processes, snapshot_conns)
                self.notify(f"Reporte exportado a: {path}")
            except Exception as e:
                self.notify(f"Error al exportar: {e}", severity="error")

        self.app.push_screen(ExportReportModal(), handle_export)

    def action_zombie_check(self) -> None:
        print("[DEBUG] action_zombie_check triggered!")
        self.app.push_screen(ZombieAnalysisModal())

    def action_clear_selection(self) -> None:
        self.filter_by_process = not self.filter_by_process
        self.refresh_connections()
        self.update_details_drawer()
        if self.filter_by_process:
            self.notify("Filtrando conexiones por proceso seleccionado")
        else:
            self.notify("Mostrando todas las conexiones del sistema")

    def action_dismiss_modal(self) -> None:
        if self.filter_by_process:
            self.filter_by_process = False
            self.refresh_connections()
            self.update_details_drawer()
            self.notify("Filtro desactivado: mostrando todas las conexiones")

    def action_open_maps(self) -> None:
        ct = self.query_one("#connection_table", ConnectionTable)
        if ct.cursor_row is not None:
            try:
                row_key = ct.coordinate_to_cell_key((ct.cursor_row, 0)).row_key
                parts = row_key.value.split("_")
                if len(parts) >= 6:
                    raddr_ip = parts[4]
                    if raddr_ip and raddr_ip not in ("-", "0.0.0.0", "::", "127.0.0.1"):
                        self.notify(f"Abriendo Dashboard Web para ubicación de {raddr_ip}...")
                        self.resolve_geoip_and_open_browser(raddr_ip)
                        return
            except Exception:
                pass
        
        self.notify("Abriendo Mapa Global en el navegador...")
        import webbrowser
        webbrowser.open(f"http://127.0.0.1:{PORT}")

    @work(exclusive=True)
    async def resolve_geoip_and_open_browser(self, ip_str: str):
        from core.geoip import lookup_ip_geoip
        import webbrowser
        res = await lookup_ip_geoip(ip_str)
        if res and res.get("lat") is not None and res.get("lon") is not None:
            lat = res["lat"]
            lon = res["lon"]
            city = res.get("city", "Desconocida")
            country = res.get("country", "Desconocido")
            
            # Interactive and graphical OSM map
            map_url = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=12/{lat}/{lon}"
            self.notify(f"Abriendo mapa en browser para {ip_str} ({city}, {country})")
            
            import asyncio
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, webbrowser.open, map_url)
        else:
            self.notify(f"No se pudo determinar la ubicación de {ip_str}", severity="error")

    def action_toggle_security(self) -> None:
        zombie_detector.ADVANCED_SECURITY_ENABLED = not zombie_detector.ADVANCED_SECURITY_ENABLED
        enabled = zombie_detector.ADVANCED_SECURITY_ENABLED
        status_bar = self.query_one("#security_status_bar", Static)
        if enabled:
            status_bar.update(
                "[#34d399]●[/] ANALÍTICA DE SEGURIDAD: [bold #34d399]ACTIVA[/]   "
                "[#888888]S=Activar/Desactivar  z=Análisis Zombie  a=Analizar  v=VT  x=Kill  s=Ordenar  /=Buscar  d=DNS[/]"
            )
            status_bar.remove_class("sec-off")
            status_bar.add_class("sec-on")
            self.notify("● Herramientas de seguridad analítica ACTIVADAS.", severity="information")
        else:
            status_bar.update(
                "[#888888]○[/] ANALÍTICA DE SEGURIDAD: [bold #888888]DESACTIVADA[/]   "
                "[#888888]S=Activar/Desactivar  z=Análisis Zombie  a=Analizar  v=VT  x=Kill  s=Ordenar  /=Buscar  d=DNS[/]"
            )
            status_bar.remove_class("sec-on")
            status_bar.add_class("sec-off")
            self.notify("○ Herramientas de seguridad desactivadas. Modo monitor ligero.", severity="warning")
        self.update_tick()

    def action_open_graphics(self) -> None:
        import webbrowser
        self.notify(f"Abriendo gráficos en browser (http://localhost:{PORT})...")
        webbrowser.open(f"http://localhost:{PORT}")

    def action_show_tui_graphics(self) -> None:
        # Get protocol distribution
        proto_dist = get_system_protocol_distribution()
        
        # Get top CPU processes
        pt = self.query_one("#process_table", ProcessTable)
        top_procs = get_top_processes_by_resource(pt.raw_processes, "cpu", limit=5)
        
        # Get threat status
        widget = self.query_one("#c2_security_widget", C2SecurityWidget)
        score = widget.score
        level = widget.risk_level
        
        from screens.modals import TuiGraphicsModal
        self.app.push_screen(
            TuiGraphicsModal(
                self.rx_history,
                self.tx_history,
                proto_dist,
                top_procs,
                score,
                level
            )
        )

    def action_show_interpretation(self) -> None:
        focused = self.focused
        pt = self.query_one("#process_table", ProcessTable)
        ct = self.query_one("#connection_table", ConnectionTable)
        
        conn_data = None
        proc_data = None
        
        if focused == ct and ct.cursor_row is not None:
            try:
                row_key = ct.coordinate_to_cell_key((ct.cursor_row, 0)).row_key
                parts = row_key.value.split("_")
                for c in ct.raw_connections:
                    if (str(c.get("pid", "-")) == parts[0] and
                        c["proto"] == parts[1] and
                        str(c["laddr_ip"]) == parts[2] and
                        str(c["laddr_port"]) == parts[3] and
                        str(c["raddr_ip"]) == parts[4] and
                        str(c["raddr_port"]) == parts[5]):
                        conn_data = c
                        break
            except Exception:
                pass
        elif focused == pt and pt.cursor_row is not None:
            try:
                row_key = pt.coordinate_to_cell_key((pt.cursor_row, 0)).row_key
                pid = int(row_key.value)
                for p in pt.raw_processes:
                    if p["pid"] == pid:
                        proc_data = p
                        break
            except Exception:
                pass
                
        from screens.modals import InterpretationModal
        self.app.push_screen(InterpretationModal(conn_data, proc_data))

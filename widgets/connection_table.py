import time
from textual.widgets import DataTable
from rich.text import Text

class ConnectionTable(DataTable):
    """
    A custom DataTable for showing network connections.
    Includes active highlights for new entries (azul) and fading closed entries (gray).
    """

    def __init__(self, id: str = None):
        super().__init__(id=id)
        self.cursor_type = "row"
        self.zebra_striping = False

        # Track connections over ticks for visual effects
        # Key: (proto, laddr_ip, laddr_port, raddr_ip, raddr_port)
        # Value: {'first_seen': float, 'last_seen': float, 'is_dead': bool}
        self.connection_states = {}
        self.raw_connections = []
        self.filter_query = ""

        # Flag indicating if DNS resolution is active
        self.dns_active = False

    def on_mount(self) -> None:
        self.add_column("Proceso", key="name")
        self.add_column("PID", key="pid")
        self.add_column("Proto", key="proto")
        self.add_column("IP Origen", key="laddr_ip")
        self.add_column("Pto Orig.", key="laddr_port")
        self.add_column("IP Destino", key="raddr_ip")
        self.add_column("Pto Dest.", key="raddr_port")
        self.add_column("Estado", key="status")
        self.add_column("Hostname", key="hostname")

    def set_filter(self, query: str) -> None:
        self.filter_query = query.strip().lower()
        self.refresh_table()

    def update_connections(self, connections: list, dns_resolved_cache: dict = None) -> None:
        """
        Updates connection lists, processes fades and highlights, and refreshes view.
        """
        now = time.time()
        incoming_keys = set()

        # Build states
        for c in connections:
            key = (
                str(c.get("pid", "-")),
                c["proto"],
                str(c["laddr_ip"]),
                str(c["laddr_port"]),
                str(c["raddr_ip"]),
                str(c["raddr_port"])
            )
            incoming_keys.add(key)

            if key not in self.connection_states:
                # Newly appeared connection
                self.connection_states[key] = {
                    "first_seen": now,
                    "last_seen": now,
                    "is_dead": False,
                    "data": c
                }
            else:
                # Connection persists
                self.connection_states[key]["last_seen"] = now
                self.connection_states[key]["is_dead"] = False
                self.connection_states[key]["data"] = c

        # Find connections that were present but are missing now (dead / closed)
        for key, state in list(self.connection_states.items()):
            if key not in incoming_keys:
                if not state["is_dead"]:
                    state["is_dead"] = True
                    state["last_seen"] = now
                else:
                    # If it has been dead for more than 2 seconds, drop it
                    if now - state["last_seen"] > 2.0:
                        del self.connection_states[key]

        # Prepare final list of entries to display
        self.raw_connections = []
        for key, state in self.connection_states.items():
            c = state["data"].copy()
            c["first_seen"] = state["first_seen"]
            c["last_seen"] = state["last_seen"]
            c["is_dead"] = state["is_dead"]

            # DNS resolution if toggled active
            raddr_ip = str(c["raddr_ip"])
            if self.dns_active and dns_resolved_cache and raddr_ip in dns_resolved_cache:
                c["hostname"] = dns_resolved_cache[raddr_ip]
            else:
                c["hostname"] = "-"

            self.raw_connections.append(c)

        self.refresh_table()

    def refresh_table(self) -> None:
        # Save focused connection index if possible
        selected_key = None
        try:
            if self.cursor_row is not None:
                selected_key = self.coordinate_to_cell_key(
                    (self.cursor_row, 0)
                ).row_key
        except Exception:
            pass

        # Filter
        filtered = []
        for c in self.raw_connections:
            if self.filter_query:
                matches = (
                    self.filter_query in (c.get("name") or "").lower() or
                    self.filter_query in str(c.get("pid") or "").lower() or
                    self.filter_query in (c.get("proto") or "").lower() or
                    self.filter_query in str(c.get("laddr_ip") or "").lower() or
                    self.filter_query in str(c.get("laddr_port") or "").lower() or
                    self.filter_query in str(c.get("raddr_ip") or "").lower() or
                    self.filter_query in str(c.get("raddr_port") or "").lower() or
                    self.filter_query in (c.get("status") or "").lower() or
                    self.filter_query in (c.get("hostname") or "").lower()
                )
                if not matches:
                    continue
            filtered.append(c)

        self.clear()

        now = time.time()
        target_row_idx = None

        for idx, c in enumerate(filtered):
            # BUG #1 FIX: Python closure bug — define color as default arg so each
            # style_cell captures its OWN value of color, not the loop variable.
            # Without this fix every row ends up with the last iteration's color.
            is_new = (now - c["first_seen"]) < 2.0 and not c["is_dead"]
            is_dead = c["is_dead"]

            if is_dead:
                color = "#888888"
            elif is_new:
                color = "#4A7A9D"
            else:
                color = "#E0E0E0"

            # FIX: capture color by value using default argument
            def style_cell(val, _color=color):
                return Text(str(val), style=_color)

            row_key_str = (
                f"{c.get('pid', '-')}_{c['proto']}_{c['laddr_ip']}_{c['laddr_port']}_"
                f"{c['raddr_ip']}_{c['raddr_port']}"
            )

            self.add_row(
                style_cell(c.get("name", "-")),
                style_cell(c.get("pid", "-")),
                style_cell(c["proto"]),
                style_cell(c["laddr_ip"]),
                style_cell(c["laddr_port"]),
                style_cell(c["raddr_ip"]),
                style_cell(c["raddr_port"]),
                style_cell(c["status"]),
                style_cell(c["hostname"]),
                key=row_key_str
            )

            if selected_key is not None and row_key_str == selected_key.value:
                target_row_idx = idx

        if target_row_idx is not None and target_row_idx < len(filtered):
            self.move_cursor(row=target_row_idx)

from textual.widgets import DataTable
from textual.message import Message

class ProcessTable(DataTable):
    """
    A custom DataTable for showing processes.
    Supports filtering and sorting cycle.
    """

    class ProcessSelected(Message):
        """Emitted when a process row is focused/selected."""
        def __init__(self, pid: int, name: str):
            super().__init__()
            self.pid = pid
            self.name = name

    def __init__(self, id: str = None):
        super().__init__(id=id)
        self.cursor_type = "row"
        self.zebra_striping = False

        # Sort state tracking — Columns: PID, Name, User, CPU%, RAM%
        self.sort_keys = ["pid", "name", "user", "cpu", "ram"]
        self.current_sort_index = 0
        self.sort_descending = False

        # Cache processes list for filtering/sorting operations
        self.raw_processes = []
        self.filter_query = ""

        # BUG #7 FIX: Track last emitted PID so we don't storm the event bus
        # every 1.5 seconds with redundant ProcessSelected messages when the
        # user hasn't changed their selection.
        self._last_emitted_pid = None

    def on_mount(self) -> None:
        self.add_column("PID", key="pid")
        self.add_column("Nombre", key="name")
        self.add_column("Usuario", key="user")
        self.add_column("CPU %", key="cpu")
        self.add_column("RAM %", key="ram")

    def update_processes(self, processes: list) -> None:
        """
        Updates internal list of processes, applies active sort and filters,
        and refreshes the DataTable rows.
        """
        self.raw_processes = processes
        self.refresh_table()

    def set_filter(self, query: str) -> None:
        self.filter_query = query.strip().lower()
        self.refresh_table()

    def cycle_sort(self) -> str:
        """
        Cycles sort column criteria. Returns the active sort column name.
        """
        if not self.sort_descending:
            self.sort_descending = True
        else:
            self.sort_descending = False
            self.current_sort_index = (self.current_sort_index + 1) % len(self.sort_keys)

        self.refresh_table()
        return self.get_active_sort_label()

    def get_active_sort_label(self) -> str:
        key = self.sort_keys[self.current_sort_index]
        direction = "v" if self.sort_descending else "^"
        return f"{key.upper()} {direction}"

    def refresh_table(self) -> None:
        # Save focused row PID to restore after rebuild
        selected_pid = None
        try:
            if self.cursor_row is not None:
                row_key = self.coordinate_to_cell_key((self.cursor_row, 0)).row_key
                selected_pid = int(row_key.value)
        except Exception:
            pass

        # ── Filter ──────────────────────────────────────────────────────────
        filtered = []
        for p in self.raw_processes:
            if self.filter_query:
                matches = (
                    self.filter_query in str(p["pid"]) or
                    self.filter_query in (p.get("name") or "").lower() or
                    self.filter_query in (p.get("user") or "").lower() or
                    self.filter_query in str(p.get("cpu") or 0.0) or
                    self.filter_query in str(p.get("ram") or 0.0)
                )
                if not matches:
                    continue
            filtered.append(p)

        # ── Sort ─────────────────────────────────────────────────────────────
        sort_key = self.sort_keys[self.current_sort_index]

        def get_sort_val(x):
            val = x[sort_key]
            return val.lower() if isinstance(val, str) else val

        filtered.sort(key=get_sort_val, reverse=self.sort_descending)

        # ── Rebuild rows ─────────────────────────────────────────────────────
        self.clear()
        target_row_idx = None

        for idx, p in enumerate(filtered):
            row_key = str(p["pid"])
            self.add_row(
                str(p["pid"]),
                p["name"],
                p["user"],
                f"{p['cpu']}%",
                f"{p['ram']}%",
                key=row_key
            )
            if selected_pid is not None and p["pid"] == selected_pid:
                target_row_idx = idx

        # Restore cursor position
        if target_row_idx is not None and target_row_idx < len(filtered):
            self.move_cursor(row=target_row_idx)

        # BUG #7 FIX: Only emit if the currently selected PID has actually
        # changed (or is being set for the first time). This prevents a storm
        # of ProcessSelected events every 1.5 seconds causing redundant
        # refresh_connections() + update_details_drawer() calls.
        try:
            if self.cursor_row is not None:
                row_key = self.coordinate_to_cell_key((self.cursor_row, 0)).row_key
                current_pid = int(row_key.value)
                if current_pid != self._last_emitted_pid:
                    self._last_emitted_pid = current_pid
                    name = next(
                        (p["name"] for p in self.raw_processes if p["pid"] == current_pid),
                        "?"
                    )
                    self.post_message(self.ProcessSelected(current_pid, name))
        except Exception:
            pass

    def _emit_selected_process(self):
        """Force-emit a ProcessSelected event for the current cursor row."""
        if self.cursor_row is not None:
            try:
                row_key = self.coordinate_to_cell_key((self.cursor_row, 0)).row_key
                pid = int(row_key.value)
                name = next(
                    (p["name"] for p in self.raw_processes if p["pid"] == pid),
                    "?"
                )
                # Always emit on explicit user action (Enter / click)
                self._last_emitted_pid = pid
                self.post_message(self.ProcessSelected(pid, name))
            except Exception:
                pass

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self._emit_selected_process()

    def on_data_table_cell_selected(self, event: DataTable.CellSelected) -> None:
        self._emit_selected_process()

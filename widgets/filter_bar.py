from textual.widget import Widget
from textual.widgets import Input, Static
from textual.containers import Horizontal
from textual.message import Message

class FilterBar(Widget):
    """
    A toggleable filtering bar.
    Contains:
    - Live text search input (affects currently focused grid)
    - Protocol filter tabs: [TCP] [UDP] [LISTEN] [ALL]
    """
    
    class FilterChanged(Message):
        """Emitted when the text search query changes."""
        def __init__(self, query: str):
            super().__init__()
            self.query = query

    class ProtocolChanged(Message):
        """Emitted when active protocol tab cycles."""
        def __init__(self, protocol: str):
            super().__init__()
            self.protocol = protocol

    def __init__(self, id: str = None):
        super().__init__(id=id)
        # Internal states
        self.protocols = ["ALL", "TCP", "UDP", "LISTEN"]
        self.current_proto_idx = 0

    def compose(self):
        # We wrap in Horizontal layout
        yield Horizontal(
            Input(placeholder="Buscar (PID, Nombre, IP, Puerto...)...", id="search_input"),
            Static(self._get_proto_markup(), id="proto_indicator"),
            id="filter_container"
        )

    def _get_proto_markup(self) -> str:
        markup = "Filtro: "
        for idx, proto in enumerate(self.protocols):
            if idx == self.current_proto_idx:
                markup += f"[[bold #4A7A9D]{proto}[/]] "
            else:
                markup += f" {proto}  "
        return markup

    def cycle_protocol(self) -> str:
        """Cycles through ALL -> TCP -> UDP -> LISTEN."""
        self.current_proto_idx = (self.current_proto_idx + 1) % len(self.protocols)
        proto_indicator = self.query_one("#proto_indicator", Static)
        proto_indicator.update(self._get_proto_markup())
        
        active_proto = self.protocols[self.current_proto_idx]
        self.post_message(self.ProtocolChanged(active_proto))
        return active_proto

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search_input":
            self.post_message(self.FilterChanged(event.value))

    def focus_input(self) -> None:
        inp = self.query_one("#search_input", Input)
        inp.focus()
        
    def blur_input(self) -> None:
        inp = self.query_one("#search_input", Input)
        # Textual doesn't have blur directly on widget, but we can focus another pane
        # Let parent handle it.
        pass
        
    def clear_filter(self) -> None:
        inp = self.query_one("#search_input", Input)
        inp.value = ""

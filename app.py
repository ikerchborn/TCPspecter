from textual.app import App
from screens.main_screen import MainScreen


class TCPspecterApp(App):
    """
    TCPspecter — Linux TUI Network & Process Monitor (TCPView equivalent for Linux)
    """
    CSS_PATH = "styles.css"

    # BUG #5 FIX: 'tab' and 'enter' were defined here at App level, which
    # shadowed Textual's native Tab focus cycling and the Enter key handling
    # inside Input and DataTable widgets.
    #
    # Fix:
    # - Removed 'tab' and 'shift+tab' from here — Textual handles them natively
    #   and MainScreen.action_focus_next / action_focus_previous override them
    #   only when the focused widget is a DataTable (not an Input).
    # - Removed 'enter' from App level — enter is handled by DataTable's own
    #   row-selection event and by MainScreen.action_select_process when needed.
    # - All navigation actions are delegated to MainScreen which is the active screen.
    BINDINGS = [
        ("q",              "quit",              "Salir"),
    ]

    def on_mount(self) -> None:
        import os, json
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
                if config.get("ACTIVE_RESPONSE_ENABLED", False):
                    self.notify("WARNING: ACTIVE_RESPONSE_ENABLED is True! System may alter connectivity.", title="TCPspecter", severity="warning", timeout=5)
        except Exception:
            pass
        self.push_screen(MainScreen())


if __name__ == "__main__":
    from core.response_engine import start_engine
    from core.intelligence_engine import initialize_intelligence

    initialize_intelligence()
    start_engine()
    
    app = TCPspecterApp()
    app.run()

from textual.widget import Widget
from textual.reactive import reactive
from rich.text import Text

class C2SecurityWidget(Widget):
    """
    A dashboard widget that displays the real-time C2 / Zombie security status of the system.
    """
    risk_level = reactive("BAJO")
    score = reactive(0)
    findings_count = reactive(0)
    risk_processes = reactive("Ninguno")

    def render(self) -> Text:
        # Apply color code depending on threat level
        if self.risk_level == "CRÍTICO":
            level_markup = "[bold red]CRÍTICO[/]"
        elif self.risk_level == "ALTO":
            level_markup = "[bold yellow]ALTO[/]"
        elif self.risk_level == "MEDIO":
            level_markup = "[bold #4A7A9D]MEDIO[/]"
        else:
            level_markup = "[bold green]BAJO[/]"

        risk_procs_disp = self.risk_processes
        if len(risk_procs_disp) > 18:
            risk_procs_disp = risk_procs_disp[:15] + "..."

        markup = (
            f" [bold #E0E0E0]MONITOR DE SEGURIDAD (C2)[/]\n"
            f" -----------------------------\n"
            f" Nivel de Riesgo: {level_markup}\n"
            f" Puntuación:      [bold]{self.score}[/]/100\n"
            f" Alertas activas: [bold]{self.findings_count}[/]\n"
            f" Proc. de Riesgo: [bold yellow]{risk_procs_disp}[/]\n\n"
            f" [italic #888888]Presiona 'z' para ver detalles[/]"
        )
        return Text.from_markup(markup)

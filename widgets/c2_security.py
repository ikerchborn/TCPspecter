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
        if self.risk_level == "DESACTIVADO":
            level_markup = "[bold #888888]DESACTIVADO[/]"
            score_disp = "—"
            findings_disp = "—"
            procs_disp = "[#888888]Analítica apagada (S)[/]"
        else:
            if self.risk_level == "CRÍTICO":
                level_markup = "[bold red]CRÍTICO[/]"
            elif self.risk_level == "ALTO":
                level_markup = "[bold yellow]ALTO[/]"
            elif self.risk_level == "MEDIO":
                level_markup = "[bold #4A7A9D]MEDIO[/]"
            else:
                level_markup = "[bold green]BAJO[/]"
            score_disp = str(self.score)
            findings_disp = str(self.findings_count)
            procs_disp = self.risk_processes
            if len(procs_disp) > 18:
                procs_disp = procs_disp[:15] + "..."

        markup = (
            f" [bold #E0E0E0]MONITOR DE SEGURIDAD (C2)[/]\n"
            f" -----------------------------\n"
            f" Nivel de Riesgo: {level_markup}\n"
            f" Puntuación:      [bold]{score_disp}[/]/100\n"
            f" Alertas activas: [bold]{findings_disp}[/]\n"
            f" Proc. de Riesgo: [bold yellow]{procs_disp}[/]\n\n"
            f" [italic #888888]Presiona 'z' para ver detalles[/]"
        )
        return Text.from_markup(markup)

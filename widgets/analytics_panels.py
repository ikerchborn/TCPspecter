from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal
from textual.widgets import Static

class ExplanationPanel(Static):
    """
    A unified panel displaying the Explanation Engine output.
    Contains the narrative explanation, actionable recommendations,
    and educational context based on the selected network event.
    """
    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("Motor de Explicación", classes="panel_title"),
            Static("Selecciona una conexión para analizar su riesgo, comportamiento y contexto.", id="expl_narrative", classes="expl_text"),
            Horizontal(
                Vertical(
                    Static("Recomendaciones:", classes="panel_subtitle"),
                    Static("-", id="expl_recommendations", classes="expl_text"),
                    id="expl_rec_box"
                ),
                Vertical(
                    Static("Contexto Educativo:", classes="panel_subtitle"),
                    Static("-", id="expl_educational", classes="expl_text"),
                    id="expl_edu_box"
                ),
                id="expl_split"
            ),
            id="explanation_container"
        )

    def update_explanation(self, explanation: str, recommendations: list, educational: str, level: str):
        color = "#f3f4f6"
        if "CRÍTICO" in level:
            color = "#f87171"
        elif "REVISAR" in level:
            color = "#fbbf24"
            
        narrative_widget = self.query_one("#expl_narrative", Static)
        narrative_widget.update(f"[{color}][b]{level}[/b][/]\n{explanation}")
        
        rec_text = "\n".join([f"• {r}" for r in recommendations]) if recommendations else "No hay recomendaciones específicas."
        self.query_one("#expl_recommendations", Static).update(rec_text)
        
        edu_text = educational if educational else "Selecciona conexiones con actividad externa o sospechosa para aprender más."
        self.query_one("#expl_educational", Static).update(edu_text)

    def clear_explanation(self):
        self.query_one("#expl_narrative", Static).update("Selecciona una conexión externa o crítica para ver su explicación.")
        self.query_one("#expl_recommendations", Static).update("-")
        self.query_one("#expl_educational", Static).update("-")

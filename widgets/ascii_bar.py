from textual.widget import Widget
from textual.reactive import reactive
from rich.text import Text

class AsciiProgressBar(Widget):
    """
    A custom ASCII-only progress bar widget using HSL/Hex tailored colors.
    """
    percent = reactive(0.0)
    label = reactive("")
    color_class = reactive("") # 'cpu' (blue) or 'ram' (cream)

    def __init__(self, label: str, percent: float = 0.0, color_class: str = "", id: str = None):
        super().__init__(id=id)
        self.label = label
        self.percent = percent
        self.color_class = color_class

    def render(self) -> Text:
        # Calculate segments (we will draw a bar of length 20 segments)
        bar_len = 20
        # Restrict percent to 0-100
        pct = max(0.0, min(100.0, self.percent))
        filled_segments = int(round((pct / 100.0) * bar_len))
        empty_segments = bar_len - filled_segments
        
        # Color hex references
        # CPU = Blue (#4A7A9D)
        # RAM = Cream (#F2E8C9)
        color_tag = "cyan" # Default fallback
        if self.color_class == "cpu":
            color_tag = "#4A7A9D"
        elif self.color_class == "ram":
            color_tag = "#F2E8C9"
            
        bar_str = f"[{color_tag}]" + "#" * filled_segments + "[/]" + "-" * empty_segments
        
        # Format textual percentage
        pct_str = f"{pct:5.1f}%"
        
        return Text.from_markup(f"{self.label:<5} {bar_str} {pct_str}")

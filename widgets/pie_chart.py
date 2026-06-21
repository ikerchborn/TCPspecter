import math
from textual.widget import Widget
from textual.reactive import reactive
from rich.text import Text

PIE_WIDTH = 13
PIE_HEIGHT = 7

class AsciiPieChart(Widget):
    """
    A custom widget that renders a mathematically correct circular ASCII pie chart.
    Supports up to 4 categories with distinct colors and patterns.
    """
    # List of tuples: (label, value, percentage, color, char)
    data = reactive([])
    title = reactive("")

    def __init__(self, title: str, id: str = None):
        super().__init__(id=id)
        self.title = title
        self.data = []

    def set_data(self, data_list):
        """
        data_list: list of (label, value)
        """
        total = sum(v for l, v in data_list)
        if total == 0:
            self.data = []
            return
            
        # Distribute percentages
        # Colors:
        # 1. Cream: #F2E8C9, char: #
        # 2. Blue: #4A7A9D, char: =
        # 3. Gray Dark: #555555, char: *
        # 4. Gray Light: #888888, char: -
        colors = ["#4A7A9D", "#F2E8C9", "#888888", "#555555"]
        chars = ["#", "=", "*", "-"]
        
        parsed = []
        acc_pct = 0.0
        for idx, (label, val) in enumerate(data_list):
            pct = (val / total) * 100.0
            color = colors[idx % len(colors)]
            char = chars[idx % len(chars)]
            parsed.append({
                "label": label,
                "value": val,
                "pct": pct,
                "start_deg": acc_pct * 3.6,
                "end_deg": (acc_pct + pct) * 3.6,
                "color": color,
                "char": char
            })
            acc_pct += pct
            
        self.data = parsed

    def render(self) -> Text:
        if not self.data:
            return Text.from_markup(f" [italic #888888]{self.title}[/]\n No hay datos")
            
        # Draw the circle grid
        cx = (PIE_WIDTH - 1) / 2.0
        cy = (PIE_HEIGHT - 1) / 2.0
        radius = 3.3  # radius of circle
        
        grid = []
        for y in range(PIE_HEIGHT):
            row = []
            for x in range(PIE_WIDTH):
                # Adjust for character aspect ratio (characters are taller than wide, roughly 2:1)
                dx = (x - cx) * 1.0
                dy = (y - cy) * 1.8
                dist = math.sqrt(dx**2 + dy**2)
                
                if dist <= radius:
                    # Calculate angle from center in degrees (0 to 360)
                    angle = math.atan2(dy, dx)
                    deg = (math.degrees(angle) + 360.0) % 360.0
                    
                    # Find which slice this angle belongs to
                    matched_slice = None
                    for sl in self.data:
                        # Handle wrapping if any, but start/end are monotonic
                        if sl["start_deg"] <= deg <= sl["end_deg"]:
                            matched_slice = sl
                            break
                    if not matched_slice and self.data:
                        matched_slice = self.data[-1] # fallback
                        
                    if matched_slice:
                        row.append(f"[{matched_slice['color']}]{matched_slice['char']}[/]")
                    else:
                        row.append(" ")
                else:
                    row.append(" ")
            grid.append("".join(row))
            
        # Format legend panel next to it
        legend_rows = [f"[bold #E0E0E0]{self.title}[/]"]
        for sl in self.data:
            legend_rows.append(
                f" [{sl['color']}]{sl['char']}[/] {sl['label'][:8]:<8} "
                f"{sl['pct']:5.1f}% ({sl['value']})"
            )
            
        # Combine grid rows and legend
        combined = []
        for i in range(max(PIE_HEIGHT, len(legend_rows))):
            g_row = grid[i] if i < len(grid) else " " * PIE_WIDTH
            l_row = legend_rows[i] if i < len(legend_rows) else ""
            combined.append(f" {g_row}   {l_row}")
            
        markup = "\n".join(combined)
        return Text.from_markup(markup)

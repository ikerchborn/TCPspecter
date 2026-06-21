import time
from textual.widget import Widget
from textual.reactive import reactive
from rich.text import Text

MAP_WIDTH = 50
MAP_HEIGHT = 15

# Coarse ASCII world map layout — each row must be exactly MAP_WIDTH characters wide
BASE_WORLD_MAP = [
    "                 .---.     .-----.              ",
    "              .-'     `._.-'      `._           ",
    "             /    N.     /   Eur     `-.        ",
    "            |    Amer   |   /  Asia     \\       ",
    "             \\         /|  |             |      ",
    "              `._   _.'  \\  \\           /       ",
    "                 `-'      `._`---.._..-'        ",
    "               .-.           /                  ",
    "              /   \\         |  Africa           ",
    "             | S.  |         \\                  ",
    "             | Amer|          `._               ",
    "              \\   /              `-.   Aust     ",
    "               `-'                  `-.---.     ",
    "                                       \\  /     ",
    "                                        `'      "
]

class WorldMap(Widget):
    """
    An interactive ASCII world map panel showing where IP packets go.
    Accepts latitude, longitude, and metadata, projecting coordinates to grid.
    """
    DEFAULT_CSS = """
    WorldMap {
        height: 15;
    }
    """
    
    lat = reactive(None)
    lon = reactive(None)
    country = reactive("Sin Conexion")
    city = reactive("Desconocido")
    org = reactive("Desconocido")
    ip_address = reactive("-")

    def __init__(self, id: str = None):
        super().__init__(id=id)
        self.blink = True
        self.set_interval(0.5, self.toggle_blink)

    def toggle_blink(self) -> None:
        self.blink = not self.blink
        self.refresh()

    def set_location(self, ip_str, lat, lon, country, city, org):
        self.ip_address = ip_str
        self.lat = lat
        self.lon = lon
        self.country = country
        self.city = city
        self.org = org

    def clear_location(self):
        self.ip_address = "-"
        self.lat = None
        self.lon = None
        self.country = "Sin Conexion"
        self.city = "Desconocido"
        self.org = "Desconocido"

    def render(self) -> Text:
        # BUG #6 FIX: Remove dead import 'from rich.markup import render' that
        # was inside the hot-path render() method called 2x per second.
        # It was imported but never used — only Text.from_markup is needed.

        lines = [list(line.ljust(MAP_WIDTH)) for line in BASE_WORLD_MAP]

        has_coord = (
            self.lat is not None and
            self.lon is not None and
            (self.lat != 0.0 or self.lon != 0.0)
        )
        col, row = None, None

        if has_coord:
            col = int(((self.lon + 180.0) / 360.0) * MAP_WIDTH)
            row = int(((90.0 - self.lat) / 180.0) * MAP_HEIGHT)
            col = max(0, min(MAP_WIDTH - 1, col))
            row = max(0, min(MAP_HEIGHT - 1, row))

            lines[row][col] = "*" if self.blink else "X"

        # Build markup string — apply accent color only on the pointer character row
        markup_lines = []
        for r_idx, line in enumerate(lines):
            line_str = "".join(line)
            if has_coord and r_idx == row and col is not None:
                left = line_str[:col]
                char = line_str[col]
                right = line_str[col + 1:]
                line_str = f"{left}[bold #4A7A9D]{char}[/]{right}"
            markup_lines.append(line_str)

        map_render = "\n".join(markup_lines)

        # Info panel to the right of the map
        lat_str = f"{self.lat:.2f}" if self.lat is not None else "0.00"
        lon_str = f"{self.lon:.2f}" if self.lon is not None else "0.00"
        info_panel = (
            f" [bold #F2E8C9]GEOLOCALIZACION IP[/]\n"
            f" +---------------------------------+\n"
            f"  IP:     {self.ip_address}\n"
            f"  Pais:   {self.country}\n"
            f"  Ciudad: {self.city}\n"
            f"  Org:    {self.org}\n"
            f"  Lat/Lon:{lat_str}, {lon_str}\n"
            f" +---------------------------------+\n"
            f" [italic #888888]El puntero [*] parpadea en la[/]\n"
            f" [italic #888888]ubicacion aproximada del host.[/]"
        )

        map_rows = map_render.split("\n")
        info_rows = info_panel.split("\n")

        combined_rows = []
        for i in range(max(len(map_rows), len(info_rows))):
            m_part = map_rows[i] if i < len(map_rows) else " " * MAP_WIDTH
            # Compute visual width without Rich markup tags
            visual_len = len(Text.from_markup(m_part).plain)
            padding = " " * max(0, MAP_WIDTH - visual_len)
            i_part = info_rows[i] if i < len(info_rows) else ""
            combined_rows.append(f"{m_part}{padding}  {i_part}")

        return Text.from_markup("\n".join(combined_rows))

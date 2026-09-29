"""Pygame renderer for the two-cell secure handover demonstration."""

from __future__ import annotations

import math
import time
from pathlib import Path
from typing import Optional

import pygame

from board_link import MAX_SESSIONS
from simulator import (
    BOUNDARY_METERS, ROAD_METERS, VEHICLE_KINDS, DemoController, Vehicle,
)

LOGICAL_SIZE = (1600, 900)

BG = (10, 16, 27)
PANEL = (20, 29, 45)
PANEL_2 = (25, 36, 55)
TEXT = (225, 232, 241)
MUTED = (139, 153, 175)
BLUE = (45, 139, 255)
ORANGE = (255, 151, 58)
GREEN = (57, 211, 153)
RED = (255, 82, 105)
YELLOW = (255, 208, 74)
GREY = (126, 139, 158)
WHITE = (242, 245, 250)
ROAD = (45, 50, 60)
DARK = (8, 14, 23)
GLASS = (181, 211, 232)
LEGEND = (176, 187, 204)

ROAD_TOP = 164
ROAD_HEIGHT = 220


class DemoUI:
    def __init__(self, controller: DemoController, fullscreen: bool = False):
        pygame.init()
        pygame.display.set_caption("Zynq FPGA PQC Secure Handover Demo")
        flags = pygame.RESIZABLE
        if fullscreen:
            flags = pygame.FULLSCREEN
        self.screen = pygame.display.set_mode(LOGICAL_SIZE, flags)
        self.canvas = pygame.Surface(LOGICAL_SIZE)
        self.controller = controller
        self.fonts = {
            "xs": pygame.font.SysFont("segoeui,arial", 15),
            "small": pygame.font.SysFont("segoeui,arial", 18),
            "body": pygame.font.SysFont("segoeui,arial", 21),
            "sub": pygame.font.SysFont("segoeui,arial", 25, bold=True),
            "title": pygame.font.SysFont("segoeui,arial", 34, bold=True),
            "big": pygame.font.SysFont("segoeui,arial", 44, bold=True),
        }
        self.vehicle_rects: dict[int, pygame.Rect] = {}
        self.buttons: dict[str, pygame.Rect] = {}

    def close(self) -> None:
        pygame.quit()

    def logical_mouse(self, pos: tuple[int, int]) -> tuple[int, int]:
        width, height = self.screen.get_size()
        return int(pos[0] * 1600 / width), int(pos[1] * 900 / height)

    def handle_event(self, event: pygame.event.Event) -> Optional[str]:
        if event.type == pygame.QUIT:
            return "quit"
        if event.type == pygame.KEYDOWN:
            if event.key in (pygame.K_ESCAPE, pygame.K_q):
                return "quit"
            if event.key == pygame.K_SPACE:
                self.controller.toggle_running()
            if event.key == pygame.K_t:
                self.controller.attack_selected()
            if event.key == pygame.K_F11:
                pygame.display.toggle_fullscreen()
        if event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:
            point = self.logical_mouse(event.pos)
            for vehicle_id, rect in self.vehicle_rects.items():
                if rect.collidepoint(point):
                    self.controller.select_vehicle(vehicle_id)
                    return None
            for name, rect in self.buttons.items():
                if rect.collidepoint(point):
                    if name == "pause":
                        self.controller.toggle_running()
                    elif name == "attack":
                        self.controller.attack_selected()
                    elif name == "quit":
                        return "quit"
        return None

    def draw(self) -> None:
        self.canvas.fill(BG)
        self._draw_header()
        self._draw_road()
        self._draw_board_panel("A", pygame.Rect(40, 470, 470, 280), BLUE)
        self._draw_board_panel("B", pygame.Rect(530, 470, 470, 280), ORANGE)
        self._draw_event_log(pygame.Rect(1020, 470, 540, 380))
        self._draw_controls(pygame.Rect(40, 770, 960, 80))
        scaled = pygame.transform.smoothscale(self.canvas, self.screen.get_size())
        self.screen.blit(scaled, (0, 0))
        pygame.display.flip()

    def save_screenshot(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        pygame.image.save(self.canvas, str(path))

    def _text(
        self,
        text: str,
        position: tuple[int, int],
        font: str = "body",
        color: tuple[int, int, int] = TEXT,
        anchor: str = "topleft",
    ) -> pygame.Rect:
        surface = self.fonts[font].render(text, True, color)
        rect = surface.get_rect()
        setattr(rect, anchor, position)
        self.canvas.blit(surface, rect)
        return rect

    def _round_panel(self, rect: pygame.Rect, color=PANEL, radius: int = 14) -> None:
        pygame.draw.rect(self.canvas, color, rect, border_radius=radius)
        pygame.draw.rect(self.canvas, (47, 62, 84), rect, 1, border_radius=radius)

    def _draw_header(self) -> None:
        self._text("Zynq FPGA PQC Secure Handover", (40, 25), "title")
        self._text(
            "ML-KEM session establishment  +  ChaCha20-Poly1305 authenticated data",
            (42, 67), "small", MUTED,
        )
        mode = "MOCK MODE" if self.controller.is_mock else "2-BOARD UART"
        badge_color = (36, 89, 76) if self.controller.is_mock else (35, 73, 128)
        badge = pygame.Rect(1325, 30, 235, 44)
        pygame.draw.rect(self.canvas, badge_color, badge, border_radius=22)
        self._text(mode, badge.center, "small", WHITE, "center")
        self._draw_legend(right=1305, center_y=52)

    def _draw_legend(self, right: int, center_y: int) -> None:
        scale = 0.45
        items = []
        for spec in VEHICLE_KINDS.values():
            surface = self.fonts["xs"].render(spec.title, True, MUTED)
            items.append((spec, surface))
        width = sum(int(s.length_px * scale) + 5 + t.get_width() for s, t in items) + 16 * (len(items) - 1)
        x = right - width
        for spec, surface in items:
            w, h = int(spec.length_px * scale), int(spec.height_px * scale)
            rect = pygame.Rect(x, center_y - h // 2 - 2, w, h)
            self._draw_body(spec.key, rect, 1, LEGEND, scale)
            x += w + 5
            self.canvas.blit(surface, surface.get_rect(midleft=(x, center_y)))
            x += surface.get_width() + 16

    def _draw_road(self) -> None:
        outer = pygame.Rect(40, 100, 1520, 340)
        self._round_panel(outer, PANEL)
        road = pygame.Rect(78, ROAD_TOP, 1444, ROAD_HEIGHT)
        pygame.draw.rect(self.canvas, ROAD, road, border_radius=14)
        pygame.draw.rect(self.canvas, (29, 62, 101), (78, ROAD_TOP, 722, ROAD_HEIGHT), border_radius=14)
        pygame.draw.rect(self.canvas, (101, 60, 28), (800, ROAD_TOP, 722, ROAD_HEIGHT), border_radius=14)
        pygame.draw.rect(self.canvas, ROAD, road, 2, border_radius=14)
        lanes = self.controller.lane_count
        per_dir = self.controller.lanes_per_direction
        lane_h = ROAD_HEIGHT / lanes
        for i in range(1, lanes):
            y = int(ROAD_TOP + lane_h * i)
            if i == per_dir:
                # centre line between the two directions: double solid yellow
                pygame.draw.line(self.canvas, YELLOW, (84, y - 3), (1516, y - 3), 2)
                pygame.draw.line(self.canvas, YELLOW, (84, y + 2), (1516, y + 2), 2)
            else:
                for x in range(95, 1510, 70):
                    pygame.draw.rect(self.canvas, (205, 211, 220), (x, y - 1, 38, 3), border_radius=2)
        pygame.draw.line(self.canvas, YELLOW, (800, 136), (800, 411), 3)
        for y in range(136, 412, 18):
            pygame.draw.line(self.canvas, BG, (800, y), (800, y + 8), 3)
        self._text("CELL A", (98, 118), "sub", BLUE)
        self._text("ZedBoard A", (98, 145), "small", MUTED)
        self._text("CELL B", (1502, 118), "sub", ORANGE, "topright")
        self._text("ZedBoard B", (1502, 145), "small", MUTED, "topright")
        self._text("200 m  HANDOVER BOUNDARY", (800, 414), "xs", YELLOW, "midtop")
        self._draw_antenna((205, 135), BLUE)
        self._draw_antenna((1395, 135), ORANGE)
        self._text("0 m", (78, 390), "xs", MUTED)
        self._text("400 m", (1522, 390), "xs", MUTED, "topright")

        self.vehicle_rects.clear()
        scale = min(1.0, (lane_h - 10) / 34)
        for vehicle in self.controller.vehicles:
            x = 100 + int((vehicle.position_m / ROAD_METERS) * 1400)
            y = int(ROAD_TOP + lane_h * (vehicle.lane + 0.5))
            spec = vehicle.spec
            w, h = int(spec.length_px * scale), int(spec.height_px * scale)
            rect = pygame.Rect(0, 0, w, h)
            rect.center = (x, y)
            self.vehicle_rects[vehicle.vehicle_id] = rect.inflate(6, 6)
            self._draw_vehicle(vehicle, rect, scale)

    def _draw_antenna(self, center: tuple[int, int], color) -> None:
        x, y = center
        pygame.draw.line(self.canvas, color, (x, y + 18), (x, y - 14), 3)
        pygame.draw.circle(self.canvas, color, (x, y - 17), 4)
        for radius in (12, 22):
            arc = pygame.Rect(x - radius, y - 17 - radius, radius * 2, radius * 2)
            pygame.draw.arc(self.canvas, color, arc, math.radians(205), math.radians(335), 2)
        pygame.draw.line(self.canvas, color, (x, y + 18), (x - 13, y + 30), 3)
        pygame.draw.line(self.canvas, color, (x, y + 18), (x + 13, y + 30), 3)

    def _draw_vehicle(self, vehicle: Vehicle, rect: pygame.Rect, scale: float) -> None:
        if vehicle.state in ("connecting", "handover", "exiting"):
            color = GREY
        elif vehicle.board == "A":
            color = BLUE
        elif vehicle.board == "B":
            color = ORANGE
        else:
            color = WHITE
        self._draw_body(vehicle.kind, rect, vehicle.direction, color, scale)
        if vehicle.kind == "bike":
            self._text(vehicle.label, (rect.centerx, rect.y - 2), "xs", WHITE, "midbottom")
        elif vehicle.kind == "truck":
            cargo_x = rect.x + int(rect.width * (0.35 if vehicle.direction > 0 else 0.65))
            self._text(vehicle.label, (cargo_x, rect.centery + 1), "xs", BG, "center")
        else:
            self._text(vehicle.label, (rect.centerx, rect.centery + 1), "xs", BG, "center")
        selected = self.controller.selected_vehicle == vehicle.vehicle_id
        attacked = time.monotonic() < vehicle.attacked_until
        if selected or attacked:
            border = RED if attacked else WHITE
            pygame.draw.rect(self.canvas, border, rect.inflate(10, 10), 3, border_radius=10)
        if vehicle.state == "handover":
            self._text("HANDOVER", (rect.centerx, rect.y - 16), "xs", YELLOW, "center")

    def _draw_body(self, kind: str, rect: pygame.Rect, direction: int, color, scale: float) -> None:
        """Side-view vehicle silhouette; the front faces the travel direction."""
        c = self.canvas
        w, h = rect.width, rect.height

        def part(u0: float, u1: float, v0: float, v1: float) -> pygame.Rect:
            # u: 0 = rear, 1 = front along the length; v: 0 = top, 1 = bottom
            if direction > 0:
                x0, x1 = rect.x + u0 * w, rect.x + u1 * w
            else:
                x0, x1 = rect.right - u1 * w, rect.right - u0 * w
            return pygame.Rect(int(x0), int(rect.y + v0 * h), max(1, int(x1 - x0)), max(1, int((v1 - v0) * h)))

        def px(u: float) -> int:
            return int(rect.x + u * w) if direction > 0 else int(rect.right - u * w)

        def wheels(us, r=None) -> None:
            radius = r or max(3, int(5 * scale))
            for u in us:
                pygame.draw.circle(c, (5, 8, 13), (px(u), rect.bottom), radius)

        rad = max(2, int(7 * scale))
        if kind == "bike":
            r = max(3, int(h * 0.3))
            body = part(0.2, 0.8, 0.35, 0.75)
            pygame.draw.rect(c, color, body, border_radius=3)
            pygame.draw.rect(c, DARK, body, 1, border_radius=3)
            pygame.draw.circle(c, color, (px(0.55), rect.y + int(h * 0.2)), max(3, int(h * 0.2)))
            pygame.draw.line(c, color, (px(0.55), rect.y + int(h * 0.3)), (px(0.8), body.y), 3)
            for u in (0.15, 0.85):
                pygame.draw.circle(c, (5, 8, 13), (px(u), rect.bottom - r + 2), r, 3)
            return
        if kind == "truck":
            cargo = part(0.0, 0.70, 0.0, 1.0)
            cab = part(0.73, 1.0, 0.22, 1.0)
            pygame.draw.rect(c, color, cargo, border_radius=3)
            pygame.draw.rect(c, DARK, cargo, 2, border_radius=3)
            for u in (0.08, 0.62):
                pygame.draw.line(c, DARK, (px(u), cargo.y + 3), (px(u), cargo.bottom - 3), 1)
            pygame.draw.rect(c, color, cab, border_radius=rad)
            pygame.draw.rect(c, DARK, cab, 2, border_radius=rad)
            pygame.draw.rect(c, GLASS, part(0.82, 0.96, 0.32, 0.55), border_radius=2)
            wheels((0.12, 0.30, 0.86))
            return

        pygame.draw.rect(c, color, rect, border_radius=rad)
        pygame.draw.rect(c, DARK, rect, 2, border_radius=rad)
        if kind == "bus":
            for i in range(5):
                u0 = 0.06 + i * 0.145
                pygame.draw.rect(c, GLASS, part(u0, u0 + 0.11, 0.14, 0.42), border_radius=2)
            pygame.draw.rect(c, GLASS, part(0.86, 0.96, 0.14, 0.62), border_radius=2)
            wheels((0.17, 0.82))
        elif kind == "suv":
            pygame.draw.rect(c, GLASS, part(0.22, 0.50, 0.12, 0.40), border_radius=2)
            pygame.draw.rect(c, GLASS, part(0.54, 0.84, 0.12, 0.40), border_radius=2)
            wheels((0.20, 0.80), max(4, int(6 * scale)))
        elif kind == "ambulance":
            pygame.draw.rect(c, WHITE, part(0.0, 1.0, 0.58, 0.74))
            cross = part(0.14, 0.34, 0.12, 0.52)
            cx, cy = cross.center
            arm = max(2, cross.height // 6)
            pygame.draw.rect(c, RED, (cx - arm, cross.y, arm * 2, cross.height))
            pygame.draw.rect(c, RED, (cx - cross.height // 2, cy - arm, cross.height, arm * 2))
            pygame.draw.rect(c, GLASS, part(0.66, 0.90, 0.12, 0.44), border_radius=2)
            blink = int(time.monotonic() * 4) % 2 == 0
            bar = part(0.44, 0.62, -0.18, 0.02)
            half = bar.width // 2
            pygame.draw.rect(c, RED if blink else BLUE, (bar.x, bar.y, half, bar.height), border_radius=2)
            pygame.draw.rect(c, BLUE if blink else RED, (bar.x + half, bar.y, bar.width - half, bar.height), border_radius=2)
            wheels((0.20, 0.80))
        else:  # sedan
            pygame.draw.rect(c, GLASS, part(0.48, 0.84, 0.14, 0.44), border_radius=3)
            wheels((0.22, 0.78))

    def _draw_board_panel(self, name: str, rect: pygame.Rect, accent) -> None:
        self._round_panel(rect)
        worker = self.controller.workers[name]
        stats = worker.stats
        pygame.draw.circle(self.canvas, accent, (rect.x + 25, rect.y + 27), 7)
        self._text(f"BOARD {name}", (rect.x + 42, rect.y + 13), "sub")
        state_text = "ONLINE" if stats.connected and not stats.error else "ERROR"
        state_color = GREEN if state_text == "ONLINE" else RED
        self._text(state_text, (rect.right - 20, rect.y + 18), "xs", state_color, "topright")

        grid_x, grid_y = rect.x + 20, rect.y + 60
        cell, gap = 41, 3
        for slot in range(MAX_SESSIONS):
            row, col = divmod(slot, 8)
            cell_rect = pygame.Rect(
                grid_x + col * (cell + gap), grid_y + row * 23, cell, 20
            )
            vehicle_id = stats.slots[slot]
            fill = accent if vehicle_id is not None else PANEL_2
            pygame.draw.rect(self.canvas, fill, cell_rect, border_radius=4)
            label = str(vehicle_id) if vehicle_id is not None else f"{slot}"
            label_color = BG if vehicle_id is not None else (87, 103, 127)
            self._text(label, cell_rect.center, "xs", label_color, "center")

        sx = rect.x + 386
        self._text("ACTIVE", (sx, grid_y), "xs", MUTED)
        self._text(f"{stats.active_count}/64", (sx, grid_y + 20), "big", accent)
        self._text("PENDING", (sx, grid_y + 77), "xs", MUTED)
        self._text(str(worker.pending_count), (sx, grid_y + 98), "sub")
        self._text("LAST ML-KEM", (sx, grid_y + 137), "xs", MUTED)
        self._text(f"{stats.last_kem_us} us", (sx, grid_y + 158), "body")

        footer_y = rect.bottom - 28
        self._text(f"DATA OK  {stats.data_ok}", (rect.x + 20, footer_y), "xs", GREEN)
        self._text(f"FAIL  {stats.data_fail}", (rect.x + 145, footer_y), "xs", RED)
        self._text(f"BLOCKED  {stats.attacks_blocked}", (rect.x + 245, footer_y), "xs", YELLOW)
        self._text(f"RTT  {stats.last_rtt_ms:.1f} ms", (rect.right - 18, footer_y), "xs", MUTED, "topright")

    def _draw_event_log(self, rect: pygame.Rect) -> None:
        self._round_panel(rect)
        self._text("LIVE EVENT LOG", (rect.x + 22, rect.y + 18), "sub")
        self._text(f"HANDOVERS  {self.controller.handovers}", (rect.right - 20, rect.y + 22), "xs", YELLOW, "topright")
        y = rect.y + 62
        colors = {
            "OPEN": GREEN,
            "HO": YELLOW,
            "LEAVE": MUTED,
            "ATTACK": RED,
            "BLOCKED": GREEN,
            "ERROR": RED,
            "SYSTEM": BLUE,
        }
        for kind, message in self.controller.events:
            color = colors.get(kind, TEXT)
            pygame.draw.circle(self.canvas, color, (rect.x + 18, y + 10), 4)
            clipped = message if len(message) <= 58 else message[:55] + "..."
            self._text(clipped, (rect.x + 31, y), "xs", TEXT)
            y += 26

    def _draw_controls(self, rect: pygame.Rect) -> None:
        self._round_panel(rect)
        selected = self.controller.vehicle_by_id(self.controller.selected_vehicle) \
            if self.controller.selected_vehicle is not None else None
        target = selected.title if selected else "Click a vehicle"
        status = (
            f"{selected.board or '-'} / slot {selected.slot if selected and selected.slot is not None else '-'}"
            if selected else "No target selected"
        )
        self._text("ATTACK TARGET", (rect.x + 22, rect.y + 14), "xs", MUTED)
        self._text(target, (rect.x + 22, rect.y + 35), "sub")
        self._text(status, (rect.x + 270, rect.y + 41), "small", MUTED)

        attack_rect = pygame.Rect(rect.x + 410, rect.y + 17, 210, 48)
        pause_rect = pygame.Rect(rect.x + 640, rect.y + 17, 135, 48)
        quit_rect = pygame.Rect(rect.x + 795, rect.y + 17, 135, 48)
        self.buttons = {"attack": attack_rect, "pause": pause_rect, "quit": quit_rect}
        self._button(attack_rect, "TAMPER DATA", RED)
        self._button(pause_rect, "PAUSE" if self.controller.running else "START", BLUE)
        self._button(quit_rect, "EXIT", GREY)
        self._text(
            f"ATTACKS {self.controller.attack_attempts}   BLOCKED {self.controller.attack_blocked}",
            (rect.x + 410, rect.bottom + 12), "xs", MUTED,
        )
        self._text("Space: pause   T: attack   F11: fullscreen", (rect.right, rect.bottom + 12), "xs", MUTED, "topright")

    def _button(self, rect: pygame.Rect, label: str, color) -> None:
        pygame.draw.rect(self.canvas, color, rect, border_radius=9)
        self._text(label, rect.center, "small", WHITE, "center")

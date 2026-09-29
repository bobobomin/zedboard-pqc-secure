#!/usr/bin/env python3
"""Launch the supplied Pygame UI with fresh ML-KEM sessions on real boards."""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from board_link import BoardWorker, MockBoardLink
from serial_board_v2 import SerialBoardLink
from simulator import DemoController


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Two-ZedBoard PQC handover demonstration")
    parser.add_argument("--mock", action="store_true")
    parser.add_argument("--board-a", metavar="PORT")
    parser.add_argument("--board-b", metavar="PORT")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--vehicles", type=int, default=12)
    parser.add_argument("--speed", type=float, default=25.0, help="metres per second")
    parser.add_argument("--lanes", type=int, default=2, help="lanes per direction (1..3)")
    parser.add_argument("--seed", type=int, default=None, help="fix vehicle mix for rehearsal")
    parser.add_argument("--fullscreen", action="store_true")
    args = parser.parse_args()
    if not args.mock and not (args.board_a and args.board_b):
        parser.error("use --mock or provide both --board-a and --board-b")
    if args.mock and (args.board_a or args.board_b):
        parser.error("--mock cannot be combined with real board ports")
    if not 1 <= args.vehicles <= 64:
        parser.error("--vehicles must be 1..64")
    if not 1 <= args.lanes <= 3:
        parser.error("--lanes must be 1..3")
    return args


def make_workers(args: argparse.Namespace) -> tuple[BoardWorker, BoardWorker]:
    if args.mock:
        return BoardWorker(MockBoardLink("A", 1101)), BoardWorker(MockBoardLink("B", 2202))
    unused = Path(__file__).resolve().parent
    board_a = BoardWorker(SerialBoardLink("A", args.board_a, args.baud, unused))
    try:
        board_b = BoardWorker(SerialBoardLink("B", args.board_b, args.baud, unused))
    except Exception:
        board_a.stop()
        raise
    return board_a, board_b


def main() -> int:
    args = parse_args()
    try:
        import pygame
        from ui import DemoUI
    except ImportError as exc:
        print("Missing dependencies. Run: py -m pip install -r requirements.txt", file=sys.stderr)
        raise SystemExit(2) from exc
    board_a = board_b = controller = ui = None
    try:
        board_a, board_b = make_workers(args)
        controller = DemoController(
            board_a, board_b, args.vehicles, args.speed, args.lanes, args.seed
        )
        ui = DemoUI(controller, fullscreen=args.fullscreen)
        clock = pygame.time.Clock()
        while True:
            dt = clock.tick(60) / 1000.0
            if any(ui.handle_event(event) == "quit" for event in pygame.event.get()):
                return 0
            controller.update(dt)
            ui.draw()
    finally:
        if ui is not None:
            ui.close()
        if controller is not None:
            controller.shutdown()
        else:
            for worker in (board_a, board_b):
                if worker is not None:
                    worker.stop()


if __name__ == "__main__":
    raise SystemExit(main())

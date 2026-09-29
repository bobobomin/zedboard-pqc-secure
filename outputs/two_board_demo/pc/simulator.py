"""Vehicle motion and make-before-break handover state machine."""

from __future__ import annotations

import itertools
import random
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional

from board_link import BoardCommand, BoardResult, BoardWorker, MAX_SESSIONS

ROAD_METERS = 400.0
BOUNDARY_METERS = 200.0
ROAD_PIXELS = 1400.0                  # must match the road width drawn in ui.py
PX_PER_METER = ROAD_PIXELS / ROAD_METERS
MIN_GAP_METERS = 3.0                  # bumper-to-bumper gap kept in the same lane
MAX_LANES_PER_DIRECTION = 3
DEFAULT_PS_MLKEM_US = 1258.523        # measured Cortex-A9 software ML-KEM baseline
KEM_HISTORY = 120                     # samples kept for the live chart
KEM_RATE_WINDOW_S = 10.0
SWKEM_INTERVAL_S = 2.0                # per board: one PS software ML-KEM timing


@dataclass(frozen=True)
class VehicleKind:
    key: str
    title: str
    length_px: int      # drawn length at scale 1.0
    height_px: int      # drawn height at scale 1.0
    speed_factor: float
    weight: int         # relative spawn probability


VEHICLE_KINDS: dict[str, VehicleKind] = {
    "sedan": VehicleKind("sedan", "Sedan", 50, 28, 1.00, 34),
    "suv": VehicleKind("suv", "SUV", 54, 32, 0.95, 20),
    "truck": VehicleKind("truck", "Truck", 80, 34, 0.75, 12),
    "bus": VehicleKind("bus", "Bus", 92, 34, 0.70, 10),
    "bike": VehicleKind("bike", "Bike", 32, 24, 1.15, 14),
    "ambulance": VehicleKind("ambulance", "Ambulance", 58, 32, 1.25, 10),
}


@dataclass
class Vehicle:
    vehicle_id: int
    lane: int
    direction: int
    position_m: float
    speed_mps: float
    kind: str = "sedan"
    board: Optional[str] = None
    slot: Optional[int] = None
    state: str = "connecting"
    target_board: Optional[str] = None
    old_board: Optional[str] = None
    old_slot: Optional[int] = None
    next_data_at: float = 0.0
    retry_at: float = 0.0
    attacked_until: float = 0.0
    retry_target: Optional[str] = None

    @property
    def label(self) -> str:
        return str(self.vehicle_id)

    @property
    def spec(self) -> VehicleKind:
        return VEHICLE_KINDS[self.kind]

    @property
    def title(self) -> str:
        return f"{self.spec.title} {self.vehicle_id}"


class DemoController:
    def __init__(
        self,
        board_a: BoardWorker,
        board_b: BoardWorker,
        vehicle_count: int = 16,
        speed_mps: float = 40.0,
        lanes_per_direction: int = 2,
        seed: Optional[int] = None,
        ps_kem_us: float = DEFAULT_PS_MLKEM_US,
    ):
        if vehicle_count not in range(1, MAX_SESSIONS + 1):
            raise ValueError("vehicle count must be 1..64")
        if lanes_per_direction not in range(1, MAX_LANES_PER_DIRECTION + 1):
            raise ValueError(f"lanes per direction must be 1..{MAX_LANES_PER_DIRECTION}")
        if ps_kem_us <= 0:
            raise ValueError("PS ML-KEM baseline must be positive")
        self.workers = {"A": board_a, "B": board_b}
        self.ps_kem_ref_us = ps_kem_us    # used until the boards report live SW timings
        # (monotonic time, board, kem_us, reason) for every completed ML-KEM session setup
        self.kem_history: deque[tuple[float, str, int, str]] = deque(maxlen=KEM_HISTORY)
        # (monotonic time, board, sw_us) for every live PS software ML-KEM timing
        self.sw_history: deque[tuple[float, str, int]] = deque(maxlen=KEM_HISTORY)
        self._next_swkem = {"A": 0.0, "B": 1.0}
        self.vehicle_count = vehicle_count
        self.speed_mps = speed_mps
        self.lanes_per_direction = lanes_per_direction
        self._rng = random.Random(seed)
        self.running = True
        self.sim_time = 0.0
        self.handovers = 0
        self.attack_attempts = 0
        self.attack_blocked = 0
        self.selected_vehicle: Optional[int] = None
        self.events: deque[tuple[str, str]] = deque(maxlen=12)
        self._command_ids = itertools.count(1)
        self._next_vehicle_id = vehicle_count
        self._pending: dict[int, tuple[str, int, dict]] = {}
        self._reserved = {"A": set(), "B": set()}
        self.vehicles = self._make_initial_vehicles(vehicle_count)
        self.log("SYSTEM", "Simulation ready" if self.is_mock else "Boards connected")
        for vehicle in self.vehicles:
            self._request_open(vehicle, self._board_for_position(vehicle.position_m), "entry")

    @property
    def is_mock(self) -> bool:
        return self.workers["A"].board.__class__.__name__.startswith("Mock")

    @property
    def lane_count(self) -> int:
        return self.lanes_per_direction * 2

    # ------------------------------------------------------------------ ML-KEM analysis

    @property
    def kem_samples(self) -> int:
        return sum(w.stats.kem_samples for w in self.workers.values())

    @property
    def average_pl_kem_us(self) -> float:
        samples = self.kem_samples
        if samples == 0:
            return 0.0
        return sum(w.stats.kem_total_us for w in self.workers.values()) / samples

    @property
    def sw_samples(self) -> int:
        return sum(w.stats.sw_samples for w in self.workers.values())

    @property
    def sw_live(self) -> bool:
        return self.sw_samples > 0

    @property
    def ps_kem_us(self) -> float:
        """PS software ML-KEM time: live average if measured, else the reference."""
        samples = self.sw_samples
        if samples == 0:
            return self.ps_kem_ref_us
        return sum(w.stats.sw_total_us for w in self.workers.values()) / samples

    @property
    def mlkem_speedup(self) -> float:
        average = self.average_pl_kem_us
        return self.ps_kem_us / average if average > 0 else 0.0

    @property
    def kem_min_max(self) -> tuple[int, int]:
        stats = [w.stats for w in self.workers.values() if w.stats.kem_samples]
        if not stats:
            return 0, 0
        return min(s.kem_min_us for s in stats), max(s.kem_max_us for s in stats)

    @property
    def kem_rate_per_s(self) -> float:
        """ML-KEM session setups completed per second over the recent window."""
        cutoff = time.monotonic() - KEM_RATE_WINDOW_S
        recent = sum(1 for t, *_ in self.kem_history if t >= cutoff)
        return recent / KEM_RATE_WINDOW_S

    @property
    def recent_jitter_us(self) -> float:
        """Standard deviation of the samples currently shown on the chart."""
        values = [k for _, _, k, _ in self.kem_history]
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        return (sum((v - mean) ** 2 for v in values) / (len(values) - 1)) ** 0.5

    # ------------------------------------------------------------------ setup

    def lanes_for(self, direction: int) -> list[int]:
        """Lanes 0..L-1 move right (+1), lanes L..2L-1 move left (-1)."""
        n = self.lanes_per_direction
        return list(range(n)) if direction > 0 else list(range(n, 2 * n))

    def _random_kind(self) -> str:
        kinds = list(VEHICLE_KINDS.values())
        return self._rng.choices(kinds, weights=[k.weight for k in kinds])[0].key

    def _speed_for(self, kind: str) -> float:
        return self.speed_mps * VEHICLE_KINDS[kind].speed_factor * self._rng.uniform(0.92, 1.08)

    def _make_initial_vehicles(self, count: int) -> list[Vehicle]:
        vehicles = []
        lanes_n = self.lanes_per_direction
        for direction, total, id_offset in ((1, (count + 1) // 2, 0), (-1, count // 2, 1)):
            lanes = self.lanes_for(direction)
            per_lane: dict[int, int] = {lane: 0 for lane in lanes}
            assignment = []
            for index in range(total):
                lane = lanes[index % lanes_n]
                assignment.append((index, lane, per_lane[lane]))
                per_lane[lane] += 1
            for index, lane, order in assignment:
                in_lane = per_lane[lane]
                lane_pos = lanes.index(lane)
                # Stagger lanes so vehicles do not line up in columns.
                position = (order + (lane_pos + 1) / (lanes_n + 1)) * ROAD_METERS / in_lane
                if direction < 0:
                    position = ROAD_METERS - position
                kind = self._random_kind()
                vehicles.append(Vehicle(
                    index * 2 + id_offset, lane, direction, position,
                    self._speed_for(kind), kind,
                ))
        return vehicles

    # ------------------------------------------------------------------ public

    def log(self, kind: str, message: str) -> None:
        stamp = f"{self.sim_time:05.1f}s"
        self.events.appendleft((kind, f"{stamp}  [{kind}] {message}"))

    def vehicle_by_id(self, vehicle_id: int) -> Optional[Vehicle]:
        return next((v for v in self.vehicles if v.vehicle_id == vehicle_id), None)

    def toggle_running(self) -> None:
        self.running = not self.running
        self.log("SYSTEM", "Simulation resumed" if self.running else "Simulation paused")

    def select_vehicle(self, vehicle_id: Optional[int]) -> None:
        self.selected_vehicle = vehicle_id

    def attack_selected(self) -> bool:
        if self.selected_vehicle is None:
            self.log("ERROR", "Select a connected vehicle first")
            return False
        vehicle = self.vehicle_by_id(self.selected_vehicle)
        if vehicle is None or vehicle.board is None or vehicle.slot is None:
            self.log("ERROR", "Selected vehicle has no active session")
            return False
        if vehicle.state not in ("connected", "handover"):
            self.log("ERROR", f"{vehicle.title} is busy")
            return False
        if any(meta[1] == vehicle.vehicle_id and meta[0] == "data" for meta in self._pending.values()):
            self.log("ERROR", f"{vehicle.title} already has pending DATA")
            return False
        self.attack_attempts += 1
        vehicle.attacked_until = time.monotonic() + 1.5
        payload = f"{vehicle.kind}-{vehicle.vehicle_id} telemetry".encode("ascii")
        self._submit(
            vehicle.board,
            "data",
            vehicle.vehicle_id,
            vehicle.slot,
            payload,
            tamper=True,
            context={"attack": True},
        )
        self.log("ATTACK", f"{vehicle.title}: ciphertext bit flipped")
        return True

    # ------------------------------------------------------------------ motion

    def update(self, dt: float) -> None:
        self._collect_results()
        if not self.running:
            return
        dt = min(dt, 0.1)
        self.sim_time += dt
        now = time.monotonic()
        self._schedule_swkem(now)
        # Front-most vehicles first, so each follower sees its leader's new position.
        order = sorted(self.vehicles, key=lambda v: -v.direction * v.position_m)
        for vehicle in order:
            self._step_vehicle(vehicle, dt, now)

    def _schedule_swkem(self, now: float) -> None:
        for name, worker in self.workers.items():
            if worker.stats.sw_supported is False or now < self._next_swkem[name]:
                continue
            if any(kind == "swkem" and ctx.get("board") == name
                   for kind, _, ctx in self._pending.values()):
                continue
            self._submit(name, "swkem", -1, None, context={"board": name})
            self._next_swkem[name] = now + SWKEM_INTERVAL_S

    def _leader_of(self, vehicle: Vehicle) -> Optional[Vehicle]:
        best, best_dist = None, None
        for other in self.vehicles:
            if other is vehicle or other.lane != vehicle.lane:
                continue
            ahead = (other.position_m - vehicle.position_m) * vehicle.direction
            if ahead <= 0:
                continue
            if best_dist is None or ahead < best_dist:
                best, best_dist = other, ahead
        return best

    @staticmethod
    def _gap_m(leader: Vehicle, follower: Vehicle) -> float:
        half_lengths = (leader.spec.length_px + follower.spec.length_px) / 2
        return half_lengths / PX_PER_METER + MIN_GAP_METERS

    def _step_vehicle(self, vehicle: Vehicle, dt: float, now: float) -> None:
        if vehicle.state in ("connecting", "handover", "exiting"):
            return
        if vehicle.retry_at and now >= vehicle.retry_at:
            vehicle.retry_at = 0.0
            target = vehicle.retry_target or self._board_for_position(vehicle.position_m)
            vehicle.retry_target = None
            self._request_open(vehicle, target, "retry")
            return

        previous = vehicle.position_m
        step = vehicle.speed_mps * dt
        leader = self._leader_of(vehicle)
        if leader is not None:
            room = abs(leader.position_m - vehicle.position_m) - self._gap_m(leader, vehicle)
            step = max(0.0, min(step, room))
        vehicle.position_m += vehicle.direction * step

        crossed = (
            vehicle.direction > 0
            and previous < BOUNDARY_METERS <= vehicle.position_m
        ) or (
            vehicle.direction < 0
            and previous > BOUNDARY_METERS >= vehicle.position_m
        )
        if crossed and vehicle.board is not None:
            vehicle.position_m = BOUNDARY_METERS
            target = "B" if vehicle.direction > 0 else "A"
            if target != vehicle.board:
                self._request_open(vehicle, target, "handover")
                return

        if vehicle.position_m < 0.0 or vehicle.position_m > ROAD_METERS:
            vehicle.position_m = max(0.0, min(ROAD_METERS, vehicle.position_m))
            self._request_exit(vehicle)
            return

        if (
            vehicle.board is not None
            and vehicle.slot is not None
            and now >= vehicle.next_data_at
            and not any(
                kind == "data" and vid == vehicle.vehicle_id
                for kind, vid, _ in self._pending.values()
            )
        ):
            payload = f"{vehicle.kind}-{vehicle.vehicle_id} pos-{vehicle.position_m:.0f}m".encode("ascii")
            self._submit(
                vehicle.board, "data", vehicle.vehicle_id,
                vehicle.slot, payload, context={"attack": False}
            )
            vehicle.next_data_at = now + 3.0 + (vehicle.vehicle_id % 5) * 0.12

    # ------------------------------------------------------------------ sessions

    def _board_for_position(self, position_m: float) -> str:
        return "A" if position_m < BOUNDARY_METERS else "B"

    def _free_slot(self, board: str) -> Optional[int]:
        occupied = self.workers[board].stats.slots
        return next(
            (
                slot for slot in range(MAX_SESSIONS)
                if occupied[slot] is None and slot not in self._reserved[board]
            ),
            None,
        )

    def _request_open(self, vehicle: Vehicle, target: str, reason: str) -> None:
        slot = self._free_slot(target)
        if slot is None:
            vehicle.state = "disconnected"
            vehicle.retry_at = time.monotonic() + 1.0
            self.log("ERROR", f"Board {target} full; {vehicle.title} waits")
            return
        self._reserved[target].add(slot)
        vehicle.target_board = target
        vehicle.old_board = vehicle.board
        vehicle.old_slot = vehicle.slot
        vehicle.state = "handover" if reason == "handover" else "connecting"
        self._submit(
            target, "open", vehicle.vehicle_id, slot,
            context={"reason": reason, "target": target},
        )
        if reason == "handover":
            self.log("HO", f"{vehicle.title} {vehicle.board}->{target}: ML-KEM opening")
        else:
            self.log("OPEN", f"{vehicle.title} requests board {target}, slot {slot}")

    def _request_exit(self, vehicle: Vehicle) -> None:
        if vehicle.board is None or vehicle.slot is None:
            self._respawn(vehicle)
            return
        vehicle.state = "exiting"
        self._submit(
            vehicle.board, "leave", vehicle.vehicle_id, vehicle.slot,
            context={"reason": "exit"},
        )

    def _submit(
        self,
        board: str,
        kind: str,
        vehicle_id: int,
        slot: Optional[int],
        payload: bytes = b"",
        tamper: bool = False,
        context: Optional[dict] = None,
    ) -> None:
        command_id = next(self._command_ids)
        command = BoardCommand(
            command_id, kind, vehicle_id, slot, payload, tamper
        )
        self._pending[command_id] = (kind, vehicle_id, context or {})
        self.workers[board].submit(command)

    def _collect_results(self) -> None:
        for worker in self.workers.values():
            for result in worker.poll():
                pending = self._pending.pop(result.command_id, None)
                if pending is None:
                    continue
                kind, vehicle_id, context = pending
                if kind == "swkem":
                    self._handle_swkem(result)
                    continue
                vehicle = self.vehicle_by_id(vehicle_id)
                if kind == "open" and result.slot is not None:
                    self._reserved[result.board].discard(result.slot)
                if vehicle is None:
                    continue
                if not result.ok and not result.blocked:
                    self._handle_error(vehicle, result, context)
                elif kind == "open":
                    self._handle_open(vehicle, result, context)
                elif kind == "leave":
                    self._handle_leave(vehicle, result, context)
                elif kind == "data":
                    self._handle_data(vehicle, result, context)

    def _handle_swkem(self, result: BoardResult) -> None:
        if result.sw_us:
            self.sw_history.append((time.monotonic(), result.board, result.sw_us))
            if not result.ok:
                self.log("ERROR", f"Board {result.board} SW ML-KEM secret mismatch")
        elif not self.is_mock:
            self.log("SYSTEM", f"Board {result.board}: no SWKEM in firmware, PS SW = reference")

    def _handle_open(self, vehicle: Vehicle, result: BoardResult, context: dict) -> None:
        old_board, old_slot = vehicle.old_board, vehicle.old_slot
        vehicle.board = result.board
        vehicle.slot = result.slot
        vehicle.target_board = None
        vehicle.state = "connected"
        vehicle.next_data_at = time.monotonic() + 0.4
        reason = context.get("reason")
        if result.session is not None:
            self.kem_history.append(
                (time.monotonic(), result.board, result.session.kem_us, reason or "entry")
            )
        if reason == "handover":
            self.handovers += 1
            self.log(
                "HO",
                f"{vehicle.title} READY on {result.board}/{result.slot}; switching",
            )
            if old_board is not None and old_slot is not None:
                self._submit(
                    old_board, "leave", vehicle.vehicle_id, old_slot,
                    context={"reason": "handover_old"},
                )
        else:
            kem = result.session.kem_us if result.session else 0
            self.log(
                "OPEN",
                f"{vehicle.title} connected {result.board}/{result.slot} ({kem} us)",
            )
        vehicle.old_board = None
        vehicle.old_slot = None

    def _handle_leave(self, vehicle: Vehicle, result: BoardResult, context: dict) -> None:
        reason = context.get("reason")
        if reason == "exit":
            self.log("LEAVE", f"{vehicle.title} left board {result.board}")
            self._respawn(vehicle)
        else:
            self.log("LEAVE", f"{vehicle.title} released {result.board}/{result.slot}")

    def _handle_data(self, vehicle: Vehicle, result: BoardResult, context: dict) -> None:
        if context.get("attack"):
            if result.blocked:
                self.attack_blocked += 1
                self.log(
                    "BLOCKED",
                    f"Board {result.board} rejected {vehicle.title} (ERR AUTH)",
                )
            else:
                self.log("ERROR", f"Attack on {vehicle.title} was not rejected")

    def _handle_error(self, vehicle: Vehicle, result: BoardResult, context: dict) -> None:
        self.log(
            "ERROR",
            f"Board {result.board} {result.kind} {vehicle.title}: {result.detail}",
        )
        if result.kind == "open":
            vehicle.state = "connected" if vehicle.old_board else "disconnected"
            if vehicle.old_board:
                vehicle.board = vehicle.old_board
                vehicle.slot = vehicle.old_slot
                offset = -0.5 if vehicle.direction > 0 else 0.5
                vehicle.position_m = BOUNDARY_METERS + offset
            vehicle.retry_at = time.monotonic() + 1.0
            vehicle.retry_target = context.get("target", result.board)
            vehicle.target_board = None
            vehicle.old_board = None
            vehicle.old_slot = None
        elif result.kind == "leave" and context.get("reason") == "exit":
            self._respawn(vehicle)

    def _entry_lane(self, direction: int, entry_m: float) -> int:
        """Pick the lane whose nearest vehicle is farthest from the entry point."""
        best_lane, best_room = None, -1.0
        for lane in self.lanes_for(direction):
            room = min(
                (abs(v.position_m - entry_m) for v in self.vehicles if v.lane == lane),
                default=ROAD_METERS,
            )
            if room > best_room:
                best_lane, best_room = lane, room
        return best_lane

    def _respawn(self, vehicle: Vehicle) -> None:
        used_ids = {v.vehicle_id for v in self.vehicles if v is not vehicle}
        while self._next_vehicle_id in used_ids:
            self._next_vehicle_id = (self._next_vehicle_id + 1) % MAX_SESSIONS
        vehicle.vehicle_id = self._next_vehicle_id
        self._next_vehicle_id = (self._next_vehicle_id + 1) % MAX_SESSIONS
        entry = 0.0 if vehicle.direction > 0 else ROAD_METERS
        vehicle.position_m = ROAD_METERS * 2  # park off-road while choosing a lane
        vehicle.lane = self._entry_lane(vehicle.direction, entry)
        vehicle.position_m = entry
        vehicle.kind = self._random_kind()
        vehicle.speed_mps = self._speed_for(vehicle.kind)
        vehicle.board = None
        vehicle.slot = None
        vehicle.old_board = None
        vehicle.old_slot = None
        vehicle.state = "connecting"
        vehicle.retry_at = 0.0
        vehicle.retry_target = None
        if self.selected_vehicle not in {v.vehicle_id for v in self.vehicles}:
            self.selected_vehicle = None
        self._request_open(vehicle, "A" if vehicle.direction > 0 else "B", "entry")

    def shutdown(self) -> None:
        for worker in self.workers.values():
            worker.stop()

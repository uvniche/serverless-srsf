from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class Detection:
    anomalous: bool
    proposed_action: str | None
    mean: float
    standard_deviation: float
    consecutive: int


class FrozenEWMA:
    """EWMA rate detector that freezes learning while observations are anomalous."""

    def __init__(self, alpha: float = 0.2, deviations: float = 4.0, confirmations: int = 3):
        if not 0 < alpha <= 1 or deviations <= 0 or confirmations < 1:
            raise ValueError("invalid detector parameters")
        self.alpha = alpha
        self.deviations = deviations
        self.confirmations = confirmations
        self.mean: float | None = None
        self.variance = 0.0
        self.consecutive = 0

    def observe(self, value: float) -> Detection:
        if value < 0:
            raise ValueError("rate cannot be negative")
        if self.mean is None:
            self.mean = value
            return Detection(False, None, value, 0.0, 0)
        sd = math.sqrt(max(self.variance, 0.0))
        threshold = self.mean + self.deviations * max(sd, 1.0)
        candidate = value > threshold
        if candidate:
            self.consecutive += 1
            # Deliberately do not update the baseline here.
        else:
            delta = value - self.mean
            self.mean += self.alpha * delta
            self.variance = (1 - self.alpha) * (self.variance + self.alpha * delta * delta)
            self.consecutive = 0
        anomalous = self.consecutive >= self.confirmations
        return Detection(
            anomalous,
            "page-on-call-and-propose-function-throttle" if anomalous else None,
            self.mean,
            math.sqrt(max(self.variance, 0.0)),
            self.consecutive,
        )


def unit_cost(request_price: float, gb_second_price: float, memory_gb: float, duration_s: float) -> float:
    return request_price + gb_second_price * memory_gb * duration_s


def burn_rate(observed_spend: float, expected_spend: float) -> float:
    if expected_spend <= 0:
        raise ValueError("expected spend must be positive")
    return observed_spend / expected_spend


BURN_WINDOWS = (
    ("5m/1m", 14.4, "page", "propose-throttle"),
    ("30m/5m", 6.0, "page", "investigate"),
    ("6h/30m", 3.0, "ticket", "same-day"),
    ("3d/6h", 1.5, "ticket", "review-baseline"),
)


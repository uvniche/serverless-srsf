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

    def __init__(self, alpha: float = 0.2, deviations: float = 4.0, confirmations: int = 3, noise_floor: float = 1.0):
        if not 0 < alpha <= 1 or deviations <= 0 or confirmations < 1 or noise_floor <= 0:
            raise ValueError("invalid detector parameters")
        self.noise_floor = noise_floor
        self.alpha = alpha
        self.deviations = deviations
        self.confirmations = confirmations
        self.mean: float | None = None
        self.variance = 0.0
        self.consecutive = 0

    def observe(self, value: float) -> Detection:
        if not math.isfinite(value) or value < 0:
            raise ValueError("rate must be finite and nonnegative")
        if self.mean is None:
            self.mean = value
            return Detection(False, None, value, 0.0, 0)
        sd = math.sqrt(max(self.variance, 0.0))
        threshold = self.mean + self.deviations * max(sd, self.noise_floor)
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



def spending_summary(observed: float, expected: float, monthly_baseline: float,
                     tolerance: float = .30) -> dict[str, float | bool | None]:
    """Keep total expenditure and excess allowance denominators separate."""
    values = (observed, expected, monthly_baseline, tolerance)
    if any(not math.isfinite(v) or v < 0 for v in values) or monthly_baseline == 0:
        raise ValueError("finite nonnegative costs and positive monthly baseline required")
    excess = max(0, observed - expected)
    cap = (1 + tolerance) * monthly_baseline
    allowance = tolerance * monthly_baseline
    return {"observed": observed, "expected": expected, "excess": excess,
            "spend_multiplier": observed / expected if expected else None,
            "unexpected_activity": expected == 0 and observed > 0,
            "monthly_baseline": monthly_baseline, "total_cap": cap,
            "excess_allowance": allowance, "total_percent_of_baseline": 100 * observed / monthly_baseline,
            "excess_percent_of_baseline": 100 * excess / monthly_baseline,
            "total_percent_of_cap": 100 * observed / cap,
            "excess_percent_of_allowance": 100 * excess / allowance if allowance else None}


def multi_window_alerts(windows: dict[str, tuple[float, float]]) -> list[dict[str, object]]:
    """Input spend must include measured downstream costs for the declared scope.

    Each window contains (observed, expected) spend; both windows must breach.
    """
    findings = []
    for pair, threshold, action, response in BURN_WINDOWS:
        names = pair.split('/')
        if any(name not in windows for name in names):
            continue
        multipliers = []
        for name in names:
            observed, expected = windows[name]
            if any(not math.isfinite(x) or x < 0 for x in (observed, expected)):
                raise ValueError("invalid spending window")
            if expected == 0:
                if observed > 0:
                    findings.append({"window": name, "action": "unexpected-activity", "multiplier": None})
                break
            multipliers.append(observed / expected)
        if len(multipliers) == 2 and all(value > threshold for value in multipliers):
            findings.append({"windows": pair, "threshold": threshold, "action": action, "response": response})
    return findings

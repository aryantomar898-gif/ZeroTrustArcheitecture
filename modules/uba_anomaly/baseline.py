"""
S5: Statistical baseline modeling.
Updates user behavior baselines using Exponential Moving Average (EMA).
"""

from __future__ import annotations

import math
from typing import Any

from sentinelcommand.core.models import UBABaseline


class BaselineModel:
    """Updates baseline statistics using Exponential Moving Average (EMA)."""
    
    def __init__(self, alpha: float = 0.1):
        """
        alpha: Smoothing factor (0 < alpha <= 1).
        Smaller alpha = longer memory (slow adapting).
        Larger alpha = shorter memory (fast adapting).
        """
        self.alpha = alpha

    def update_continuous(self, old_avg: float, old_var: float, new_value: float) -> tuple[float, float, float]:
        """
        Update a continuous variable (like login hour or file count).
        Returns (new_avg, new_var, new_std).
        """
        # EMA for mean
        new_avg = (self.alpha * new_value) + ((1 - self.alpha) * old_avg)
        
        # EMA for variance
        diff = new_value - old_avg
        new_var = (1 - self.alpha) * (old_var + self.alpha * diff**2)
        
        # New standard deviation
        new_std = math.sqrt(new_var) if new_var > 0 else 0.0
        
        return new_avg, new_var, new_std

    def update_categorical(self, old_freqs: dict[str, int], new_category: str, max_items: int = 10) -> list[str]:
        """
        Update a categorical frequency map and return the top N categories.
        """
        old_freqs[new_category] = old_freqs.get(new_category, 0) + 1
        
        # Sort by frequency descending
        sorted_cats = sorted(old_freqs.items(), key=lambda x: x[1], reverse=True)
        
        # Return top N as a list
        return [cat for cat, _ in sorted_cats[:max_items]]

    def apply_to_model(self, baseline: UBABaseline, login_hour: float | None = None, file_count: float | None = None):
        """Update a UBABaseline SQLAlchemy model."""
        if login_hour is not None:
            old_var = baseline.std_login_hour ** 2
            new_avg, _, new_std = self.update_continuous(baseline.avg_login_hour, old_var, login_hour)
            baseline.avg_login_hour = new_avg
            baseline.std_login_hour = new_std
            
        if file_count is not None:
            old_var = baseline.std_file_access_count ** 2
            new_avg, _, new_std = self.update_continuous(baseline.avg_file_access_count, old_var, file_count)
            baseline.avg_file_access_count = new_avg
            baseline.std_file_access_count = new_std
            
        baseline.event_count += 1

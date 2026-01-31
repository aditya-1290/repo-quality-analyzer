from statistics import mean, median
from .models import LOCAggregate

def compute_statistics(agg: LOCAggregate) -> dict:
    if not agg.files:
        return {}

    totals = [f.total_lines for f in agg.files]
    codes = [f.code_lines for f in agg.files]

    return {
        "mean_total_lines": mean(totals),
        "median_total_lines": median(totals),
        "mean_code_lines": mean(codes),
        "median_code_lines": median(codes),
    }

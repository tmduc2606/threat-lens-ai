from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable
from collections.abc import Iterable

import numpy as np
import pandas as pd

DATA_COLUMNS = {
    "Created", "Modified", "dateAdded", "dueDate", "Creation_Date",
    "Last_Update_Date", "Last_Analysis_Date"
}

def load_csv(path: str | Path) -> pd.DataFrame:
    return pd.read_csv(path)

def standardize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [c.strip().replace(" ", "_") for c in df.columns]
    return df

def safe_to_datetime(series: pd.Series) -> pd.Series:
    """
    Robust datetime parser for mixed cybersecurity datasets.

    Handles:
    - ISO timestamps
    - Unix timestamps
    - Mixed formats
    - Unknown values
    - Timezone normalization
    """

    import pandas as pd
    import numpy as np

    # Normalize common invalid values
    series = series.replace(
        ["Unknown", "unknown", "", "None", "nan"],
        np.nan
    )

    # Detect numeric timestamps
    numeric = pd.to_numeric(series, errors="coerce")

    # Heuristic: Unix timestamps
    is_unix = numeric.notna() & (numeric > 1e9)

    result = pd.Series(index=series.index, dtype="datetime64[ns, UTC]")

    # Parse unix timestamps
    result.loc[is_unix] = pd.to_datetime(
        numeric[is_unix],
        unit="s",
        errors="coerce",
        utc=True
    )

    # Parse standard date strings
    result.loc[~is_unix] = pd.to_datetime(
        series[~is_unix],
        errors="coerce",
        utc=True
    )

    # Convert everything to timezone-naive consistently
    result = result.dt.tz_localize(None)

    return result

def normalize_text(value: object) -> str:
    """
    Normalize mixed cybersecurity text fields safely.

    Handles:
    - NaN / None
    - lists
    - numpy arrays
    - dicts
    - regular strings
    """

    import numpy as np
    import pandas as pd
    import re

    # Missing values
    if value is None:
        return ""

    if isinstance(value, float) and pd.isna(value):
        return ""

    # Nested structures
    if isinstance(value, (list, tuple, set)):
        value = ", ".join(map(str, value))

    elif isinstance(value, np.ndarray):
        value = ", ".join(map(str, value.tolist()))

    elif isinstance(value, dict):
        value = " ".join(f"{k}:{v}" for k, v in value.items())

    # Normalize text
    text = str(value).lower().strip()

    text = re.sub(r"\s+", " ", text)

    text = re.sub(r"[^\w\s\-.,:/]", "", text)

    return text


def split_multi_value(value, sep=",") -> list[str]:

    if value is None:
        return []

    if isinstance(value, float) and pd.isna(value):
        return []

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return []

        return [x.strip() for x in value.split(sep) if x.strip()]

    if isinstance(value, np.ndarray):
        value = value.tolist()

    if isinstance(value, Iterable):
        return [str(x).strip() for x in value if str(x).strip()]

    return [str(value).strip()]

def truncate_tags(tag_str, max_tags=10):
    tags = split_multi_value(tag_str)
    return ", ".join(tags[:max_tags])

def make_hashable(value):
    """
    Convert nested Python objects into hashable forms
    for nunique(), drop_duplicates(), parquet stability.
    """

    import numpy as np

    if isinstance(value, list):
        return tuple(value)

    if isinstance(value, np.ndarray):
        return tuple(value.tolist())

    if isinstance(value, dict):
        return tuple(sorted(value.items()))

    return value


def safe_ratio(a: pd.Series, b: pd.Series) -> pd.Series:
    a = pd.to_numeric(a, errors="coerce")
    b = pd.to_numeric(b, errors="coerce")
    return np.where(b.fillna(0) == 0, 0, a / b)


def binary_from_text(series: pd.Series, pattern: str) -> pd.Series:
    return series.fillna("").astype(str).str.contains(pattern, case=False, regex=True).astype(int)
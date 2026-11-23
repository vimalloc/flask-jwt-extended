from datetime import timedelta
from typing import Literal

ExpiresDelta = Literal[False] | timedelta
Fresh = bool | float | timedelta

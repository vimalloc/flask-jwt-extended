from datetime import timedelta
from typing import Literal
from typing import Union

ExpiresDelta = Union[Literal[False], timedelta]
Fresh = Union[bool, float, timedelta]

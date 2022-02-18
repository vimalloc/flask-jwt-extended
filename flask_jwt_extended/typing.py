import sys
from typing import Any
from typing import Union

if sys.version_info >= (3, 8):
    from typing import Literal  # pragma: no cover
else:
    from typing_extensions import Literal  # pragma: no cover

ExpiresDelta = Union[Literal[False], Any]

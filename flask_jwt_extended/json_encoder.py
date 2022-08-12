import json
from typing import Any


try:
    # Flask 2.2 deprecated the flask.json.JSONEncoder (see below), lets recreate
    # a class with the same semantics as the old JSONEncoder.

    from flask.json.provider import DefaultJSONProvider

    class JSONEncoder(json.JSONEncoder):
        """The default JSON encoder. Handles extra types compared to the
        built-in :class:`json.JSONEncoder`.

        -   :class:`datetime.datetime` and :class:`datetime.date` are
            serialized to :rfc:`822` strings. This is the same as the HTTP
            date format.
        -   :class:`decimal.Decimal` is serialized to a string.
        -   :class:`uuid.UUID` is serialized to a string.
        -   :class:`dataclasses.dataclass` is passed to
            :func:`dataclasses.asdict`.
        -   :class:`~markupsafe.Markup` (or any object with a ``__html__``
            method) will call the ``__html__`` method to get a string.

        """

        def default(self, o: Any) -> Any:
            """Convert ``o`` to a JSON serializable type. See
            :meth:`json.JSONEncoder.default`. Python does not support
            overriding how basic types like ``str`` or ``list`` are
            serialized, they are handled before this method.
            """
            return DefaultJSONProvider.default(o)

except ModuleNotFoundError:  # pragma: no cover
    from flask.json import JSONEncoder  # type: ignore  # noqa: F401

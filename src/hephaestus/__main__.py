"""Allow ``python -m hephaestus`` to invoke the offline forge."""

from .cli import main


raise SystemExit(main())

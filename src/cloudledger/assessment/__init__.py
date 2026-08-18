"""
Assessment evidence engine.

Produces deterministic security findings from collected scan data. Scoring
is the MCP client's responsibility, directed by its skills.
Uses Australian English in all documentation and comments.
"""

from .registry import CATEGORIES, get_catalogue, run_checks  # noqa: F401

# Check modules are imported for their registration side effects. Tasks
# adding check modules must extend this list.
from . import checks_identity  # noqa: F401,E402
from . import checks_network  # noqa: F401,E402
from . import checks_data  # noqa: F401,E402
from . import checks_logging  # noqa: F401,E402
from . import exposure  # noqa: F401,E402
from .exposure import run_exposure  # noqa: F401,E402

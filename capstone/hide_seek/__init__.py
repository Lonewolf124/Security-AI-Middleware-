"""
Local Hide-and-Seek (HaS) layer for the DLP proxy.

Hide : detect private values in an outgoing prompt and replace each one
       with a random surrogate of the same kind and shape.
Vault: remember original <-> surrogate per chat session in a local
       encrypted SQLite database, so later turns reuse the same surrogates.
Seek : put the original values back into the provider's response before it
       reaches the user.

Everything runs in the proxy process on one machine. Nothing in this
package opens a network connection.
"""

from .hide import Hider
from .seek import restore, StreamRestorer, SSERestorer
from .vault import Vault, Session

__all__ = [
    "Hider",
    "Vault",
    "Session",
    "restore",
    "StreamRestorer",
    "SSERestorer",
]

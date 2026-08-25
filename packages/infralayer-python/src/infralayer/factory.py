"""
InfraLayer Python SDK - Factory Functions
==========================================

Convenience factory functions for creating InfraLayer clients.
"""

from __future__ import annotations

from typing import Any, Optional

from .client import InfraLayer, create_infralayer, create_local_infralayer, create_remote_infralayer
from .core import InfraLayerCore, create_infralayer_core
from .types import InfraLayerConfig, UserContext


__all__ = [
    "create_infralayer",
    "create_local_infralayer",
    "create_remote_infralayer",
    "create_infralayer_core",
    "InfraLayer",
    "InfraLayerCore",
    "InfraLayerConfig",
    "UserContext",
]
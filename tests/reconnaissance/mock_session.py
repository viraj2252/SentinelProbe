"""Mock session for testing."""

from typing import Any, Dict, List, Optional, Union

from sentinelprobe.reconnaissance.models import Port, Service, Target


class MockSession:
    """Mock session for testing."""

    def __init__(self):
        """Initialize mock session."""
        self.targets: List[Target] = []
        self.ports: List[Port] = []
        self.services: List[Service] = []
        self.next_id = 1

    async def commit(self):
        """Simulate commit."""
        pass

    async def refresh(self, obj):
        """Simulate refresh."""
        if not hasattr(obj, "id") or obj.id is None:
            obj.id = self.next_id
            self.next_id += 1

    def add(self, obj):
        """Add object to session."""
        if isinstance(obj, Target):
            self.targets.append(obj)
        elif isinstance(obj, Port):
            self.ports.append(obj)
        elif isinstance(obj, Service):
            self.services.append(obj)
        else:
            raise ValueError(f"Unknown object type: {type(obj)}")

        if not hasattr(obj, "id") or obj.id is None:
            obj.id = self.next_id
            self.next_id += 1

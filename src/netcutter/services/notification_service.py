"""
In-App Notification and Toast Alert Service.
Coordinates real-time UI alerts, persistent notification history, and event-driven signals.
"""
from __future__ import annotations

import collections
import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, List, Optional

from netcutter.persistence.repository import NotificationItem, NotificationRepository

logger = logging.getLogger("netcutter.notifications")


class NotificationCategory(str, Enum):
    SUCCESS = "SUCCESS"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class ToastNotification:
    """Ephemeral toast message displayed floating above main application pages."""
    toast_id: str
    category: NotificationCategory
    title: str
    message: str
    duration_ms: int = 4000
    action_label: Optional[str] = None
    action_data: Optional[str] = None
    created_at: float = field(default_factory=time.time)


class NotificationService:
    """
    Central event-driven notification manager.
    Dispatches ephemeral toasts for immediate user feedback and commits critical/important
    records to persistent storage for historical review in the Notification Center.
    """

    def __init__(self, repo: NotificationRepository):
        self.repo = repo
        self._listeners: List[Callable[[NotificationItem], None]] = []
        self._toast_listeners: List[Callable[[ToastNotification], None]] = []
        self._recent_signatures: collections.deque = collections.deque(maxlen=50)
        self._lock = threading.Lock()

    def add_notification_listener(self, listener: Callable[[NotificationItem], None]):
        """Subscribe to persistent notification records."""
        with self._lock:
            self._listeners.append(listener)

    def add_toast_listener(self, listener: Callable[[ToastNotification], None]):
        """Subscribe to ephemeral toast alerts."""
        with self._lock:
            self._toast_listeners.append(listener)

    def post(
        self,
        category: NotificationCategory,
        title: str,
        message: str,
        related_guid: Optional[str] = None,
        action_label: Optional[str] = None,
        action_payload: Optional[str] = None,
        show_toast: bool = True,
        toast_duration_ms: int = 4000,
    ) -> NotificationItem:
        """
        Post an event notification.
        Dedupes rapid identical notifications (e.g. repeated ping errors).
        """
        now = time.time()
        sig = (category.value, title, message[:80])

        with self._lock:
            # Rate-limiting / deduplication: Drop identical notifications within 3 seconds
            for old_sig, old_time in list(self._recent_signatures):
                if old_sig == sig and (now - old_time) < 3.0:
                    logger.debug(f"Suppressed duplicate notification: {title}")
                    return NotificationItem(category=category.value, title=title, message=message)

            self._recent_signatures.append((sig, now))

        # Create persistent item
        item = NotificationItem(
            category=category.value,
            title=title,
            message=message,
            related_guid=related_guid,
            action_type=action_label,
            action_payload=action_payload,
        )

        try:
            self.repo.add(item)
        except Exception as ex:
            logger.error(f"Failed to persist notification: {ex}")

        # Broadcast to persistent listeners
        with self._lock:
            listeners = list(self._listeners)
            toast_listeners = list(self._toast_listeners)

        for cb in listeners:
            try:
                cb(item)
            except Exception as ex:
                logger.warning(f"Error in notification listener: {ex}")

        # Broadcast toast if requested
        if show_toast:
            # Adjust duration based on severity
            duration = toast_duration_ms
            if category == NotificationCategory.CRITICAL:
                duration = 8000
            elif category == NotificationCategory.ERROR:
                duration = 6000

            toast = ToastNotification(
                toast_id=item.notification_id,
                category=category,
                title=title,
                message=message,
                duration_ms=duration,
                action_label=action_label,
                action_data=action_payload,
            )
            for t_cb in toast_listeners:
                try:
                    t_cb(toast)
                except Exception as ex:
                    logger.warning(f"Error in toast listener: {ex}")

        return item

    def get_recent(self, limit: int = 100, unread_only: bool = False) -> List[NotificationItem]:
        return self.repo.get_all(limit=limit, unread_only=unread_only)

    def get_unread_count(self) -> int:
        return self.repo.get_unread_count()

    def mark_read(self, notification_id: str) -> None:
        self.repo.mark_as_read(notification_id)

    def mark_all_read(self) -> None:
        self.repo.mark_all_as_read()

    def clear(self) -> None:
        self.repo.clear_all()

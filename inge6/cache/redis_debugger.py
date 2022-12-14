import logging
from typing import Optional

import threading

from redis import StrictRedis

from ..config import get_settings, Settings


class RedisGetDebugger(threading.Thread):
    def __init__(
        self,
        redis_client: StrictRedis,
        *args,
        settings: Optional[Settings] = None,
        **kwargs,
    ) -> None:
        threading.Thread.__init__(self, *args, **kwargs)
        self.settings = settings if settings is not None else get_settings()

        logging.basicConfig(
            level=getattr(logging, self.settings.loglevel.upper()),
            datefmt="%m/%d/%Y %I:%M:%S %p",
        )
        self.log: logging.Logger = logging.getLogger(__package__)

        self.psubscribe = "__keyevent@0__:expired"
        self.redis_client = redis_client

        # live 5 minutes longer than regular redis objects
        self.debug_set_expiry: int = int(self.settings.redis.object_ttl) + 300
        self.key_prefix: str = self.settings.redis.default_cache_namespace

    def debug_get(self, key, value):
        if value is None:
            self.log.debug("Retrieved expired value with key: %s", key)
            return

        debug_keyname = f"{self.key_prefix}:retrieved:{key}"
        self.redis_client.set(debug_keyname, value, ex=self.debug_set_expiry)

    def _listen_for_expiration_events(self):
        """
        Function listening for `psubscribe` events, defaults to expired events. Only listening
        for those keys starting with `{KEY_PREFIX}:{key_type}`, where the key_type is configurable in redis
        under the redis.debug_keytype key.

        If the expired key is a key we are listening for, see if it exists in redis by the keyname:

            `{KEY_PREFIX}:retrieved:{set_key}`,

        where the `set_key` is the expired key. If the get returns a None it was never retrieved from redis.
        """
        pubsub = self.redis_client.pubsub()
        pubsub.psubscribe(self.psubscribe)

        # Once a event has launched, retrieve a msg
        for msg in pubsub.listen():
            set_key = msg["data"]
            if isinstance(set_key, bytes):
                set_key = set_key.decode()
            else:
                set_key = str(set_key)

            if not set_key.startswith(f"{self.key_prefix}:"):
                continue

            expected_retrieved_key = f"{self.key_prefix}:retrieved:{set_key}"
            self.log.debug(
                "Attempting retrieval of debug-key: %s", expected_retrieved_key
            )
            isretrieved = self.redis_client.get(expected_retrieved_key) is not None
            if not isretrieved:
                self.log.debug("Key %s has expired, but was never retrieved", set_key)

    def run(self):
        self.log.debug("Start listening for redis events: %s.", self.psubscribe)
        self._listen_for_expiration_events()
        self.log.debug("Stopped listening")

import logging

import threading

from redis import StrictRedis


# pylint: disable=too-few-public-methods
class RedisGetDebuggerFactory:
    def __init__(
        self,
        redis_client: StrictRedis,
        loglevel: str,
        redis_object_ttl: int,
        redis_default_cache_namespace: str,
    ):
        self.redis_client = redis_client
        self.redis_object_ttl = redis_object_ttl
        self.redis_default_cache_namespace = redis_default_cache_namespace

        self.level_number = logging.getLevelName(loglevel.upper())
        if isinstance(self.level_number, str):
            raise ValueError(f"Invalid loglevel {loglevel.upper()}")

    def create(self, *args, **kwargs):
        return RedisGetDebugger(
            self.redis_client,
            self.level_number,
            self.redis_object_ttl,
            self.redis_default_cache_namespace,
            *args,
            **kwargs,
        )


class RedisGetDebugger(threading.Thread):
    def __init__(
        self,
        redis_client: StrictRedis,
        loglevel: int,
        redis_object_ttl: int,
        redis_default_cache_namespace: str,
        *args,
        **kwargs,
    ) -> None:
        threading.Thread.__init__(self, *args, **kwargs)
        self.log: logging.Logger = logging.getLogger(__package__)
        self.log.level = loglevel
        self.psubscribe = "__keyevent@0__:expired"
        self.redis_client = redis_client

        # live 5 minutes longer than regular redis objects
        self.debug_set_expiry: int = redis_object_ttl + 300
        self.key_prefix: str = redis_default_cache_namespace

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

        # noinspection PyBroadException
        try:
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
                is_retrieved = self.redis_client.get(expected_retrieved_key) is not None
                if not is_retrieved:
                    self.log.debug(
                        "Key %s has expired, but was never retrieved", set_key
                    )
        # pylint: disable=broad-except
        except Exception:
            self.log.warning("Connection exception in redis debugger")

    def run(self):
        self.log.debug("Start listening for redis events: %s.", self.psubscribe)
        self._listen_for_expiration_events()
        self.log.debug("Stopped listening")

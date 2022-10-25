from typing import TypeVar, Generic, Callable


T = TypeVar("T")


class Lazy(Generic[T]):
    def __init__(self, generator: Callable[[], T]) -> None:
        self._initialized = False
        self._value = None
        self._exception = None
        self._generator = generator

    def _initialize(self) -> None:
        self._initialized = True
        try:
            self._value = self._generator()
        except Exception as e:
            self._exception = e

    @property
    def value(self) -> T:
        if not self._initialized:
            self._initialize()
        if self._exception is not None:
            raise ValueError(
                "Unable to get value from lazy object"
            ) from self._exception
        return self._value

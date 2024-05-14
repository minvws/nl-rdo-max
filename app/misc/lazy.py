from typing import TypeVar, Generic, Callable, Union

T = TypeVar("T")


class Lazy(Generic[T]):
    def __init__(self, generator: Callable[[], T]) -> None:
        self._initialized = False
        self._value: Union[T, None] = None
        self._exception: Union[Exception, None] = None
        self._generator = generator

    def _initialize(self) -> None:
        self._initialized = True
        try:
            self._value = self._generator()
        # pylint:disable=broad-except
        except Exception as exception:
            self._exception = exception

    @property
    def value(self) -> Union[T, None]:
        if not self._initialized:
            self._initialize()
        if self._exception is not None:
            raise ValueError(
                "Unable to get value from lazy object"
            ) from self._exception
        return self._value

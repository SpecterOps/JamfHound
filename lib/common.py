#!/usr/bin/env python3
from __future__ import annotations
from argparse import (
    ArgumentParser as Parser,
    Namespace
)
from typing import (
    TypeVar,
    Union,
    Generic,
    Any,
    Annotated,
    final
)
from sys import (
    stdout,
    stderr,
    argv,
    stdin,
    exit
)
from abc import abstractmethod
from json import (
    loads,
    dumps
)
from os.path import (
    exists,
)
from os import write
from requests import (
    Request,
    Response,
    Session
)
from datetime import datetime


_T = TypeVar("_T")
_S = TypeVar("_S", bound=Union[str, bytes, Exception, None])


class Object(object):
    def __init__(self, *ag, **kw):
        self.set(**kw)

    def __str__(self) -> str:
        return self.serialize().decode("ascii")

    def serialize(self) -> bytes:
        return dumps(self.__dict__, indent=4).encode("ascii")

    def get(self, *ag, **kw) -> Any:
        return self.__dict__.get(*ag, **kw)

    def set(self, **kw) -> Object:
        self.__dict__.update(**kw)
        return self

class Common(Object):
    def __init__(self, *ag, **kw):
        Object.__init__(self, *ag, **kw)

    @staticmethod
    def getExpiration(value: str) -> datetime:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")

    @staticmethod
    def readFile(path: str) -> bytes:
        with open(path, "rb") as file:
            return file.read()

    @staticmethod
    def writeFile(path: str, data: bytes) -> Any:
        with open(path, "wb") as file:
            return file.write(data)

    @staticmethod
    def writeJsonFile(path: str, data: dict) -> Any:
        with open(path, "w") as file:
            return file.write(dumps(data, indent=4))

    @staticmethod
    def readJsonFile(path: str) -> Object:
        return Object(**loads(Common.readFile(path).decode()))

    @staticmethod
    def string(value: _S) -> str:
        return (
            value.decode()
            if type(value) is bytes
            else str(value)
        )

    @staticmethod
    def bytes(value: _S) -> bytes:
        return (
            value.encode()
            if type(value) is str
            else value
        )
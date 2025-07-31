#!/usr/bin/env python3
from __future__ import annotations
from lib.common import (
    Object,
    TypeVar,
    Union,
    Generic
)

_T = TypeVar("_T")


class Model(Object, Generic[_T]):
    def __init__(self, *ag, **kw):
        Object.__init__(self, *ag, **kw)
        self.uuid = kw.get("uuid", "")

    def properties(self) -> dict:
        return {
            "Properties": self.__dict__
        }

class Script(Model):
    def __init__(self, *ag, **kw):
        Model.__init__(self, *ag, **kw)

class Computer(Model):
    def __init__(self, *ag, **kw):
        Model.__init__(self, *ag, **kw)

class Policy(Model):
    def __init__(self, *ag, **kw):
        Model.__init__(self, *ag, **kw)

class User(Model):
    def __init__(self, *ag, **kw):
        Model.__init__(self, *ag, **kw)

class Account(Model):
    def __init__(self, *ag, **kw):
        Model.__init__(self, *ag, **kw)

class Me(Model):
    def __init__(self, *ag, **kw):
        Model.__init__(self, *ag, **kw)

class Meta(Object):
    def __init__(self, *ag, **kw):
        Object.__init__(self)
        self.methods = kw.get("methods", 1)
        self.type = kw.get("type", "type")
        self.count = kw.get("count", 0)
        self.version = kw.get("version", 1)

    def properties(self) -> dict:
        return self.__dict__

class Data(Object, Generic[_T]):
    def __init__(self, *ag, **kw):
        Object.__init__(self, *ag, **kw)
        self.data = kw.get("data", [])
        self.meta = Meta(**kw).set(count=len(self.data))

    def properties(self) -> dict:
        return {
            "data": self.data,
            "meta": self.meta.properties()
        }

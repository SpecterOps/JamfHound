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
            "meta": self.meta.properties() # type: ignore
        }

# Minimum required attributes for edges in BH Generic Ingest
class Edge():
    def __init__(self, nkind):
        self.kind = nkind
        self.start = {"value": "", "match_by": "id"}
        self.end = {"value": "", "match_by": "id"}
        self.properties = {"description":"", "traversable":False}

# Minimum required attributes for nodes in BH Generic Ingest
class Node():
    def __init__(self, nkind):
        self.id = ""
        self.kind = nkind
        self.properties = {}
        self.properties["Tier"] = 1

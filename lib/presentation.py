#!/usr/bin/env python3
from __future__ import annotations
from lib.common import (
    Object,
    Common,
    Request,
    Response,
    Session,
    TypeVar,
    Union,
    datetime,
    Any,
    Generic,
    stderr,
    stdout,
    stdin,
    write
)
from traceback import (
    print_exc,
    print_stack
)
from lib.models import (
    User,
    Computer,
    Account,
    Me,
    Script,
    Policy,
    Data
)

_T = TypeVar("_T")
_S = TypeVar("_S", bound=Union[str, bytes, Exception, None])


class Display(Generic[_S]):
    UNDERLINE: str = '\033[4m'
    HEADER: str = '\033[95m'
    BLUE: str = '\033[94m'
    CYAN: str = '\033[96m'
    GREEN: str = '\033[92m'
    WARNING: str = '\033[93m'
    FAIL: str = '\033[91m'
    EOL: str = '\033[0m'
    BOLD: str = '\033[1m'

    @staticmethod
    def bytes(data: _S) -> bytes:
        return Common.bytes(data)

    @staticmethod
    def string(data: _S) -> str:
        return Common.string(data)

    def bold(self, data: _S) -> str:
        return f"{self.BOLD}{self.string(data)}"

    def green(self, data: _S) -> str:
        return f"{self.GREEN}{self.string(data)}{self.EOL}"

    def blue(self, data: _S) -> str:
        return f"{self.BLUE}{self.string(data)}{self.EOL}"

    def red(self, data: _S) -> str:
        return f"{self.FAIL}{self.string(data)}{self.EOL}"

    def yellow(self, data: _S) -> str:
        return f"{self.WARNING}{self.string(data)}{self.EOL}"

    def boldGreen(self, data: _S) -> str:
        return self.bold(self.green(data))

    def boldBlue(self, data: _S) -> str:
        return self.bold(self.green(data))

    def greenPlain(self, key: _S, value: _S) -> str:
        return f"{self.green(key)} {self.string(value)}"

    def bluePlain(self, key: _S, value: _S) -> str:
        return f"{self.blue(key)} {self.string(value)}"

    def blueGreen(self, key: _S, value: _S) -> str:
        return f"{self.blue(key)} {self.green(value)}"

    def plainText(self, key: _S, value: _S) -> str:
        return f"{self.string(key)} {self.string(value)}"


# noinspection PyBroadException
class ModelView(Common, Display, Generic[_T]):
    def __init__(self, *ag, **kw):
        Common.__init__(self)
        self.verbose = kw.get("verbose", False)
        self.throw = kw.get("throw", False)

    @staticmethod
    def primitives(data: Any) -> dict:
        data = data if isinstance(data, dict) else getattr(data, "__dict__", {})
        return dict(list([
            (key, value)
            for (key, value) in data.items()
            if type(value) in [str, int, bool, float]
        ]))

    def flush(self) -> ModelView:
        stdout.flush()
        return self

    @staticmethod
    def read() -> bytes:
        try:
            return stdin.readline().encode()
        except Exception:
            return b""

    def write(self, output: _S, out: bool = True) -> ModelView:
        if len(output) == 0:
            return self
        (written, output) = (0, self.bytes(output))
        while written < len(output):
            try:
                written += write(
                    (stdout if out else stderr).fileno(),
                    output[written:]
                )
            except OSError:
                pass
        return self

    def error(self, value: Any) -> ModelView:
        if bool(self.verbose):
            self.write(
                f"[!] ERROR: {self.bold(self.red(self.string(value)))}\n",
                False
            )
        if issubclass(type(value), Exception) and self.throw:
            print_exc()
            print_stack()
            if self.throw:
                raise value
        return self

    def success(self, value: _S) -> ModelView:
        return self.write(f"{self.bold(self.blue(self.string(value)))}\n")

    def failure(self, value: _S) -> ModelView:
        return self.write(f"{self.bold(self.red(self.string(value)))}\n")

    def warning(self, value: _S) -> ModelView:
        return self.write(f"{self.bold(self.yellow(self.string(value)))}\n")

    def info(self, value: _S) -> ModelView:
        return self.write(f"{self.green(self.string(value))}\n")

    def general(self, value: _S) -> ModelView:
        return self.write(f"{self.string(value)}\n")

    def debug(self, value: Any) -> ModelView:
        return (
            self.write(f"[*] DEBUG: {self.green(self.string(value))}\n")
            if self.verbose else self
        )


# noinspection PyPep8Naming
class AccountView(ModelView[Account]):
    def __init__(self, *ag, **kw):
        ModelView.__init__(self, *ag, **kw)

    def accountPermissions(self, account: Account, dangerous: list) -> AccountView:
        self.info(f"Checking permissions for {account.get('name')}")
        self.success(f"Access level: {account.get('access_level')}")
        self.success(f"Account ID: {account.get('id')}")
        self.success(f"Privilege set: {account.get('privilege_set')}")
        self.info(f"Attributes")
        [
            self.success(f"{str(key).capitalize()}: {value}")
            for (key, value) in self.primitives(account).items()
        ]
        if account.get("privileges"):
            self.info(f"Account Permissions")
            for name in ["jss_objects", "jss_settings", "jss_actions"]:
                [
                    (
                        self.warning(f"  Dangerous: {name} - {entry}")
                        if entry in dangerous
                        else self.general(f"  {name} - {entry}")
                    )
                    for entry in account.get("privileges", {}).get(name, [])
                ]
        return self

    def myPermissions(self, account: Account, dangerous: list, siteFilter: str = "all") -> AccountView:
        self.info(f"Checking permissions for {account.get('username')}")
        self.success(f"Account ID: {account.get('id')}")
        self.success(f"Access level: {account.get('accessLevel')}")
        self.success(f"Privilege set: {account.get('privilegeSet')}")
        self.info(f"Attributes")
        [
            self.success(f"{str(key).capitalize()}: {value}")
            for (key, value) in self.primitives(account).items()
        ]
        self.info(f"Site Permissions ")
        for (name, privilege) in account.get('sites').items():
            [
                (
                    (
                        self.failure(f"  Dangerous: {name} - {entry}")
                        if name in ["NONE", "-1"]
                        else self.warning(f"  Dangerous: {name} - {entry}")
                    )
                    if entry in dangerous
                    else self.general(f"  {name} - {entry}")
                )
                for entry in privilege
                if (siteFilter in ["all", name])
            ]
        return self

    def mySites(self, account: Account) -> AccountView:
        self.info(f"Checking sites for {account.get('username')}")
        [
            self.success(f"Site name {name}")
            for name in account.get('sites')
        ]
        return self


# noinspection PyPep8Naming
class ComputerView(ModelView[Computer]):
    def __init__(self, *ag, **kw):
        ModelView.__init__(self, *ag, **kw)

    def jamfComputer(self, computer: Computer) -> ComputerView:
        self.info(f"Checking computer for {computer.get('name')}")
        self.info(f"Attributes")
        [
            self.success(f"{str(key).capitalize()}: {value}")
            for (key, value) in self.primitives(computer).items()
        ]
        return self


# noinspection PyPep8Naming
class PolicyView(ModelView[Policy]):
    def __init__(self, *ag, **kw):
        ModelView.__init__(self, *ag, **kw)

    def jamfPolicy(self, policy: Policy) -> PolicyView:
        self.info(f"Checking policy {policy.get('name')}")
        self.info(f"Attributes")
        [
            self.success(f"{str(key).capitalize()}: {value}")
            for (key, value) in self.primitives(policy).items()
        ]
        return self

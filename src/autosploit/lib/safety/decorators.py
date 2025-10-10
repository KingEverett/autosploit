import functools
from typing import Callable, Optional, Any

from autosploit.lib.safety.manager import SafetyManager


def require_confirmation(
    action: Optional[str] = None,
    risk_level: str = "medium",
    auto_confirm_param: Optional[str] = None
):
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if args and hasattr(args[0], 'safety_manager'):
                safety = args[0].safety_manager
            else:
                raise RuntimeError(
                    "Function must be method with self.safety_manager attribute"
                )

            action_desc = action or f"Execute {func.__name__}"

            auto_confirm = False
            if auto_confirm_param and auto_confirm_param in kwargs:
                auto_confirm = kwargs[auto_confirm_param]

            if not safety.require_confirmation(
                action_desc,
                details=f"Function: {func.__name__}",
                risk_level=risk_level,
                auto_confirm=auto_confirm
            ):
                raise PermissionError(f"User declined: {action_desc}")

            return func(*args, **kwargs)

        return wrapper
    return decorator


def rate_limit(
    max_per_second: Optional[int] = None,
    key: Optional[str] = None,
    raise_on_limit: bool = True
):
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if args and hasattr(args[0], 'safety_manager'):
                safety = args[0].safety_manager
            else:
                raise RuntimeError(
                    "Function must be method with self.safety_manager attribute"
                )

            rate_key = key or f"{func.__module__}.{func.__name__}"

            if not safety.check_rate_limit(rate_key, max_per_second):
                if raise_on_limit:
                    raise RuntimeError(
                        f"Rate limit exceeded for {func.__name__} "
                        f"(max: {max_per_second or safety.config.max_messages_per_second}/sec)"
                    )
                else:
                    return None

            return func(*args, **kwargs)

        return wrapper
    return decorator


def blacklist_check(param_name: str = "arb_id"):
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if args and hasattr(args[0], 'safety_manager'):
                safety = args[0].safety_manager
            else:
                raise RuntimeError(
                    "Function must be method with self.safety_manager attribute"
                )

            arb_id = kwargs.get(param_name)

            if arb_id is None:
                import inspect
                sig = inspect.signature(func)
                params = list(sig.parameters.keys())

                if param_name in params:
                    param_index = params.index(param_name)
                    if param_index < len(args):
                        arb_id = args[param_index]

            if arb_id is None:
                raise ValueError(
                    f"Could not find CAN ID parameter '{param_name}' "
                    f"in function {func.__name__}"
                )

            if safety.is_blacklisted_id(arb_id):
                raise PermissionError(
                    f"Cannot access blacklisted CAN ID {hex(arb_id)} "
                    f"in function {func.__name__}"
                )

            return func(*args, **kwargs)

        return wrapper
    return decorator


def safe_can_operation(
    require_confirm: bool = True,
    check_rate_limit: bool = True,
    check_blacklist: bool = True,
    risk_level: str = "medium",
    can_id_param: str = "arb_id"
):
    def decorator(func: Callable) -> Callable:
        decorated = func

        if check_blacklist:
            decorated = blacklist_check(param_name=can_id_param)(decorated)

        if check_rate_limit:
            decorated = rate_limit()(decorated)

        if require_confirm:
            decorated = require_confirmation(
                action=f"Execute {func.__name__}",
                risk_level=risk_level
            )(decorated)

        return decorated

    return decorator
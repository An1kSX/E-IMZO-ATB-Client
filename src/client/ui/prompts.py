from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import partial
import logging
from typing import Protocol

from client.domain.commands import ProxyCommand

LOGGER = logging.getLogger(__name__)
_USER_ACTION_LOG_EXTRA = {"user_action": True}


@dataclass(frozen=True, slots=True)
class PortConflictResolution:
    terminate_process: bool
    remove_from_autostart: bool


@dataclass(frozen=True, slots=True)
class SensitiveOperationConfirmation:
    approved: bool
    manual_password: str | None = None


class PromptService(Protocol):
    async def confirm_sensitive_operation(
        self,
        *,
        command: ProxyCommand,
        identity: str,
    ) -> SensitiveOperationConfirmation:
        ...

    async def request_password(
        self,
        *,
        account_name: str,
        reason: str,
        error_message: str | None = None,
    ) -> str | None:
        ...

    async def resolve_port_conflict(
        self,
        *,
        process_name: str,
        port: int,
    ) -> PortConflictResolution:
        ...

    def close(self) -> None:
        ...


class TkPromptService:
    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="eimzo-ui")

    async def confirm_sensitive_operation(
        self,
        *,
        command: ProxyCommand,
        identity: str,
    ) -> SensitiveOperationConfirmation:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            partial(
                _show_confirmation_dialog,
                command_label=_format_command_label(command),
                identity=identity,
            ),
        )

    async def request_password(
        self,
        *,
        account_name: str,
        reason: str,
        error_message: str | None = None,
    ) -> str | None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            partial(
                _show_password_dialog,
                account_name=account_name,
                reason=reason,
                error_message=error_message,
            ),
        )

    async def resolve_port_conflict(
        self,
        *,
        process_name: str,
        port: int,
    ) -> PortConflictResolution:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            partial(
                _show_port_conflict_dialog,
                process_name=process_name,
                port=port,
            ),
        )

    def close(self) -> None:
        self._executor.shutdown(wait=True, cancel_futures=False)


def prompt_api_base_url(
    *,
    initial_value: str | None = None,
    error_message: str | None = None,
) -> str | None:
    return _show_api_base_url_dialog(initial_value=initial_value, error_message=error_message)


def show_info_message(*, title: str, message: str) -> None:
    _show_info_dialog(title=title, message=message)


def _schedule_dialog_focus(
    dialog: object,
    *,
    focus_widget: object | None = None,
    select_all: bool = False,
) -> None:
    target = focus_widget or dialog

    def _activate() -> None:
        try:
            dialog.lift()
        except Exception:
            return

        try:
            dialog.focus_force()
        except Exception:
            pass

        try:
            target.focus_set()
        except Exception:
            pass

        try:
            target.focus_force()
        except Exception:
            pass

        if select_all:
            try:
                target.selection_range(0, "end")
            except Exception:
                pass

        try:
            target.icursor("end")
        except Exception:
            pass

    try:
        dialog.after_idle(_activate)
        dialog.after(0, _activate)
        dialog.after(120, _activate)
        dialog.after(280, _activate)
        dialog.after(500, _activate)
    except Exception:
        pass


def _show_confirmation_dialog(
    *,
    command_label: str,
    identity: str,
) -> SensitiveOperationConfirmation:
    import tkinter as tk
    from tkinter import simpledialog
    from tkinter import ttk

    class ConfirmationDialog(simpledialog.Dialog):
        def __init__(self, parent: tk.Misc) -> None:
            self.result = SensitiveOperationConfirmation(approved=False)
            super().__init__(parent, title="Подтверждение операции")

        def body(self, master: tk.Misc) -> tk.Widget:
            self.resizable(False, False)
            self.attributes("-topmost", True)

            container = ttk.Frame(master, padding=16)
            container.grid(sticky="nsew")
            container.columnconfigure(0, weight=1)

            ttk.Label(
                container,
                text="Данное действие вызывает автоматический ввод пароля. Подтвердите, что хотите продолжить",
                wraplength=360,
                justify="left",
            ).grid(row=0, column=0, sticky="w")

            return container

        def buttonbox(self) -> None:
            box = ttk.Frame(self, padding=(16, 0, 16, 16))
            box.pack()

            approve_button = ttk.Button(box, text="ОК", width=14, command=self.ok, default="active")
            approve_button.grid(row=0, column=0, padx=(0, 8))
            ttk.Button(
                box,
                text="Ввести пароль вручную",
                width=24,
                command=self._use_manual_password,
            ).grid(row=0, column=1, padx=(0, 8))
            ttk.Button(box, text="Отменить", width=14, command=self.cancel).grid(row=0, column=2)
            _schedule_dialog_focus(self, focus_widget=approve_button)

            self.bind("<Return>", self.ok)
            self.bind("<Escape>", self.cancel)

        def _use_manual_password(self) -> None:
            password = _show_manual_password_dialog(parent=self)
            if password is None:
                return

            self.result = SensitiveOperationConfirmation(
                approved=True,
                manual_password=password,
            )
            self.destroy()

        def apply(self) -> None:
            self.result = SensitiveOperationConfirmation(approved=True)

    return _run_dialog(dialog_factory=ConfirmationDialog)


def _show_manual_password_dialog(*, parent: object) -> str | None:
    import tkinter as tk
    from tkinter import simpledialog
    from tkinter import ttk

    class ManualPasswordDialog(simpledialog.Dialog):
        def __init__(self, dialog_parent: object) -> None:
            self._password_var = tk.StringVar()
            self._validation_message_var = tk.StringVar(value="")
            self._password_entry: tk.Widget | None = None
            self.result = None
            super().__init__(dialog_parent, title="Ввод пароля вручную")

        def body(self, master: tk.Misc) -> tk.Widget:
            self.resizable(False, False)
            self.attributes("-topmost", True)

            container = ttk.Frame(master, padding=16)
            container.grid(sticky="nsew")
            container.columnconfigure(0, weight=1)

            ttk.Label(
                container,
                text="Введенный пароль будет передан в REST-метод через аргумент password.",
                wraplength=360,
                justify="left",
            ).grid(row=0, column=0, sticky="w")

            validation_label = ttk.Label(
                container,
                textvariable=self._validation_message_var,
                foreground="#b42318",
                wraplength=360,
                justify="left",
                padding=(0, 8, 0, 0),
            )
            validation_label.grid(row=1, column=0, sticky="w")

            ttk.Label(container, text="Пароль:", padding=(0, 12, 0, 0)).grid(row=2, column=0, sticky="w")

            password_entry = ttk.Entry(
                container,
                textvariable=self._password_var,
                show="*",
                width=36,
            )
            password_entry.grid(row=3, column=0, sticky="we")
            self._password_entry = password_entry
            _schedule_dialog_focus(self, focus_widget=password_entry)
            return password_entry

        def buttonbox(self) -> None:
            box = ttk.Frame(self, padding=(16, 0, 16, 16))
            box.pack()

            approve_button = ttk.Button(box, text="ОК", width=14, command=self.ok, default="active")
            approve_button.grid(row=0, column=0, padx=(0, 8))
            ttk.Button(box, text="Отменить", width=14, command=self.cancel).grid(row=0, column=1)
            if self._password_entry is not None:
                _schedule_dialog_focus(self, focus_widget=self._password_entry)

            self.bind("<Return>", self.ok)
            self.bind("<Escape>", self.cancel)

        def validate(self) -> bool:
            password = self._password_var.get()
            if password:
                return True

            self._validation_message_var.set("Введите пароль или нажмите «Отменить».")
            self.bell()
            return False

        def apply(self) -> None:
            self.result = self._password_var.get()

    dialog = ManualPasswordDialog(parent)
    return dialog.result


def _show_password_dialog(
    *,
    account_name: str,
    reason: str,
    error_message: str | None,
) -> str | None:
    import tkinter as tk
    from tkinter import simpledialog
    from tkinter import ttk

    class PasswordDialog(simpledialog.Dialog):
        def __init__(self, parent: tk.Misc) -> None:
            self._password_var = tk.StringVar()
            self._validation_message_var = tk.StringVar(value=error_message or "")
            self._password_entry: tk.Widget | None = None
            self.result = None
            super().__init__(parent, title="Вход в E-IMZO")

        def body(self, master: tk.Misc) -> tk.Widget:
            self.resizable(False, False)
            self.attributes("-topmost", True)

            container = ttk.Frame(master, padding=16)
            container.grid(sticky="nsew")
            container.columnconfigure(0, weight=1)

            ttk.Label(
                container,
                text="Введите пароль для доступа к E-IMZO API.",
                wraplength=360,
                justify="left",
            ).grid(row=0, column=0, sticky="w")
            ttk.Label(
                container,
                text=f"Пользователь: {account_name}",
                padding=(0, 12, 0, 0),
            ).grid(row=1, column=0, sticky="w")
            ttk.Label(
                container,
                text=reason,
                wraplength=360,
                justify="left",
                padding=(0, 8, 0, 0),
            ).grid(row=2, column=0, sticky="w")

            validation_label = ttk.Label(
                container,
                textvariable=self._validation_message_var,
                foreground="#b42318",
                wraplength=360,
                justify="left",
                padding=(0, 8, 0, 0),
            )
            validation_label.grid(row=3, column=0, sticky="w")

            ttk.Label(
                container,
                text="Пароль:",
                padding=(0, 12, 0, 0),
            ).grid(row=4, column=0, sticky="w")

            password_entry = ttk.Entry(
                container,
                textvariable=self._password_var,
                show="*",
                width=36,
            )
            password_entry.grid(row=5, column=0, sticky="we")
            self._password_entry = password_entry
            _schedule_dialog_focus(self, focus_widget=password_entry)
            return password_entry

        def buttonbox(self) -> None:
            box = ttk.Frame(self, padding=(16, 0, 16, 16))
            box.pack()

            login_button = ttk.Button(box, text="Войти", width=14, command=self.ok, default="active")
            login_button.grid(row=0, column=0, padx=(0, 8))
            ttk.Button(box, text="Отменить", width=14, command=self.cancel).grid(row=0, column=1)
            if self._password_entry is not None:
                _schedule_dialog_focus(self, focus_widget=self._password_entry)

            self.bind("<Return>", self.ok)
            self.bind("<Escape>", self.cancel)

        def validate(self) -> bool:
            password = self._password_var.get()
            if password:
                return True

            self._validation_message_var.set("Введите пароль или нажмите «Отменить».")
            self.bell()
            return False

        def apply(self) -> None:
            self.result = self._password_var.get()

    return _run_dialog(dialog_factory=PasswordDialog)


def _show_port_conflict_dialog(
    *,
    process_name: str,
    port: int,
) -> PortConflictResolution:
    import tkinter as tk
    from tkinter import simpledialog
    from tkinter import ttk

    class PortConflictDialog(simpledialog.Dialog):
        def __init__(self, parent: tk.Misc) -> None:
            self._remove_from_autostart_var = tk.BooleanVar(value=False)
            self.result = PortConflictResolution(terminate_process=False, remove_from_autostart=False)
            super().__init__(parent, title="Конфликт локального порта")

        def body(self, master: tk.Misc) -> tk.Widget:
            self.resizable(False, False)
            self.attributes("-topmost", True)

            container = ttk.Frame(master, padding=16)
            container.grid(sticky="nsew")
            container.columnconfigure(0, weight=1)

            ttk.Label(
                container,
                text=(
                    f"Порт {port} уже занят процессом {process_name}. "
                    "Чтобы запустить E-IMZO ATB Client, нужно закрыть этот процесс."
                ),
                wraplength=420,
                justify="left",
            ).grid(row=0, column=0, sticky="w")

            ttk.Checkbutton(
                container,
                text="Убрать E-IMZO из автозагрузки",
                variable=self._remove_from_autostart_var,
            ).grid(row=1, column=0, sticky="w", pady=(12, 0))

            return container

        def buttonbox(self) -> None:
            box = ttk.Frame(self, padding=(16, 0, 16, 16))
            box.pack()

            ttk.Button(
                box,
                text="Выключить E-IMZO",
                width=22,
                command=self._confirm_terminate,
                default="active",
            ).grid(row=0, column=0, padx=(0, 8))
            ttk.Button(
                box,
                text="Отменить запуск",
                width=18,
                command=self.cancel,
            ).grid(row=0, column=1)

            _schedule_dialog_focus(self)

            self.bind("<Return>", lambda event: self._confirm_terminate())
            self.bind("<Escape>", self.cancel)

        def cancel(self, event=None):  # type: ignore[override]
            if not self.result.terminate_process:
                self.result = PortConflictResolution(terminate_process=False, remove_from_autostart=False)
                LOGGER.info(
                    "Port conflict dialog cancelled by user. process_name=%s port=%s",
                    process_name,
                    port,
                    extra=_USER_ACTION_LOG_EXTRA,
                )
            return super().cancel(event)

        def _confirm_terminate(self) -> None:
            self.result = PortConflictResolution(
                terminate_process=True,
                remove_from_autostart=bool(self._remove_from_autostart_var.get()),
            )
            LOGGER.info(
                "Port conflict dialog confirmed by user. process_name=%s port=%s remove_from_autostart=%s",
                process_name,
                port,
                bool(self._remove_from_autostart_var.get()),
                extra=_USER_ACTION_LOG_EXTRA,
            )
            self.ok()

    return _run_dialog(dialog_factory=PortConflictDialog)


def _show_api_base_url_dialog(
    *,
    initial_value: str | None,
    error_message: str | None,
) -> str | None:
    import tkinter as tk
    from tkinter import simpledialog
    from tkinter import ttk

    class ApiBaseUrlDialog(simpledialog.Dialog):
        def __init__(self, parent: tk.Misc) -> None:
            self._url_var = tk.StringVar(value=initial_value or "")
            self._validation_message_var = tk.StringVar(value=error_message or "")
            self._url_entry: tk.Widget | None = None
            self.result = None
            super().__init__(parent, title="Настройка E-IMZO API")

        def body(self, master: tk.Misc) -> tk.Widget:
            self.resizable(False, False)
            self.attributes("-topmost", True)

            container = ttk.Frame(master, padding=16)
            container.grid(sticky="nsew")
            container.columnconfigure(0, weight=1)

            ttk.Label(
                container,
                text="Укажите URL локального E-IMZO API. Значение сохранится в настройках приложения.",
                wraplength=380,
                justify="left",
            ).grid(row=0, column=0, sticky="w")
            ttk.Label(
                container,
                text="Пример: http://172.16.10.66:7000",
                padding=(0, 8, 0, 0),
            ).grid(row=1, column=0, sticky="w")

            validation_label = ttk.Label(
                container,
                textvariable=self._validation_message_var,
                foreground="#b42318",
                wraplength=380,
                justify="left",
                padding=(0, 8, 0, 0),
            )
            validation_label.grid(row=2, column=0, sticky="w")

            ttk.Label(
                container,
                text="API URL:",
                padding=(0, 12, 0, 0),
            ).grid(row=3, column=0, sticky="w")

            url_entry = ttk.Entry(
                container,
                textvariable=self._url_var,
                width=44,
            )
            url_entry.grid(row=4, column=0, sticky="we")
            self._url_entry = url_entry
            _schedule_dialog_focus(self, focus_widget=url_entry, select_all=True)
            return url_entry

        def buttonbox(self) -> None:
            box = ttk.Frame(self, padding=(16, 0, 16, 16))
            box.pack()

            save_button = ttk.Button(box, text="Сохранить", width=14, command=self.ok, default="active")
            save_button.grid(row=0, column=0, padx=(0, 8))
            ttk.Button(box, text="Отменить", width=14, command=self.cancel).grid(row=0, column=1)
            if self._url_entry is not None:
                _schedule_dialog_focus(self, focus_widget=self._url_entry, select_all=True)

            self.bind("<Return>", self.ok)
            self.bind("<Escape>", self.cancel)

        def validate(self) -> bool:
            url = self._url_var.get().strip()
            if url:
                return True

            self._validation_message_var.set("Введите URL E-IMZO API или нажмите «Отменить».")
            self.bell()
            return False

        def apply(self) -> None:
            self.result = self._url_var.get().strip()

    return _run_dialog(dialog_factory=ApiBaseUrlDialog)


def _show_info_dialog(*, title: str, message: str) -> None:
    import tkinter as tk
    from tkinter import messagebox

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)

    try:
        messagebox.showinfo(title=title, message=message, parent=root)
    finally:
        root.destroy()


def _run_dialog(
    dialog_factory: type,
) -> bool | str | PortConflictResolution | SensitiveOperationConfirmation | None:
    import tkinter as tk

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)

    try:
        dialog = dialog_factory(root)
        return dialog.result
    finally:
        root.destroy()


@dataclass(frozen=True, slots=True)
class _CommandLabelParts:
    plugin: str | None
    name: str


def _format_command_label(command: ProxyCommand) -> str:
    label = _CommandLabelParts(plugin=command.plugin, name=command.name)
    if label.plugin:
        return f"{label.plugin}/{label.name}"
    return label.name

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import partial
from typing import Protocol

from client.domain.commands import ProxyCommand


class PromptService(Protocol):
    async def confirm_sensitive_operation(
        self,
        *,
        command: ProxyCommand,
        identity: str,
    ) -> bool:
        ...

    async def request_password(
        self,
        *,
        account_name: str,
        reason: str,
        error_message: str | None = None,
    ) -> str | None:
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
    ) -> bool:
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

    def close(self) -> None:
        self._executor.shutdown(wait=True, cancel_futures=False)


def prompt_api_base_url(
    *,
    initial_value: str | None = None,
    error_message: str | None = None,
) -> str | None:
    return _show_api_base_url_dialog(initial_value=initial_value, error_message=error_message)


def _show_confirmation_dialog(*, command_label: str, identity: str) -> bool:
    import tkinter as tk
    from tkinter import simpledialog
    from tkinter import ttk

    class ConfirmationDialog(simpledialog.Dialog):
        def __init__(self, parent: tk.Misc) -> None:
            self.result = False
            super().__init__(parent, title="Подтверждение операции")

        def body(self, master: tk.Misc) -> tk.Widget:
            self.resizable(False, False)
            self.attributes("-topmost", True)

            container = ttk.Frame(master, padding=16)
            container.grid(sticky="nsew")
            container.columnconfigure(0, weight=1)

            ttk.Label(
                container,
                text="Сайт запросил чувствительную операцию с передачей ИНН/ПИНФЛ.",
                wraplength=360,
                justify="left",
            ).grid(row=0, column=0, sticky="w")
            ttk.Label(
                container,
                text="Операция:",
                padding=(0, 12, 0, 0),
            ).grid(row=1, column=0, sticky="w")
            ttk.Label(
                container,
                text=command_label,
                wraplength=360,
                justify="left",
            ).grid(row=2, column=0, sticky="w")
            ttk.Label(
                container,
                text="ИНН/ПИНФЛ:",
                padding=(0, 12, 0, 0),
            ).grid(row=3, column=0, sticky="w")
            ttk.Label(
                container,
                text=identity,
                wraplength=360,
                justify="left",
            ).grid(row=4, column=0, sticky="w")

            return container

        def buttonbox(self) -> None:
            box = ttk.Frame(self, padding=(16, 0, 16, 16))
            box.pack()

            approve_button = ttk.Button(box, text="Да", width=14, command=self.ok, default="active")
            approve_button.grid(row=0, column=0, padx=(0, 8))
            ttk.Button(box, text="Отменить", width=14, command=self.cancel).grid(row=0, column=1)

            self.bind("<Return>", self.ok)
            self.bind("<Escape>", self.cancel)

        def apply(self) -> None:
            self.result = True

    return _run_dialog(dialog_factory=ConfirmationDialog)


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
            return password_entry

        def buttonbox(self) -> None:
            box = ttk.Frame(self, padding=(16, 0, 16, 16))
            box.pack()

            login_button = ttk.Button(box, text="Войти", width=14, command=self.ok, default="active")
            login_button.grid(row=0, column=0, padx=(0, 8))
            ttk.Button(box, text="Отменить", width=14, command=self.cancel).grid(row=0, column=1)

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
                text="Пример: http://127.0.0.1:64646",
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
            return url_entry

        def buttonbox(self) -> None:
            box = ttk.Frame(self, padding=(16, 0, 16, 16))
            box.pack()

            save_button = ttk.Button(box, text="Сохранить", width=14, command=self.ok, default="active")
            save_button.grid(row=0, column=0, padx=(0, 8))
            ttk.Button(box, text="Отменить", width=14, command=self.cancel).grid(row=0, column=1)

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


def _run_dialog(dialog_factory: type) -> bool | str | None:
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

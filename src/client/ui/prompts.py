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
    ) -> bool | SensitiveOperationConfirmation:
        ...

    async def request_password(
        self,
        *,
        account_name: str,
        reason: str,
        error_message: str | None = None,
    ) -> str | None:
        ...

    async def request_new_pfx_password(
        self,
        *,
        command: ProxyCommand,
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

    async def request_new_pfx_password(
        self,
        *,
        command: ProxyCommand,
    ) -> str | None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            partial(
                _show_new_pfx_password_dialog,
                command_label=_format_command_label(command),
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


def _schedule_input_focus(widget: object, *, select_all: bool = False) -> None:
    def _activate() -> None:
        try:
            widget.focus_set()
        except Exception:
            return

        if select_all:
            try:
                widget.selection_range(0, "end")
            except Exception:
                pass

        try:
            widget.icursor("end")
        except Exception:
            pass

    try:
        widget.after_idle(_activate)
    except Exception:
        return

    try:
        widget.after(80, _activate)
    except Exception:
        pass


def _enable_entry_paste_support(entry_widget: object, *, tk_module: object) -> None:
    def _paste_from_clipboard(event=None) -> str:
        try:
            clipboard_text = entry_widget.clipboard_get()
        except Exception:
            return "break"

        if not clipboard_text:
            return "break"

        try:
            entry_widget.delete("sel.first", "sel.last")
        except Exception:
            pass

        try:
            entry_widget.insert("insert", clipboard_text)
        except Exception:
            return "break"

        return "break"

    def _show_context_menu(event) -> str | None:
        menu = None
        try:
            try:
                entry_widget.focus_set()
                entry_widget.icursor(f"@{event.x}")
            except Exception:
                pass

            menu = tk_module.Menu(entry_widget, tearoff=False)
            menu.add_command(label="Вставить", command=_paste_from_clipboard)
            menu.tk_popup(event.x_root, event.y_root)
            return "break"
        except Exception:
            return None
        finally:
            if menu is not None:
                try:
                    menu.grab_release()
                except Exception:
                    pass

    def _handle_control_key_press(event) -> str | None:
        # In some keyboard layouts Ctrl+V does not trigger <Control-v>,
        # but the same physical key keeps virtual-key code 86 on Windows.
        if getattr(event, "keycode", None) == 86:
            return _paste_from_clipboard(event)
        return None

    try:
        entry_widget.bind("<Control-v>", _paste_from_clipboard, add="+")
        entry_widget.bind("<Control-V>", _paste_from_clipboard, add="+")
        entry_widget.bind("<Shift-Insert>", _paste_from_clipboard, add="+")
        entry_widget.bind("<Control-KeyPress>", _handle_control_key_press, add="+")
        entry_widget.bind("<Button-3>", _show_context_menu, add="+")
    except Exception:
        return


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
            self._manual_password: str | None = None
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

            approve_button = ttk.Button(box, text="Да", width=14, command=self.ok, default="active")
            approve_button.grid(row=0, column=0, padx=(0, 8))
            ttk.Button(
                box,
                text="Ввести пароль вручную",
                width=24,
                command=self._enter_password_manually,
            ).grid(row=0, column=1, padx=(0, 8))
            ttk.Button(box, text="Отменить", width=14, command=self.cancel).grid(row=0, column=2)

            self.bind("<Return>", self.ok)
            self.bind("<Escape>", self.cancel)

        def _enter_password_manually(self) -> None:
            try:
                password = _show_manual_password_dialog(parent=self)
            except Exception:
                LOGGER.exception("Manual password dialog failed to open.")
                return

            if password is None:
                return

            self._manual_password = password
            self.ok()

        def apply(self) -> None:
            self.result = SensitiveOperationConfirmation(
                approved=True,
                manual_password=self._manual_password,
            )

    return _run_dialog(dialog_factory=ConfirmationDialog)


def _show_manual_password_dialog(*, parent: object) -> str | None:
    import tkinter as tk
    from tkinter import simpledialog
    from tkinter import ttk

    class ManualPasswordDialog(simpledialog.Dialog):
        def __init__(self, dialog_parent: object) -> None:
            self._password_var = tk.StringVar()
            self._validation_message_var = tk.StringVar(value="")
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
            _enable_entry_paste_support(password_entry, tk_module=tk)
            _schedule_input_focus(password_entry)
            return password_entry

        def buttonbox(self) -> None:
            box = ttk.Frame(self, padding=(16, 0, 16, 16))
            box.pack()

            approve_button = ttk.Button(box, text="ОК", width=14, command=self.ok, default="active")
            approve_button.grid(row=0, column=0, padx=(0, 8))
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

    dialog = ManualPasswordDialog(parent)
    return dialog.result


def _show_new_pfx_password_dialog(*, command_label: str) -> str | None:
    import tkinter as tk
    from tkinter import simpledialog
    from tkinter import ttk

    class NewPfxPasswordDialog(simpledialog.Dialog):
        def __init__(self, parent: tk.Misc) -> None:
            self._password_var = tk.StringVar()
            self._confirmation_var = tk.StringVar()
            self._validation_message_var = tk.StringVar(value="")
            self.result = None
            super().__init__(parent, title="Новый пароль PFX")

        def body(self, master: tk.Misc) -> tk.Widget:
            self.resizable(False, False)
            self.attributes("-topmost", True)

            container = ttk.Frame(master, padding=16)
            container.grid(sticky="nsew")
            container.columnconfigure(0, weight=1)

            ttk.Label(
                container,
                text=f"Введите новый пароль для операции {command_label}.",
                wraplength=380,
                justify="left",
            ).grid(row=0, column=0, sticky="w")
            ttk.Label(
                container,
                text=(
                    "Пароль должен содержать минимум 10 символов, только латинские буквы и цифры, "
                    "минимум 2 маленькие буквы, 2 большие буквы и 1 цифру."
                ),
                wraplength=380,
                justify="left",
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

            ttk.Label(container, text="Новый пароль:", padding=(0, 12, 0, 0)).grid(
                row=3,
                column=0,
                sticky="w",
            )
            password_entry = ttk.Entry(
                container,
                textvariable=self._password_var,
                show="*",
                width=40,
            )
            password_entry.grid(row=4, column=0, sticky="we")
            _enable_entry_paste_support(password_entry, tk_module=tk)

            ttk.Label(container, text="Подтверждение пароля:", padding=(0, 12, 0, 0)).grid(
                row=5,
                column=0,
                sticky="w",
            )
            confirmation_entry = ttk.Entry(
                container,
                textvariable=self._confirmation_var,
                show="*",
                width=40,
            )
            confirmation_entry.grid(row=6, column=0, sticky="we")
            _enable_entry_paste_support(confirmation_entry, tk_module=tk)

            _schedule_input_focus(password_entry)
            return password_entry

        def buttonbox(self) -> None:
            box = ttk.Frame(self, padding=(16, 0, 16, 16))
            box.pack()

            approve_button = ttk.Button(box, text="ОК", width=14, command=self.ok, default="active")
            approve_button.grid(row=0, column=0, padx=(0, 8))
            ttk.Button(box, text="Отменить", width=14, command=self.cancel).grid(row=0, column=1)

            self.bind("<Return>", self.ok)
            self.bind("<Escape>", self.cancel)

        def validate(self) -> bool:
            validation_message = _validate_new_pfx_password(
                password=self._password_var.get(),
                confirmation=self._confirmation_var.get(),
            )
            if validation_message is None:
                return True

            self._validation_message_var.set(validation_message)
            self.bell()
            return False

        def apply(self) -> None:
            self.result = self._password_var.get()

    return _run_dialog(dialog_factory=NewPfxPasswordDialog)


def _validate_new_pfx_password(*, password: str, confirmation: str) -> str | None:
    if not password:
        return "Введите новый пароль или нажмите «Отменить»."

    if password != confirmation:
        return "Пароль и подтверждение пароля не совпадают."

    if len(password) < 10:
        return "Пароль должен содержать минимум 10 символов."

    if not password.isascii() or not password.isalnum():
        return "Пароль должен содержать только латинские буквы и цифры."

    lowercase_count = sum(1 for character in password if "a" <= character <= "z")
    uppercase_count = sum(1 for character in password if "A" <= character <= "Z")
    digit_count = sum(1 for character in password if character.isdigit())

    if lowercase_count < 2:
        return "Пароль должен содержать минимум 2 маленькие латинские буквы."

    if uppercase_count < 2:
        return "Пароль должен содержать минимум 2 большие латинские буквы."

    if digit_count < 1:
        return "Пароль должен содержать минимум 1 цифру."

    return None


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
            _enable_entry_paste_support(password_entry, tk_module=tk)
            _schedule_input_focus(password_entry)
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
            _enable_entry_paste_support(url_entry, tk_module=tk)
            _schedule_input_focus(url_entry, select_all=True)
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
        try:
            dialog = dialog_factory(root)
        except Exception:
            LOGGER.exception("Prompt dialog failed to initialize.")
            return None
        return dialog.result
    finally:
        try:
            root.destroy()
        except Exception:
            pass


@dataclass(frozen=True, slots=True)
class _CommandLabelParts:
    plugin: str | None
    name: str


def _format_command_label(command: ProxyCommand) -> str:
    label = _CommandLabelParts(plugin=command.plugin, name=command.name)
    if label.plugin:
        return f"{label.plugin}/{label.name}"
    return label.name

/* Только для отдельной страницы: никаких повторных запросов или записи ввода. */
(() => {
    const form = document.getElementById("console-auth");
    const status = document.getElementById("console-status");
    const screen = document.getElementById("console-terminal");
    const workspace = document.getElementById("console-workspace");
    const tools = document.getElementById("console-tools");
    const fullscreen = document.getElementById("console-fullscreen");
    const manualPaste = document.getElementById("console-paste-form");
    const pasteField = document.getElementById("console-paste-text");
    const notice = document.getElementById("console-notice");
    const keys = {
        Esc: "\x1b", "Ctrl+C": "\x03",
        F1: "\x1bOP", F2: "\x1bOQ", F3: "\x1bOR", F4: "\x1bOS",
        F5: "\x1b[15~", F6: "\x1b[17~", F7: "\x1b[18~", F8: "\x1b[19~",
        F9: "\x1b[20~", F10: "\x1b[21~", F11: "\x1b[23~", F12: "\x1b[24~"
    };
    const encoder = new TextEncoder();
    let channel, terminal, fit, resize, animation = 0, fontSize = 15, ready = false;

    function send(kind, bytes) {
        if (!ready || !channel || channel.readyState !== WebSocket.OPEN || !bytes.length) return;
        if (bytes.length + channel.bufferedAmount > 262144) {
            channel.close();
            return;
        }
        for (let offset = 0; offset < bytes.length; offset += 16384) {
            const chunk = bytes.subarray(offset, offset + 16384);
            const payload = new Uint8Array(chunk.length + 1);
            payload[0] = kind;
            payload.set(chunk, 1);
            channel.send(payload);
        }
    }

    function message(text) {
        notice.textContent = text;
        notice.hidden = !text;
    }

    function fitScreen() {
        if (!terminal || !fit) return;
        const size = fit.proposeDimensions();
        if (!size || !Number.isFinite(size.rows) || !Number.isFinite(size.cols)) return;
        terminal.resize(Math.min(500, Math.max(10, size.cols)), Math.min(200, Math.max(2, size.rows)));
    }

    function scheduleFit() {
        if (!animation) animation = requestAnimationFrame(() => {
            animation = 0;
            fitScreen();
        });
    }

    function reportSize(rows, cols) {
        const bytes = new Uint8Array(4);
        const size = new DataView(bytes.buffer);
        size.setUint16(0, rows);
        size.setUint16(2, cols);
        send(2, bytes);
    }

    function hidePaste() {
        pasteField.value = "";
        manualPaste.hidden = true;
    }

    async function copySelection() {
        if (!ready) return;
        const active = terminal;
        const text = active.getSelection();
        try {
            if (!text) {
                message("Выделите текст для копирования.");
                return;
            }
            await navigator.clipboard.writeText(text);
            if (terminal === active) message("Выделенный текст скопирован.");
        } catch {
            if (terminal === active) message("Буфер недоступен. Воспользуйтесь меню браузера для копирования.");
        } finally {
            if (terminal === active) active.focus();
        }
    }

    function paste(text) {
        if (!ready) return;
        if (text.length > 65536 || encoder.encode(text).length > 65536) {
            message("Вставляйте текст частями, не более 64 КиБ.");
            return;
        }
        // xterm сам применяет режим bracketed paste, если приложение его включило.
        if (text) terminal.paste(text);
        hidePaste();
        message("");
        terminal.focus();
    }

    async function pasteClipboard() {
        if (!ready) return;
        const active = terminal;
        try {
            const text = await navigator.clipboard.readText();
            if (terminal === active) paste(text);
        } catch {
            if (terminal !== active) return;
            manualPaste.hidden = false;
            message("Вставьте текст из буфера в поле.");
            pasteField.focus();
        }
    }

    function disconnected(message) {
        ready = false;
        if (channel) {
            const previous = channel;
            channel = undefined;
            previous.close();
        }
        if (resize) resize.disconnect();
        if (animation) cancelAnimationFrame(animation);
        animation = 0;
        if (terminal) terminal.dispose();
        terminal = undefined;
        fit = undefined;
        screen.hidden = true;
        tools.hidden = true;
        hidePaste();
        notice.textContent = "";
        notice.hidden = true;
        form.hidden = false;
        form.querySelector("button").disabled = false;
        status.textContent = message;
        if (document.fullscreenElement === workspace) document.exitFullscreen().catch(() => {});
    }

    document.getElementById("console-close").addEventListener("click", () => disconnected("Терминал закрыт."));
    document.getElementById("console-copy").addEventListener("click", copySelection);
    document.getElementById("console-paste").addEventListener("click", pasteClipboard);
    document.getElementById("console-paste-cancel").addEventListener("click", () => {
        hidePaste();
        message("");
        terminal?.focus();
    });
    manualPaste.addEventListener("submit", (event) => {
        event.preventDefault();
        paste(pasteField.value);
    });
    fullscreen.addEventListener("click", async () => {
        if (!ready) return;
        try {
            if (document.fullscreenElement === workspace) await document.exitFullscreen();
            else await workspace.requestFullscreen();
        } catch {
            message("Полноэкранный режим недоступен в этом браузере.");
        }
        terminal?.focus();
    });
    document.addEventListener("fullscreenchange", () => {
        const active = document.fullscreenElement === workspace;
        fullscreen.textContent = active ? "Выйти из полноэкранного режима" : "На весь экран";
        fullscreen.setAttribute("aria-pressed", String(active));
        scheduleFit();
    });
    tools.querySelectorAll("[data-font]").forEach((button) => button.addEventListener("click", () => {
        if (!ready) return;
        fontSize = Math.min(28, Math.max(10, fontSize + Number(button.dataset.font)));
        terminal.options.fontSize = fontSize;
        scheduleFit();
        terminal.focus();
    }));
    tools.querySelectorAll("[data-key]").forEach((button) => button.addEventListener("click", () => {
        if (!ready) return;
        send(1, encoder.encode(keys[button.dataset.key]));
        terminal.focus();
    }));
    window.addEventListener("pagehide", () => {
        if (channel) channel.close();
    });

    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (form.querySelector("button").disabled) return;
        form.querySelector("button").disabled = true;
        const fields = new URLSearchParams(new FormData(form));
        form.reset();
        status.textContent = "Проверяю доступ…";
        try {
            const response = await fetch(form.action, {method: "POST", body: fields, credentials: "same-origin"});
            fields.delete("root_password");
            if (!response.ok) {
                const message = response.status === 403 ? "Пароль не принят или учётная запись root заблокирована."
                    : response.status === 429 ? "Терминал занят или слишком много попыток. Повторите позже."
                    : "Консоль недоступна. Используйте SSH.";
                disconnected(message);
                return;
            }
            let {grant} = await response.json();
            if (typeof grant !== "string") throw new Error();
            terminal = new Terminal({fontSize, scrollback: 1500, allowProposedApi: false, theme: {background: "#111820"}});
            fit = new FitAddon.FitAddon();
            terminal.loadAddon(fit);
            screen.hidden = false;
            terminal.open(screen);
            fitScreen();
            const target = new URL("ws", form.action);
            target.protocol = "wss:";
            const ws = new WebSocket(target);
            channel = ws;
            ws.binaryType = "arraybuffer";
            ws.addEventListener("open", () => {
                if (ws !== channel) return;
                ws.send(JSON.stringify({grant, rows: terminal.rows, columns: terminal.cols}));
                grant = "";
            });
            ws.addEventListener("message", ({data}) => {
                if (ws !== channel) return;
                if (data === '{"ready":true}') {
                    ready = true;
                    form.hidden = true;
                    tools.hidden = false;
                    status.textContent = "Терминал подключён.";
                    reportSize(terminal.rows, terminal.cols);
                    scheduleFit();
                    terminal.focus();
                } else if (ready && data instanceof ArrayBuffer) {
                    terminal.write(new Uint8Array(data));
                }
            });
            ws.addEventListener("close", () => {
                grant = "";
                if (ws === channel) disconnected(ready ? "Терминал отключён." : "Не удалось подключить терминал.");
            });
            terminal.onData((data) => send(1, encoder.encode(data)));
            terminal.onBinary((data) => send(1, Uint8Array.from(data, (byte) => byte.charCodeAt(0))));
            terminal.onResize(({rows, cols}) => reportSize(rows, cols));
            terminal.attachCustomKeyEventHandler((event) => {
                if (event.type !== "keydown") return true;
                const key = event.key.toLowerCase();
                if ((event.ctrlKey && key === "insert") || (event.ctrlKey && event.shiftKey && key === "c")) {
                    event.preventDefault();
                    copySelection();
                    return false;
                }
                if ((event.shiftKey && key === "insert") || (event.ctrlKey && event.shiftKey && key === "v")) {
                    event.preventDefault();
                    pasteClipboard();
                    return false;
                }
                return true;
            });
            resize = new ResizeObserver(scheduleFit);
            resize.observe(screen);
        } catch {
            fields.delete("root_password");
            disconnected("Не удалось подключить терминал.");
        }
    });
})();

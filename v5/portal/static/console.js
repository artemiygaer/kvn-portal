/* Только для отдельной страницы: никаких повторных запросов или записи ввода. */
(() => {
    const form = document.getElementById("console-auth");
    const status = document.getElementById("console-status");
    const screen = document.getElementById("console-terminal");
    const close = document.getElementById("console-close");
    const encoder = new TextEncoder();
    let channel, terminal, resize, ready = false;

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

    function disconnected(message) {
        ready = false;
        if (channel) {
            const previous = channel;
            channel = undefined;
            previous.close();
        }
        if (resize) resize.disconnect();
        if (terminal) terminal.dispose();
        terminal = undefined;
        screen.hidden = true;
        close.hidden = true;
        form.hidden = false;
        form.querySelector("button").disabled = false;
        status.textContent = message;
    }

    close.addEventListener("click", () => disconnected("Терминал закрыт."));
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
            terminal = new Terminal({scrollback: 1500, allowProposedApi: false, theme: {background: "#111820"}});
            const fit = new FitAddon.FitAddon();
            terminal.loadAddon(fit);
            screen.hidden = false;
            terminal.open(screen);
            fit.fit();
            const target = new URL("/maintenance/console/ws", window.location.href);
            target.protocol = "wss:";
            const ws = new WebSocket(target);
            channel = ws;
            ws.binaryType = "arraybuffer";
            ws.addEventListener("open", () => {
                ws.send(JSON.stringify({grant, rows: terminal.rows, columns: terminal.cols}));
                grant = "";
            });
            ws.addEventListener("message", ({data}) => {
                if (ws !== channel) return;
                if (data === '{"ready":true}') {
                    ready = true;
                    form.hidden = true;
                    close.hidden = false;
                    status.textContent = "Терминал подключён.";
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
            terminal.onResize(({rows, cols}) => {
                const bytes = new Uint8Array(4);
                const size = new DataView(bytes.buffer);
                size.setUint16(0, rows);
                size.setUint16(2, cols);
                send(2, bytes);
            });
            resize = new ResizeObserver(() => fit.fit());
            resize.observe(screen);
        } catch {
            fields.delete("root_password");
            disconnected("Не удалось подключить терминал.");
        }
    });
})();

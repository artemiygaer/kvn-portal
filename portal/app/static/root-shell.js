(() => {
  "use strict";
  const root = document.querySelector("[data-root-shell]");
  if (!root) return;
  const { msg, announce } = window.KVN;
  const form = root.querySelector("[data-shell-open-form]");
  const password = root.querySelector("[name='root_password']");
  const frame = root.querySelector("[data-shell-terminal]");
  const status = root.querySelector("[data-shell-status]");
  const closeButton = root.querySelector("[data-shell-close]");
  const controls = [...root.querySelectorAll("[data-shell-control]")];
  const encoder = new TextEncoder();
  let shellId = "", socket = null, connected = false, stopped = true;
  let cursor = 0, nextSeq = 1, pending = null, queue = "", queuedBytes = 0;
  let retryTimer, inputTimer, fitTimer, retries = 0, lastSize = "", rendering = false;
  const terminal = window.Terminal ? new window.Terminal({
    convertEol: false, cursorBlink: true, disableStdin: true,
    fontFamily: "'Cascadia Mono', 'Consolas', 'Liberation Mono', monospace",
    fontSize: 14, lineHeight: 1.15, scrollback: 5000,
    theme: { background: "#0f1419", foreground: "#d8dee9", cursor: "#ffffff",
      selectionBackground: "#4b556380" }
  }) : null;
  const fit = window.FitAddon?.FitAddon ? new window.FitAddon.FitAddon() : null;
  const setStatus = (text, state = "stale") => {
    status.textContent = text;
    status.title = text;
    status.className = `status ${state}`;
  };
  const enable = (active) => {
    if (terminal) terminal.options.disableStdin = !active;
    frame.setAttribute("aria-disabled", String(!active));
    frame.classList.toggle("is-active", active);
    closeButton.disabled = !active;
    controls.forEach((button) => { button.disabled = !active; });
    form.hidden = active;
  };
  const send = (message) => {
    if (socket?.readyState !== WebSocket.OPEN) return false;
    socket.send(JSON.stringify(message));
    return true;
  };
  const fitTerminal = () => {
    const size = fit?.proposeDimensions();
    if (!terminal || !size || !Number.isFinite(size.cols) || !Number.isFinite(size.rows)) return;
    const cols = Math.max(20, Math.min(512, size.cols));
    const rows = Math.max(5, Math.min(200, size.rows));
    if (terminal.cols !== cols || terminal.rows !== rows) terminal.resize(cols, rows);
  };
  const resize = () => {
    window.clearTimeout(fitTimer);
    fitTimer = window.setTimeout(() => {
      try { fitTerminal(); } catch (_error) { return; }
      if (!terminal) return;
      const size = `${terminal.rows}:${terminal.cols}`;
      if (connected && size !== lastSize) {
        send({ type: "resize", rows: terminal.rows, cols: terminal.cols });
        lastSize = size;
      }
    }, 80);
  };
  const stop = (text = msg.shellClosed) => {
    stopped = true;
    connected = false;
    shellId = "";
    window.clearTimeout(retryTimer);
    window.clearTimeout(inputTimer);
    pending = null;
    queue = "";
    queuedBytes = 0;
    const old = socket;
    socket = null;
    old?.close();
    enable(false);
    setStatus(text);
  };
  const flush = () => {
    window.clearTimeout(inputTimer);
    if (!connected) return;
    if (!pending && queue) {
      let length = 0, bytes = 0;
      for (const char of queue) {
        const size = encoder.encode(char).length;
        if (bytes + size > 3500) break;
        bytes += size;
        length += char.length;
      }
      pending = { type: "input", seq: nextSeq, data: queue.slice(0, length) };
      queue = queue.slice(length);
      queuedBytes -= bytes;
    }
    if (pending) send(pending);
  };
  const input = (data) => {
    if (stopped || !data) return;
    const size = encoder.encode(data).length;
    if (queuedBytes + size > 256 * 1024) {
      announce("Буфер ввода заполнен. Дождитесь отправки; текст не будет обрезан молча.");
      return;
    }
    queue += data;
    queuedBytes += size;
    if (!pending) {
      window.clearTimeout(inputTimer);
      inputTimer = window.setTimeout(flush, 4);
    }
  };
  const connect = () => {
    if (stopped || !shellId) return;
    if (rendering) { retryTimer = window.setTimeout(connect, 15); return; }
    const url = new URL(root.dataset.streamEndpoint, window.location.href);
    // Flask url_for(WebSocket) может дать ws:// за HTTPS reverse proxy.
    url.protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(url);
    socket = ws;
    ws.onopen = () => send({ type: "hello", shell_id: shellId, csrf: root.dataset.csrf, cursor });
    ws.onmessage = (event) => {
      if (socket !== ws || stopped) return;
      let message;
      try { message = JSON.parse(event.data); } catch (_error) { stop(msg.shellFailed); return; }
      if (message.type === "ready") {
        connected = true;
        retries = 0;
        if (!pending) nextSeq = message.input_seq + 1;
        setStatus(msg.shellOnline, "ok");
        lastSize = "";
        resize();
        flush();
      } else if (message.type === "output") {
        const bytes = Uint8Array.from(atob(message.data), (char) => char.charCodeAt(0));
        if (message.cursor <= cursor) { send({ type: "ack", cursor }); return; }
        if (message.cursor - bytes.length !== cursor) { stop("Потеряно состояние вывода. Откройте shell заново."); return; }
        // ACK только после обработки xterm: ограничиваем очередь и не теряем кадр при reconnect.
        const id = shellId;
        rendering = true;
        terminal.write(bytes, () => {
          rendering = false;
          if (shellId !== id || stopped) return;
          cursor = message.cursor;
          if (socket === ws) send({ type: "ack", cursor });
        });
      } else if (message.type === "input_ack") {
        if (!pending || pending.seq !== message.seq) { stop(msg.shellFailed); return; }
        if (message.complete) {
          nextSeq = pending.seq + 1;
          pending = null;
          flush();
        } else if (message.alive) {
          inputTimer = window.setTimeout(flush, 40);
        } else stop(msg.shellClosed);
      } else if (message.type === "exit") stop(`${msg.shellClosed}${Number.isInteger(message.exit_code) ? ` rc=${message.exit_code}` : ""}`);
      else if (message.type === "error") {
        // Agent restart/потеря state: запрещён автоматический новый root shell/replay.
        stop("Сессия консоли недоступна. Проверьте agent и подключитесь заново.");
      }
    };
    ws.onclose = () => {
      if (socket !== ws || stopped) return;
      connected = false;
      if (++retries > 12) { stop(msg.shellFailed); return; }
      setStatus(msg.shellReconnecting);
      retryTimer = window.setTimeout(connect, Math.min(3000, 200 * retries));
    };
    ws.onerror = () => ws.close();
  };
  if (terminal) {
    if (fit) terminal.loadAddon(fit);
    terminal.open(root.querySelector("[data-shell-xterm]"));
    terminal.onData(input);
    // onResize не вызывает fit(): нет рекурсивного resize/SIGWINCH.
    terminal.onResize(({ rows, cols }) => {
      const size = `${rows}:${cols}`;
      if (connected && lastSize !== size) {
        send({ type: "resize", rows, cols });
        lastSize = size;
      }
    });
    terminal.attachCustomKeyEventHandler((event) => {
      if (event.ctrlKey && event.shiftKey && ["C", "V"].includes(event.key.toUpperCase())) return false;
      return true;
    });
    new ResizeObserver(resize).observe(frame);
    document.fonts?.ready.then(resize);
    resize();
  } else {
    const fallback = root.querySelector("[data-shell-output]");
    fallback.hidden = false;
    fallback.textContent = msg.shellTerminalMissing;
  }
  const request = async (endpoint, payload) => {
    const response = await fetch(endpoint, {
      method: "POST", credentials: "same-origin", cache: "no-store",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": root.dataset.csrf },
      body: JSON.stringify(payload)
    });
    const result = await response.json();
    if (!response.ok || !result.ok) throw new Error(result.error || msg.shellFailed);
    return result;
  };
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!terminal || !password.value || !stopped) return;
    const button = form.querySelector("button");
    button.disabled = true;
    setStatus(msg.shellConnecting);
    try {
      fitTerminal();
      const result = await request(root.dataset.openEndpoint,
        { root_password: password.value, rows: terminal.rows, cols: terminal.cols, stream: true });
      shellId = result.shell_id;
      cursor = 0;
      nextSeq = 1;
      stopped = false;
      terminal.reset(); // Только новый shell, никогда кадр/reconnect/resize.
      enable(true);
      terminal.write(result.output || "", connect);
      terminal.focus();
    } catch (error) { setStatus(msg.shellFailed, "down"); announce(error.message); }
    finally { password.value = ""; button.disabled = false; }
  });
  closeButton.addEventListener("click", async () => {
    const id = shellId;
    stop();
    if (id) {
      try { await request(root.dataset.closeEndpoint, { shell_id: id }); }
      catch (_error) { announce("Закрытие не подтверждено; agent завершит сессию по таймауту."); }
    }
  });
  controls.forEach((button) => button.addEventListener("click", () => {
    input(button.dataset.shellControl === "interrupt" ? "\x03" : "\x04");
    terminal?.focus();
  }));
  const copy = async () => {
    try { await navigator.clipboard.writeText(terminal?.getSelection() || ""); }
    catch (_error) { announce(msg.copyFailed); }
  };
  const paste = async () => {
    try {
      if (!stopped) {
        terminal?.paste(await navigator.clipboard.readText());
        terminal?.focus();
      }
    }
    catch (_error) { announce("Разрешите доступ к буферу или используйте Ctrl+Shift+V."); }
  };
  root.querySelector("[data-shell-copy]").addEventListener("click", copy);
  root.querySelector("[data-shell-paste]").addEventListener("click", paste);
  root.addEventListener("keydown", (event) => {
    if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "c") { event.preventDefault(); copy(); }
    if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "v") { event.preventDefault(); paste(); }
  });
  root.querySelectorAll("[data-shell-font]").forEach((button) => button.addEventListener("click", () => {
    if (!terminal) return;
    const delta = Number(button.dataset.shellFont);
    terminal.options.fontSize = delta ? Math.min(24, Math.max(10, terminal.options.fontSize + delta)) : 14;
    resize();
    if (!stopped) terminal.focus();
  }));
  root.querySelector("[data-shell-fullscreen]").addEventListener("click", async () => {
    try { if (document.fullscreenElement) await document.exitFullscreen(); else await root.requestFullscreen(); }
    catch (_error) { announce("Полноэкранный режим недоступен в этом браузере."); }
    resize();
    if (!stopped) terminal?.focus();
  });
  window.addEventListener("pagehide", () => { stopped = true; socket?.close(); });
  document.addEventListener("visibilitychange", () => { if (!document.hidden) resize(); });
  frame.addEventListener("click", () => { if (!stopped) terminal?.focus(); });
  enable(false);
  setStatus(msg.shellOffline);
})();

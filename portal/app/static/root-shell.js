(() => {
  "use strict";
  const { msg, announce } = window.KVN;

  const rootShell = document.querySelector("[data-root-shell]");
  if (rootShell) {
    const openForm = rootShell.querySelector("[data-shell-open-form]");
    const passwordInput = rootShell.querySelector("[name='root_password']");
    const terminalFrame = rootShell.querySelector("[data-shell-terminal]");
    const terminalMount = rootShell.querySelector("[data-shell-xterm]");
    const fallbackOutput = rootShell.querySelector("[data-shell-output]");
    const status = rootShell.querySelector("[data-shell-status]");
    const closeButton = rootShell.querySelector("[data-shell-close]");
    const controlButtons = Array.from(rootShell.querySelectorAll("[data-shell-control]"));
    const encoder = new TextEncoder();
    const terminalTheme = {
      background: "#0f1419",
      foreground: "#d8dee9",
      cursor: "#ffffff",
      cursorAccent: "#0f1419",
      selectionBackground: "#4b556380"
    };
    let shellId = "";
    let xterm = null;
    let fitAddon = null;
    let pollTimer = null;
    let resizeTimer = null;
    let writeTimer = null;
    let writeBuffer = "";
    let writeInFlight = false;
    let resizeInFlight = false;
    let readFailures = 0;

    const setShellStatus = (text, state = "stale") => {
      if (!status) return;
      status.textContent = text;
      status.className = `status ${state}`;
    };
    const setShellEnabled = (enabled) => {
      if (xterm) xterm.options.disableStdin = !enabled;
      if (terminalFrame) {
        terminalFrame.setAttribute("aria-disabled", String(!enabled));
        terminalFrame.classList.toggle("is-active", enabled);
      }
      if (closeButton) closeButton.disabled = !enabled;
      controlButtons.forEach((button) => { button.disabled = !enabled; });
      if (openForm) openForm.hidden = enabled;
    };
    const writeFallbackOutput = (text) => {
      if (!fallbackOutput || !text) return;
      fallbackOutput.hidden = false;
      fallbackOutput.textContent += text;
      if (fallbackOutput.textContent.length > 120000) fallbackOutput.textContent = fallbackOutput.textContent.slice(-96000);
      fallbackOutput.scrollTop = fallbackOutput.scrollHeight;
    };
    const appendShellOutput = (text) => {
      if (!text) return;
      if (xterm) {
        xterm.write(text);
        return;
      }
      writeFallbackOutput(text);
    };
    const clearShellOutput = () => {
      if (xterm) {
        xterm.clear();
        return;
      }
      if (fallbackOutput) fallbackOutput.textContent = "";
    };
    const focusShell = () => {
      if (!shellId) return;
      if (xterm) xterm.focus();
      else terminalFrame?.focus({ preventScroll: true });
    };
    const initTerminal = () => {
      if (xterm || !terminalMount || !window.Terminal) return;
      if (fallbackOutput) fallbackOutput.hidden = true;
      xterm = new window.Terminal({
        allowTransparency: false,
        convertEol: false,
        cursorBlink: true,
        disableStdin: true,
        fontFamily: "'Cascadia Mono', 'Consolas', 'Liberation Mono', monospace",
        fontSize: 14,
        lineHeight: 1.2,
        scrollback: 5000,
        theme: terminalTheme,
        windowsMode: false
      });
      if (window.FitAddon?.FitAddon) {
        fitAddon = new window.FitAddon.FitAddon();
        xterm.loadAddon(fitAddon);
      }
      xterm.open(terminalMount);
      xterm.onData(queueShellData);
      xterm.onResize(() => {
        if (shellId) resizeShell();
      });
      fitTerminal();
    };
    const fitTerminal = () => {
      if (!xterm) return;
      window.requestAnimationFrame(() => {
        try {
          fitAddon?.fit();
        } catch (_error) {
          // FitAddon зависит от рассчитанных размеров DOM; следующая попытка на resize исправит это.
        }
      });
    };
    const shellSize = () => {
      initTerminal();
      fitAddon?.fit();
      if (xterm) return { rows: xterm.rows, cols: xterm.cols };
      if (!fallbackOutput) return { rows: 24, cols: 100 };
      const styles = window.getComputedStyle(fallbackOutput);
      const fontSize = Number.parseFloat(styles.fontSize) || 13;
      const lineHeight = Number.parseFloat(styles.lineHeight) || fontSize * 1.5;
      const cols = Math.max(40, Math.min(180, Math.floor(fallbackOutput.clientWidth / Math.max(7, fontSize * 0.62))));
      const rows = Math.max(12, Math.min(60, Math.floor(fallbackOutput.clientHeight / Math.max(12, lineHeight))));
      return { rows, cols };
    };
    const shellRequest = async (endpoint, payload) => {
      const response = await fetch(endpoint, {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json",
          "X-CSRF-Token": rootShell.dataset.csrf || ""
        },
        body: JSON.stringify(payload)
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || data.ok === false) {
        const error = new Error(data.error || msg.shellFailed);
        error.code = data.code || "agent_error";
        error.status = response.status;
        throw error;
      }
      return data;
    };
    const isTransientShellError = (error) => error?.code === "agent_unavailable" || Number(error?.status) >= 500;
    const stopShellPolling = () => {
      window.clearTimeout(pollTimer);
      pollTimer = null;
    };
    const stopShellWriting = () => {
      window.clearTimeout(writeTimer);
      writeTimer = null;
      writeBuffer = "";
      writeInFlight = false;
    };
    const closeShellLocal = (text = msg.shellClosed) => {
      shellId = "";
      stopShellPolling();
      stopShellWriting();
      setShellEnabled(false);
      setShellStatus(text, "stale");
    };
    const takeShellChunk = () => {
      let bytes = 0;
      let index = 0;
      for (const char of writeBuffer) {
        const charBytes = encoder.encode(char).length;
        if (index > 0 && bytes + charBytes > 3500) break;
        bytes += charBytes;
        index += char.length;
      }
      const chunk = writeBuffer.slice(0, index || 1);
      writeBuffer = writeBuffer.slice(chunk.length);
      return chunk;
    };
    const flushShellWrite = async () => {
      window.clearTimeout(writeTimer);
      writeTimer = null;
      if (!shellId || writeInFlight || !writeBuffer) return;
      writeInFlight = true;
      const chunk = takeShellChunk();
      try {
        await shellRequest(rootShell.dataset.writeEndpoint, { shell_id: shellId, data: chunk });
      } catch (error) {
        if (isTransientShellError(error) && shellId) {
          writeBuffer = chunk + writeBuffer;
          setShellStatus(msg.shellReconnecting, "stale");
          writeTimer = window.setTimeout(flushShellWrite, 700);
          return;
        }
        setShellStatus(msg.shellFailed, "down");
        announce(msg.shellSendFailed);
        closeShellLocal(msg.shellFailed);
      } finally {
        writeInFlight = false;
        if (writeBuffer && !writeTimer) writeTimer = window.setTimeout(flushShellWrite, 8);
      }
    };
    const queueShellData = (data) => {
      if (!shellId || !data) return;
      writeBuffer += data;
      if (encoder.encode(writeBuffer).length >= 512) {
        flushShellWrite();
        return;
      }
      window.clearTimeout(writeTimer);
      writeTimer = window.setTimeout(flushShellWrite, 8);
    };
    const pollShell = async () => {
      if (!shellId) return;
      if (document.hidden) {
        stopShellPolling();
        return;
      }
      try {
        const data = await shellRequest(rootShell.dataset.readEndpoint, { shell_id: shellId });
        readFailures = 0;
        appendShellOutput(data.output || "");
        if (!data.alive) {
          closeShellLocal(`${msg.shellClosed}${Number.isFinite(data.exit_code) ? ` rc=${data.exit_code}` : ""}`);
          return;
        }
        if (status?.classList.contains("stale")) setShellStatus(msg.shellOnline, "ok");
        pollTimer = window.setTimeout(pollShell, data.output ? 80 : 160);
        return;
      } catch (error) {
        readFailures += 1;
        if (isTransientShellError(error) && readFailures <= 40) {
          setShellStatus(msg.shellReconnecting, "stale");
          pollTimer = window.setTimeout(pollShell, Math.min(1600, 240 + readFailures * 120));
          return;
        }
        announce(error.message || msg.shellFailed);
        closeShellLocal(msg.shellFailed);
        return;
      }
    };
    const resizeShell = async () => {
      if (!shellId || resizeInFlight) return;
      fitTerminal();
      resizeInFlight = true;
      try {
        await shellRequest(rootShell.dataset.resizeEndpoint, { shell_id: shellId, ...shellSize() });
      } catch (_error) {
        // Resize не критичен: следующая команда всё равно выполнится.
      } finally {
        resizeInFlight = false;
      }
    };
    initTerminal();
    if (!xterm) writeFallbackOutput(msg.shellTerminalMissing);
    openForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const rootPassword = passwordInput?.value || "";
      if (!rootPassword) {
        announce(msg.shellPasswordRequired);
        return;
      }
      setShellStatus(msg.shellConnecting, "stale");
      try {
        initTerminal();
        if (!xterm) {
          setShellStatus(msg.shellFailed, "down");
          writeFallbackOutput(`\n${msg.shellTerminalMissing}\n`);
          announce(msg.shellTerminalMissing);
          return;
        }
        const data = await shellRequest(rootShell.dataset.openEndpoint, { root_password: rootPassword, ...shellSize() });
        if (passwordInput) passwordInput.value = "";
        shellId = data.shell_id || "";
        readFailures = 0;
        clearShellOutput();
        appendShellOutput(data.output || "");
        setShellEnabled(Boolean(shellId));
        setShellStatus(msg.shellOnline, "ok");
        focusShell();
        stopShellPolling();
        pollShell();
      } catch (error) {
        if (passwordInput) passwordInput.value = "";
        setShellStatus(msg.shellFailed, "down");
        announce(error.message);
      }
    });
    terminalFrame?.addEventListener("click", focusShell);
    controlButtons.forEach((button) => {
      button.addEventListener("click", async () => {
        if (!shellId) return;
        const control = button.dataset.shellControl === "interrupt" ? "\u0003" : "\u0004";
        queueShellData(control);
        focusShell();
      });
    });
    closeButton?.addEventListener("click", async () => {
      if (!shellId) return;
      const id = shellId;
      closeShellLocal(msg.shellClosed);
      try {
        await shellRequest(rootShell.dataset.closeEndpoint, { shell_id: id });
      } catch (_error) {
        // Закрытие уже выполнено локально; agent уберёт просроченную сессию сам.
      }
    });
    window.addEventListener("resize", () => {
      window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(resizeShell, 400);
    });
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) stopShellPolling();
      else if (shellId && !pollTimer) {
        fitTerminal();
        pollShell();
      }
    });
    setShellEnabled(false);
    setShellStatus(msg.shellOffline, "stale");
  }

})();

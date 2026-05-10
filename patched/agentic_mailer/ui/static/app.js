(function () {
  const chatLog = document.getElementById("chatLog");
  const chatInput = document.getElementById("chatInput");
  const sendBtn = document.getElementById("sendBtn");
  const clearBtn = document.getElementById("clearBtn");
  const toggleTraceBtn = document.getElementById("toggleTraceBtn");
  const toggleThemeBtn = document.getElementById("toggleThemeBtn");
  const tracePanel = document.getElementById("tracePanel");
  const traceOutput = document.getElementById("traceOutput");
  const pendingSpinner = document.getElementById("pendingSpinner");
  const authBanner = document.getElementById("authBanner");
  const authBtn = document.getElementById("authBtn");
  const authMsg = document.getElementById("authMsg");

  let ws = null;
  let traceVisible = true;
  // Theme toggle (dark by default)
  function applyTheme(theme) {
    const root = document.documentElement;
    if (theme === 'light') {
      root.classList.add('theme-light');
    } else {
      root.classList.remove('theme-light');
    }
    if (toggleThemeBtn) {
      toggleThemeBtn.textContent = (theme === 'light') ? 'Dark mode' : 'Light mode';
    }
  }

  const savedTheme = window.localStorage.getItem('theme') || 'dark';
  applyTheme(savedTheme);


  function nowTime() {
    const d = new Date();
    return d.toLocaleTimeString();
  }

  function addMessage(role, text, meta) {
    const wrapper = document.createElement("div");
    wrapper.className = "msg " + (role === "user" ? "user" : "assistant");

    const header = document.createElement("div");
    header.className = "msgHeader";

    const who = document.createElement("div");
    who.textContent = role === "user" ? "You" : "Assistant";

    const when = document.createElement("div");
    when.textContent = nowTime();

    header.appendChild(who);
    header.appendChild(when);

    const body = document.createElement("div");
    body.textContent = text || "";

    wrapper.appendChild(header);
    wrapper.appendChild(body);

    // Optional confirmation buttons (patched mode)
    if (meta && meta.pending_action_id) {
      const hint = document.createElement("div");
      hint.className = "actionHint";
      hint.textContent = meta.pending_action_summary ? meta.pending_action_summary : "Confirmation required.";
      wrapper.appendChild(hint);

      const actionRow = document.createElement("div");
      actionRow.className = "actionRow";

      const confirmBtn = document.createElement("button");
      confirmBtn.className = "btn small primary";
      confirmBtn.textContent = "Confirm";
      confirmBtn.addEventListener("click", () => {
        sendText(`/confirm ${meta.pending_action_id}`);
      });

      const cancelBtn = document.createElement("button");
      cancelBtn.className = "btn small";
      cancelBtn.textContent = "Cancel";
      cancelBtn.addEventListener("click", () => {
        sendText(`/cancel ${meta.pending_action_id}`);
      });

      actionRow.appendChild(confirmBtn);
      actionRow.appendChild(cancelBtn);
      wrapper.appendChild(actionRow);
    }

    chatLog.appendChild(wrapper);
    chatLog.scrollTop = chatLog.scrollHeight;
  }

  function showAuthBanner(authUrl, reason) {
    if (!authBanner) return;
    if (authMsg) authMsg.textContent = reason || "Gmail authorization required.";
    if (authBtn) {
      authBtn.onclick = () => window.open(authUrl, "_blank");
    }
    authBanner.classList.remove("hidden");
    // Disable chat input while auth is pending
    if (chatInput) chatInput.disabled = true;
    if (sendBtn) sendBtn.disabled = true;
  }

  function hideAuthBanner() {
    if (!authBanner) return;
    authBanner.classList.add("hidden");
    if (chatInput) chatInput.disabled = false;
    if (sendBtn) sendBtn.disabled = false;
  }

  function setTrace(trace) {
    // Always update so the content is current when the panel is reopened.
    try {
      traceOutput.textContent = JSON.stringify(trace || [], null, 2);
    } catch (e) {
      traceOutput.textContent = String(trace || "");
    }
  }

  function connect() {
    const proto = (location.protocol === "https:") ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${location.host}/ws`);

    ws.addEventListener("open", () => {
      setLoading(false);
      addMessage("assistant", "Connected. Try: “List my newest 5 emails”", null);
    });

    ws.addEventListener("message", (ev) => {
      let msg = null;
      try { msg = JSON.parse(ev.data); } catch (e) { msg = { type: "error", error: ev.data }; }

      if (msg.type === "assistant_message") {
        setLoading(false);
        hideAuthBanner();
        addMessage("assistant", msg.assistant_text || "", {
          pending_action_id: msg.pending_action_id || null,
          pending_action_summary: msg.pending_action_summary || null
        });
        setTrace(msg.trace || []);
      } else if (msg.type === "auth_required") {
        setLoading(false);
        showAuthBanner(msg.auth_url || "/auth/start", msg.reason || "Gmail authorization required.");
      } else if (msg.type === "error") {
        setLoading(false);
        addMessage("assistant", "Error: " + (msg.error || "unknown"), null);
      }
    });

    ws.addEventListener("close", () => {
      setLoading(false);
      addMessage("assistant", "Disconnected. Reconnecting…", null);
      setTimeout(connect, 800);
    });
  }

  function setLoading(isLoading) {
    if (pendingSpinner) {
      pendingSpinner.classList.toggle("hidden", !isLoading);
    }
    if (sendBtn) {
      sendBtn.disabled = !!isLoading;
      sendBtn.textContent = isLoading ? "Sending…" : "Send";
    }
  }

  function sendText(text) {
    const t = (text || "").trim();
    if (!t) return;
    addMessage("user", t, null);
    if (ws && ws.readyState === WebSocket.OPEN) {
      setLoading(true);
      ws.send(JSON.stringify({ type: "user_message", text: t }));
    } else {
      setLoading(false);
      addMessage("assistant", "WebSocket not connected yet.", null);
    }
  }

  sendBtn.addEventListener("click", () => {
    sendText(chatInput.value);
    chatInput.value = "";
    chatInput.focus();
  });

  chatInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      sendBtn.click();
    }
  });

    if (toggleThemeBtn) {
    toggleThemeBtn.addEventListener('click', () => {
      const current = window.localStorage.getItem('theme') || 'dark';
      const next = (current === 'light') ? 'dark' : 'light';
      window.localStorage.setItem('theme', next);
      applyTheme(next);
    });
  }

clearBtn.addEventListener("click", () => {
    chatLog.textContent = "";
    traceOutput.textContent = "";
  });

  function updateTraceToggle() {
    const layout = document.querySelector(".layout");
    if (traceVisible) {
      tracePanel.classList.remove("hidden");
      layout.classList.remove("trace-collapsed");
      toggleTraceBtn.textContent = "Hide trace";
    } else {
      tracePanel.classList.add("hidden");
      layout.classList.add("trace-collapsed");
      toggleTraceBtn.textContent = "Show trace";
    }
  }

  toggleTraceBtn.addEventListener("click", () => {
    traceVisible = !traceVisible;
    updateTraceToggle();
  });

  document.querySelectorAll("[data-quick]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const q = btn.getAttribute("data-quick");
      sendText(q);
    });
  });

  connect();
})();

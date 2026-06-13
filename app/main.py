"""Gradio UI entry point for the CyberTriage agent."""

import os
import threading
import time

import gradio as gr
from dotenv import load_dotenv

from app.agent import get_workflow_state, run_agent
from app.memory import get_working_memory, reset_memory
from app.tools.action import list_incidents

load_dotenv()

WORKFLOW_STEPS = ["intake", "classify", "analyze", "confirm", "report", "done"]

WELCOME_MESSAGE = (
    "Welcome to the CyberTriage Chatbot!\n\n"
    "I am your AI security triage assistant. Tell me about a suspicious event "
    "and I will help you:\n"
    "  • Classify the threat (MITRE ATT&CK)\n"
    "  • Score severity\n"
    "  • Create an incident record\n"
    "  • Generate a PDF report\n\n"
    "Try: SQL injection attack on our login page"
)


LIGHT_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@500;700&display=swap');

:root {
    --bg-main: #f1f5f9;
    --bg-sidebar: #ffffff;
    --bg-chat: #ffffff;
    --bg-input: #ffffff;
    --accent: #2563eb;
    --accent-light: #dbeafe;
    --accent-hover: #1d4ed8;
    --text-primary: #1e293b;
    --text-secondary: #475569;
    --text-muted: #94a3b8;
    --user-bubble: #2563eb;
    --bot-bubble: #f8fafc;
    --border: #e2e8f0;
    --shadow: rgba(15, 23, 42, 0.08);
}

* { font-family: 'Inter', sans-serif; }

.gradio-container {
    background: var(--bg-main) !important;
    max-width: 100% !important;
    padding: 0 !important;
    color: var(--text-primary) !important;
}
footer, .built-with { display: none !important; }

/* ── Sidebar ── */
#sidebar-col {
    background: var(--bg-sidebar) !important;
    border-right: 1px solid var(--border) !important;
    box-shadow: 2px 0 12px var(--shadow) !important;
    min-height: 100vh;
    padding: 24px 18px !important;
}
.sidebar-title {
    color: var(--accent);
    font-size: 1.45rem;
    font-weight: 700;
    margin-bottom: 4px;
}
.sidebar-sub {
    color: var(--text-muted);
    font-size: 0.82rem;
    margin-bottom: 22px;
}
.sidebar-section-label {
    color: var(--text-secondary);
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-bottom: 10px;
}

/* ── Incident cards ── */
.incident-card {
    background: #f8fafc;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 12px;
    margin-bottom: 10px;
    border-left: 3px solid transparent;
    transition: all 0.2s;
}
.incident-card:hover { border-color: var(--accent); box-shadow: 0 2px 8px var(--shadow); }
.incident-card.active {
    border-left: 3px solid var(--accent);
    background: var(--accent-light);
}
.inc-id {
    color: var(--accent);
    font-family: 'JetBrains Mono', monospace;
    font-weight: 700;
    font-size: 0.88rem;
}
.inc-title { color: var(--text-primary); font-size: 0.82rem; margin: 5px 0; font-weight: 500; }
.inc-time { color: var(--text-muted); font-size: 0.72rem; font-family: 'JetBrains Mono', monospace; }
.badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 0.68rem;
    font-weight: 700;
    margin-top: 5px;
}
.badge-critical { background: #fee2e2; color: #dc2626; border: 1px solid #fca5a5; }
.badge-high { background: #ffedd5; color: #ea580c; border: 1px solid #fdba74; }
.badge-medium { background: #fef9c3; color: #ca8a04; border: 1px solid #fde047; }
.badge-low { background: #dcfce7; color: #16a34a; border: 1px solid #86efac; }
.no-incidents { color: var(--text-muted); font-size: 0.85rem; text-align: center; padding: 16px 0; }

/* ── Main area ── */
#main-col { background: var(--bg-main) !important; padding: 20px 24px !important; }

.top-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 18px;
    background: #ffffff;
    border: 1px solid var(--border);
    border-radius: 12px;
    margin-bottom: 14px;
    box-shadow: 0 1px 6px var(--shadow);
}
.top-bar-left { display: flex; align-items: center; gap: 12px; }
.top-label { color: var(--text-muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600; }
.inc-label {
    font-family: 'JetBrains Mono', monospace;
    color: var(--accent);
    font-weight: 700;
    font-size: 1rem;
}
.state-chip {
    background: var(--accent-light);
    color: var(--accent);
    border: 1px solid #93c5fd;
    padding: 4px 14px;
    border-radius: 20px;
    font-size: 0.78rem;
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
}

/* ── Chat panel ── */
.chat-panel {
    background: #ffffff;
    border: 1px solid var(--border);
    border-radius: 14px;
    overflow: hidden;
    margin-bottom: 0;
    box-shadow: 0 2px 16px var(--shadow);
}
.chat-panel-header {
    background: linear-gradient(135deg, #2563eb 0%, #3b82f6 100%);
    border-bottom: none;
    padding: 16px 20px;
    display: flex;
    align-items: center;
    gap: 14px;
}
.chat-icon {
    width: 40px; height: 40px;
    background: rgba(255,255,255,0.25);
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.2rem;
    flex-shrink: 0;
}
.chat-title { color: #ffffff; font-size: 1.1rem; font-weight: 700; margin: 0; }
.chat-subtitle { color: rgba(255,255,255,0.85); font-size: 0.8rem; margin: 3px 0 0 0; }
.chat-status {
    margin-left: auto;
    background: rgba(255,255,255,0.2);
    color: #ffffff;
    font-size: 0.7rem;
    font-weight: 700;
    padding: 4px 12px;
    border-radius: 20px;
    border: 1px solid rgba(255,255,255,0.4);
    letter-spacing: 0.04em;
}

/* Chatbot — minimal styling, let Gradio handle layout */
#chatbot-container,
#triage-chatbot {
    background: #ffffff !important;
    border: 1px solid var(--border) !important;
    border-top: none !important;
    border-radius: 0 0 14px 14px !important;
    margin-bottom: 14px !important;
    width: 100% !important;
}

#chatbot-container ::-webkit-scrollbar,
#triage-chatbot ::-webkit-scrollbar { width: 7px; }
#chatbot-container ::-webkit-scrollbar-track,
#triage-chatbot ::-webkit-scrollbar-track { background: #f1f5f9; }
#chatbot-container ::-webkit-scrollbar-thumb,
#triage-chatbot ::-webkit-scrollbar-thumb { background: #93c5fd; border-radius: 4px; }

#triage-chatbot .bubble {
    min-width: 120px !important;
    max-width: 80% !important;
    white-space: pre-wrap !important;
    word-break: normal !important;
    writing-mode: horizontal-tb !important;
    padding: 12px 16px !important;
    font-size: 0.95rem !important;
    line-height: 1.6 !important;
}

#triage-chatbot .user .bubble,
#triage-chatbot .bubble-wrap.user .bubble {
    background: #2563eb !important;
    color: #ffffff !important;
    border: none !important;
    border-radius: 16px 16px 4px 16px !important;
}

#triage-chatbot .bot .bubble,
#triage-chatbot .assistant .bubble,
#triage-chatbot .bubble-wrap.bot .bubble,
#triage-chatbot .bubble-wrap.assistant .bubble {
    background: #f1f5f9 !important;
    color: #1e293b !important;
    border: 1px solid #e2e8f0 !important;
    border-left: 4px solid #2563eb !important;
    border-radius: 4px 16px 16px 16px !important;
}

#triage-chatbot .user .bubble * {
    color: #ffffff !important;
}
#triage-chatbot .bot .bubble *,
#triage-chatbot .assistant .bubble * {
    color: #1e293b !important;
}

/* ── Workflow bar ── */
.workflow-wrap {
    background: #ffffff;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 12px 16px;
    margin-bottom: 14px;
    box-shadow: 0 1px 4px var(--shadow);
}
.workflow-label {
    color: var(--text-muted);
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    font-weight: 700;
    margin-bottom: 8px;
}
.workflow-bar { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; }
.wf-step {
    font-size: 0.8rem;
    font-family: 'JetBrains Mono', monospace;
    color: #cbd5e1;
    padding: 3px 6px;
}
.wf-step.done { color: var(--text-muted); text-decoration: line-through; }
.wf-step.active { color: var(--accent); font-weight: 700; border-bottom: 2px solid var(--accent); }
.wf-arrow { color: #cbd5e1; font-size: 0.75rem; padding: 0 2px; }

/* ── Input area ── */
.input-area-label {
    color: var(--text-secondary);
    font-size: 0.82rem;
    font-weight: 600;
    margin-bottom: 6px;
}
#user-input textarea, #user-input input {
    background: #ffffff !important;
    color: var(--text-primary) !important;
    border: 2px solid var(--border) !important;
    border-radius: 10px !important;
    font-size: 0.95rem !important;
}
#user-input textarea:focus {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 3px rgba(37,99,235,0.15) !important;
}
#user-input ::placeholder { color: var(--text-muted) !important; }

.send-btn {
    background: var(--accent) !important;
    color: #ffffff !important;
    border: none !important;
    font-weight: 700 !important;
    font-size: 0.9rem !important;
    border-radius: 10px !important;
    min-height: 52px !important;
    letter-spacing: 0.04em !important;
}
.send-btn:hover { background: var(--accent-hover) !important; }
.outline-btn {
    background: #ffffff !important;
    color: var(--accent) !important;
    border: 1.5px solid var(--accent) !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
}
.outline-btn:hover { background: var(--accent-light) !important; }

::-webkit-scrollbar { width: 7px; }
::-webkit-scrollbar-track { background: #f1f5f9; }
::-webkit-scrollbar-thumb { background: #93c5fd; border-radius: 4px; }
"""


def _severity_badge(severity: str) -> str:
    return f'<span class="badge badge-{severity.lower()}">{severity}</span>'


def _format_incidents_html() -> str:
    incidents = list_incidents()
    active_id = get_working_memory().get("incident_id")

    if not incidents:
        return '<div class="no-incidents">No incidents recorded yet.<br>Start a chat to create one.</div>'

    cards = []
    for inc in incidents:
        active = " active" if inc["incident_id"] == active_id else ""
        title = inc["title"][:40] + ("…" if len(inc["title"]) > 40 else "")
        created = inc.get("created_at", "")[:16]
        cards.append(
            f'<div class="incident-card{active}">'
            f'<div class="inc-id">{inc["incident_id"]}</div>'
            f'<div class="inc-title">{title}</div>'
            f'{_severity_badge(inc["severity"])}'
            f'<div class="inc-time">{created}</div>'
            f"</div>"
        )
    return "\n".join(cards)


def _format_workflow_bar_html() -> str:
    state = get_workflow_state()
    state_idx = WORKFLOW_STEPS.index(state) if state in WORKFLOW_STEPS else 0
    parts = []
    for i, step in enumerate(WORKFLOW_STEPS):
        if step == state:
            cls = "wf-step active"
        elif i < state_idx:
            cls = "wf-step done"
        else:
            cls = "wf-step"
        parts.append(f'<span class="{cls}">{step}</span>')
        if i < len(WORKFLOW_STEPS) - 1:
            parts.append('<span class="wf-arrow">›</span>')
    return (
        '<div class="workflow-wrap">'
        '<div class="workflow-label">Triage Progress</div>'
        f'<div class="workflow-bar">{"".join(parts)}</div>'
        "</div>"
    )


def _format_top_bar_html() -> str:
    wm = get_working_memory()
    incident_id = wm.get("incident_id") or "No active incident"
    state = get_workflow_state()
    return (
        '<div class="top-bar">'
        '<div class="top-bar-left">'
        '<div><div class="top-label">Current Incident</div>'
        f'<div class="inc-label">{incident_id}</div></div>'
        "</div>"
        f'<span class="state-chip">Step: {state}</span>'
        "</div>"
    )


def _normalize_history(history: list | None) -> list:
    """Ensure chat history is always Gradio 6 messages format."""
    normalized: list = []
    for item in history or []:
        if isinstance(item, dict):
            role = item.get("role")
            content = item.get("content", "")
        elif hasattr(item, "role") and hasattr(item, "content"):
            role = getattr(item, "role", None)
            content = getattr(item, "content", "")
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            user_msg, bot_msg = item
            if user_msg:
                normalized.append({"role": "user", "content": str(user_msg)})
            if bot_msg:
                normalized.append({"role": "assistant", "content": str(bot_msg)})
            continue
        else:
            continue

        if role in ("user", "assistant") and content is not None:
            normalized.append({"role": role, "content": str(content)})
    return normalized


def _stream_text(text: str, chunk_size: int = 3, delay: float = 0.045):
    """Yield progressively longer slices of text for typing animation."""
    if not text:
        yield ""
        return
    step = max(1, chunk_size)
    for i in range(step, len(text) + step, step):
        yield text[:i]
    yield text


def _thinking_message(frame: int = 0) -> str:
    dots = frame % 3 + 1
    dot_str = " ".join(["●"] * dots)
    return f"CyberTriage is thinking…  {dot_str}"


def _yield_state(history, user_input=""):
    return (
        history,
        user_input,
        _format_incidents_html(),
        _format_workflow_bar_html(),
        _format_top_bar_html(),
    )


def chat_fn(message: str, history: list):
    history = _normalize_history(history)

    if not message.strip():
        yield _yield_state(history)
        return

    history = history + [{"role": "user", "content": message}]
    yield _yield_state(history, "")

    history = history + [{"role": "assistant", "content": _thinking_message(0)}]
    yield _yield_state(history, "")

    response_box: list = [None]
    error_box: list = [None]

    def _run_agent():
        try:
            response_box[0] = run_agent(message)
        except Exception:
            error_box[0] = (
                "An error occurred while processing your request. Please try again."
            )

    agent_thread = threading.Thread(target=_run_agent, daemon=True)
    agent_thread.start()

    frame = 0
    thinking_start = time.time()
    min_thinking_secs = 1.5

    while agent_thread.is_alive() or (time.time() - thinking_start) < min_thinking_secs:
        history[-1] = {"role": "assistant", "content": _thinking_message(frame)}
        yield _yield_state(history, "")
        frame += 1
        time.sleep(0.45)

    agent_thread.join()
    response = response_box[0] or error_box[0] or "I was unable to process your request."

    history[-1] = {"role": "assistant", "content": response}
    yield _yield_state(history, "")


def new_incident_fn(history: list):
    reset_memory()
    history = _normalize_history(history)
    msg = (
        "New incident started.\n\n"
        "Describe the security event you'd like to triage. "
        "I'll ask follow-up questions if I need more details."
    )
    history = history + [{"role": "assistant", "content": msg}]
    yield (
        history,
        _format_incidents_html(),
        _format_workflow_bar_html(),
        _format_top_bar_html(),
    )


def export_report_fn() -> str | None:
    wm = get_working_memory()
    last_report = wm.get("last_report")
    if not last_report:
        return None
    pdf_path = last_report.get("pdf_path")
    if pdf_path and os.path.isfile(pdf_path):
        return pdf_path
    return None


def build_ui() -> gr.Blocks:
    with gr.Blocks(title="CyberTriage Agent") as demo:
        with gr.Row(elem_id="app-row"):
            with gr.Column(scale=0, min_width=280, elem_id="sidebar-col"):
                gr.HTML(
                    '<div class="sidebar-title">🛡 CyberTriage</div>'
                    '<div class="sidebar-sub">Security Incident AI</div>'
                    '<div class="sidebar-section-label">Incident Registry</div>'
                )
                incident_list = gr.HTML(value=_format_incidents_html())
                sidebar_new_btn = gr.Button(
                    "+ New Incident", elem_classes=["outline-btn"]
                )

            with gr.Column(scale=1, elem_id="main-col"):
                top_bar = gr.HTML(value=_format_top_bar_html())

                gr.HTML(
                    '<div class="chat-panel">'
                    '<div class="chat-panel-header">'
                    '<div class="chat-icon">💬</div>'
                    '<div>'
                    '<p class="chat-title">Security Triage Chatbot</p>'
                    '<p class="chat-subtitle">Chat with the AI assistant — describe incidents, get analysis & reports</p>'
                    '</div>'
                    '<span class="chat-status">● ONLINE</span>'
                    '</div>'
                    '</div>'
                )

                with gr.Group(elem_id="chatbot-container"):
                    chatbot = gr.Chatbot(
                        elem_id="triage-chatbot",
                        value=[{"role": "assistant", "content": WELCOME_MESSAGE}],
                        height=420,
                        show_label=False,
                        latex_delimiters=[],
                        render_markdown=True,
                    )

                workflow_bar = gr.HTML(value=_format_workflow_bar_html())

                gr.HTML('<div class="input-area-label">💬 Your message to the chatbot</div>')
                with gr.Row():
                    user_input = gr.Textbox(
                        placeholder="Type here and press SEND — e.g. \"Brute force attack on SSH server\"",
                        lines=2,
                        show_label=False,
                        elem_id="user-input",
                        scale=5,
                    )
                    send_btn = gr.Button("SEND ▶", elem_classes=["send-btn"], scale=1)

                with gr.Row():
                    new_btn = gr.Button("↺ New Incident", elem_classes=["outline-btn"])
                    export_btn = gr.Button("⬇ Export PDF Report", elem_classes=["outline-btn"])
                export_file = gr.File(label="Downloaded Report", interactive=False)

        outputs = [
            chatbot,
            user_input,
            incident_list,
            workflow_bar,
            top_bar,
        ]

        send_btn.click(chat_fn, inputs=[user_input, chatbot], outputs=outputs)
        user_input.submit(chat_fn, inputs=[user_input, chatbot], outputs=outputs)
        sidebar_new_btn.click(
            new_incident_fn,
            inputs=[chatbot],
            outputs=[chatbot, incident_list, workflow_bar, top_bar],
        )
        new_btn.click(
            new_incident_fn,
            inputs=[chatbot],
            outputs=[chatbot, incident_list, workflow_bar, top_bar],
        )
        export_btn.click(export_report_fn, inputs=[], outputs=[export_file])

    return demo


if __name__ == "__main__":
    from app.data.db_init import init_db

    init_db()

    server_name = os.getenv("GRADIO_SERVER_NAME", "0.0.0.0")
    server_port = int(os.getenv("GRADIO_SERVER_PORT", "7860"))

    demo = build_ui()
    demo.launch(
        server_name=server_name,
        server_port=server_port,
        css=LIGHT_CSS,
    )

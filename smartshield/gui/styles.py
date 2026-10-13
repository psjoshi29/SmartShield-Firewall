"""Cybersecurity Dark Theme CSS styles for SmartShield Streamlit Dashboard."""

CYBER_DARK_CSS = """
<style>
/* SmartShield Cybersecurity Theme Variables */
:root {
    --bg-primary: #0a0d14;
    --bg-card: #121824;
    --bg-card-hover: #182234;
    --border-color: #202b3c;
    --accent-blue: #00d2ff;
    --accent-cyan: #3a7bd5;
    --accent-glow: rgba(0, 210, 255, 0.15);
    --allow-green: #00e676;
    --block-red: #ff1744;
    --text-primary: #f0f6fc;
    --text-secondary: #8b949e;
}

/* Global App Container */
.stApp {
    background-color: #0b0f19;
    color: #e6edf3;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}

/* Header & Banner Styles */
.simulation-banner {
    background: linear-gradient(90deg, rgba(234, 179, 8, 0.15), rgba(245, 158, 11, 0.25));
    border: 1px solid rgba(245, 158, 11, 0.5);
    border-radius: 8px;
    padding: 10px 16px;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 12px;
    color: #fef08a;
    font-size: 0.9rem;
    font-weight: 500;
}

.simulation-banner strong {
    color: #facc15;
}

/* Metric KPI Card */
.kpi-card {
    background: #111726;
    border: 1px solid #1f293d;
    border-radius: 10px;
    padding: 16px 20px;
    margin-bottom: 15px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    transition: transform 0.2s ease, border-color 0.2s ease;
}

.kpi-card:hover {
    transform: translateY(-2px);
    border-color: #00d2ff;
    box-shadow: 0 6px 16px rgba(0, 210, 255, 0.12);
}

.kpi-title {
    color: #8b949e;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 6px;
    font-weight: 600;
}

.kpi-value {
    font-size: 2rem;
    font-weight: 700;
    color: #ffffff;
    line-height: 1.1;
    font-family: 'Consolas', 'Courier New', monospace;
}

.kpi-subtext {
    font-size: 0.8rem;
    color: #8b949e;
    margin-top: 6px;
}

.kpi-allow {
    color: #00e676 !important;
}

.kpi-block {
    color: #ff1744 !important;
}

.kpi-cyan {
    color: #00d2ff !important;
}

/* Badges */
.badge-allow {
    background-color: rgba(0, 230, 118, 0.15);
    color: #00e676;
    border: 1px solid rgba(0, 230, 118, 0.4);
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: 600;
    font-size: 0.8rem;
    display: inline-block;
}

.badge-block {
    background-color: rgba(255, 23, 68, 0.15);
    color: #ff1744;
    border: 1px solid rgba(255, 23, 68, 0.4);
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: 600;
    font-size: 0.8rem;
    display: inline-block;
}

.badge-neutral {
    background-color: rgba(139, 148, 158, 0.15);
    color: #c9d1d9;
    border: 1px solid rgba(139, 148, 158, 0.3);
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: 500;
    font-size: 0.8rem;
    display: inline-block;
}

/* Decision Cards in Inspector */
.decision-card-allow {
    background: linear-gradient(135deg, rgba(0, 230, 118, 0.1), rgba(0, 230, 118, 0.02));
    border: 2px solid #00e676;
    border-radius: 12px;
    padding: 24px;
    text-align: center;
    box-shadow: 0 0 24px rgba(0, 230, 118, 0.2);
    margin: 20px 0;
}

.decision-card-block {
    background: linear-gradient(135deg, rgba(255, 23, 68, 0.12), rgba(255, 23, 68, 0.02));
    border: 2px solid #ff1744;
    border-radius: 12px;
    padding: 24px;
    text-align: center;
    box-shadow: 0 0 24px rgba(255, 23, 68, 0.25);
    margin: 20px 0;
}

.decision-title-allow {
    color: #00e676;
    font-size: 2.2rem;
    font-weight: 800;
    letter-spacing: 0.05em;
    margin-bottom: 8px;
}

.decision-title-block {
    color: #ff1744;
    font-size: 2.2rem;
    font-weight: 800;
    letter-spacing: 0.05em;
    margin-bottom: 8px;
}

/* Form container */
div[data-testid="stForm"] {
    background-color: #111726;
    border: 1px solid #1f293d;
    border-radius: 10px;
    padding: 20px;
}

/* Custom table tweaks */
.stDataFrame {
    border: 1px solid #1f293d;
    border-radius: 8px;
    overflow: hidden;
}

/* Sidebar styling */
section[data-testid="stSidebar"] {
    background-color: #0d121c;
    border-right: 1px solid #1a2233;
}

/* Hide Streamlit default hamburger menu & footer */
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}

</style>
"""


def render_simulated_banner() -> str:
    """Return HTML string for top simulation disclaimer banner."""
    return """
    <div class="simulation-banner">
        <span>🛡️</span>
        <div>
            <strong>SIMULATION MODE ACTIVE:</strong> All network records, packet traces, and rule evaluations in SmartShield are synthetic and processed in a secure user-space sandbox. Real Windows network interfaces remain unmodified.
        </div>
    </div>
    """


def render_kpi_card(title: str, value: str, subtext: str = "", color_class: str = "kpi-cyan") -> str:
    """Render a styled KPI card."""
    return f"""
    <div class="kpi-card">
        <div class="kpi-title">{title}</div>
        <div class="kpi-value {color_class}">{value}</div>
        <div class="kpi-subtext">{subtext}</div>
    </div>
    """

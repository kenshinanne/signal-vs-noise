import csv
from pathlib import Path

import streamlit as st
import plotly.graph_objects as go

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"

PINK = "#F4B6C2"
GREEN = "#B5DCC2"
TEXT = "#111111"

st.set_page_config(
    page_title="Signal vs. Noise",
    page_icon="🌷",
    layout="wide"
)

st.markdown("""
<style>
.stApp {
    background-color: #FFFFFF;
    color: #555555;
}
h1, h2, h3 {
    color: #555555 !important;
}
.metric-card {
    padding: 20px;
    border-radius: 14px;
    margin-bottom: 10px;
}
.metric-label {
    font-size: 15px;
    color: #555555;
}
.metric-value {
    font-size: 30px;
    font-weight: bold;
    color: #555555;
}
</style>
""", unsafe_allow_html=True)


def read_csv(name):
    with open(RESULTS / name, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def total_row(name):
    rows = read_csv(name)
    return next(r for r in rows if r["rule"] == "TOTAL")


def make_chart(labels, first, second, names, title):
    fig = go.Figure()

    fig.add_trace(go.Bar(
        x=labels,
        y=first,
        name=names[0],
        marker_color=PINK,
        text=first,
        textposition="outside"
    ))

    fig.add_trace(go.Bar(
        x=labels,
        y=second,
        name=names[1],
        marker_color=GREEN,
        text=second,
        textposition="outside"
    ))

    fig.update_layout(
        title=title,
        template="plotly_white",
        barmode="group",
        plot_bgcolor="white",
        paper_bgcolor="white",
        font=dict(color=TEXT),
        legend=dict(orientation="h", y=-0.2),
        margin=dict(l=20, r=20, t=60, b=80),
        height=420,
        yaxis=dict(gridcolor="#EEEEEE", range=[
            0, max(first + second) * 1.15
        ]),
        xaxis=dict(showgrid=False)
    )

    return fig


before = total_row("before-tuning-summary.csv")
after = total_row("after-tuning-summary.csv")

before_class = total_row(
    "before-tuning-classification-summary.csv"
)
after_class = total_row(
    "after-tuning-classification-summary.csv"
)

normal_before = int(before["normal_alerts"])
normal_after = int(after["normal_alerts"])
attack_before = int(before["attack_alerts"])
attack_after = int(after["attack_alerts"])

fp_before = int(before_class["false_positives_total"])
fp_after = int(after_class["false_positives_total"])
tp_before = int(before_class["true_positives"])
tp_after = int(after_class["true_positives"])

reduction = (fp_before - fp_after) / fp_before * 100

st.title("Signal vs. Noise")
st.caption(
    "Rule-Based Detection and False-Alarm Reduction "
    "in Security Log Monitoring"
)

st.markdown("### Detection Results")

c1, c2, c3 = st.columns(3)

with c1:
    st.markdown(f"""
    <div class="metric-card" style="background:#FCE8EE;">
        <div class="metric-label">False-Positive Reduction</div>
        <div class="metric-value">{reduction:.1f}%</div>
    </div>
    """, unsafe_allow_html=True)

with c2:
    st.markdown(f"""
    <div class="metric-card" style="background:#E4F2E8;">
        <div class="metric-label">True Positives Retained</div>
        <div class="metric-value">{tp_after}/{tp_before}</div>
    </div>
    """, unsafe_allow_html=True)

with c3:
    st.markdown(f"""
    <div class="metric-card" style="background:#F5F5F5;">
        <div class="metric-label">Normal Alerts After Tuning</div>
        <div class="metric-value">{normal_after}</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("### Before vs. After Tuning")

left, right = st.columns(2)

with left:
    fig = make_chart(
        ["Before", "After"],
        [attack_before, attack_after],
        [normal_before, normal_after],
        ["Attack logs", "Normal logs"],
        "Alerts by Log Type"
    )
    st.plotly_chart(fig, use_container_width=True, theme=None)

with right:
    fig = make_chart(
        ["Before", "After"],
        [tp_before, tp_after],
        [fp_before, fp_after],
        ["True positives", "False positives"],
        "Alert Classification"
    )
    st.plotly_chart(fig, use_container_width=True, theme=None)

st.markdown("### Alerts by Detection Rule")

old_rules = {
    r["rule"]: r for r in
    read_csv("before-tuning-summary.csv")
    if r["rule"] != "TOTAL"
}
new_rules = {
    r["rule"]: r for r in
    read_csv("after-tuning-summary.csv")
    if r["rule"] != "TOTAL"
}

log_type = st.selectbox(
    "Choose log type",
    ["Normal logs", "Attack logs"]
)

column = (
    "normal_alerts"
    if log_type == "Normal logs"
    else "attack_alerts"
)

rules = list(old_rules.keys())
old_counts = [int(old_rules[r][column]) for r in rules]
new_counts = [int(new_rules[r][column]) for r in rules]

fig = make_chart(
    rules,
    old_counts,
    new_counts,
    ["Before tuning", "After tuning"],
    f"{log_type}: Alerts per Rule"
)

st.plotly_chart(fig, use_container_width=True, theme=None)

st.markdown("### Attack Timeline")

target = "PanacheSysmon_vs_AtomicRedTeam01.evtx"

events = [
    r for r in read_csv("after-tuning-attack.csv")
    if Path(r["EvtxFile"]).name == target
]

events.sort(key=lambda r: r["Timestamp"])

st.caption(f"Sample: {target}")

for i, event in enumerate(events, 1):
    with st.expander(
        f"Event {i} | {event['Timestamp']} | "
        f"{event['RuleTitle']}"
    ):
        st.write("Record ID:", event["RecordID"])
        st.write("Details:", event["Details"])

st.divider()

st.caption(
    "Tested using Hayabusa 4.1.0 and selected EVTX datasets. "
    "True positives were classified during the project review. "
    "Results do not guarantee detection of every attack."
)

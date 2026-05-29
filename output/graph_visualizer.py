"""Network graph visualization - generates an interactive HTML graph."""
import json
from pathlib import Path
from datetime import datetime
import networkx as nx
import plotly.graph_objects as go
from config.settings import GRAPHS_DIR

GRAPHS_DIR.mkdir(parents=True, exist_ok=True)


def build_graph(findings: dict) -> nx.Graph:
    G = nx.Graph()
    domain = findings.get("domain", "target")
    G.add_node(domain, node_type="domain", risk=findings.get("scores", {}).get("total", 0))

    for e in findings.get("emails", []):
        node = e["email"]
        G.add_node(node, node_type="email")
        G.add_edge(domain, node, relation="email")

    for s in findings.get("subdomains", []):
        node = s["subdomain"]
        G.add_node(node, node_type="subdomain", risk_flag=s.get("risk_flag", 0))
        G.add_edge(domain, node, relation="subdomain")

    for b in findings.get("breaches", []):
        node = f"BREACH:{b['breach_name']}"
        G.add_node(node, node_type="breach")
        G.add_edge(b["email"], node, relation="breach")

    for t in findings.get("threat_intel", []):
        if t.get("malicious"):
            node = f"THREAT:{t['indicator']}"
            G.add_node(node, node_type="threat")
            G.add_edge(domain, node, relation="threat")

    return G


def _node_color(data: dict) -> str:
    ntype = data.get("node_type", "")
    if ntype == "domain":
        return "#58a6ff"
    if ntype == "email":
        return "#3fb950"
    if ntype == "subdomain":
        return "#f85149" if data.get("risk_flag") else "#e3b341"
    if ntype == "breach":
        return "#f85149"
    if ntype == "threat":
        return "#ff0000"
    return "#8b949e"


def generate_graph_html(findings: dict) -> str:
    G = build_graph(findings)
    pos = nx.spring_layout(G, seed=42, k=1.5)

    edge_x, edge_y = [], []
    for u, v in G.edges():
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.8, color="#30363d"),
        hoverinfo="none", mode="lines",
    )

    node_x, node_y, node_text, node_colors = [], [], [], []
    for node, data in G.nodes(data=True):
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_text.append(node)
        node_colors.append(_node_color(data))

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        hoverinfo="text",
        text=node_text,
        textposition="top center",
        textfont=dict(color="#c9d1d9", size=9),
        marker=dict(size=12, color=node_colors, line=dict(width=1, color="#21262d")),
    )

    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            title=f"OSINT Network Graph - {findings.get('domain','target')}",
            paper_bgcolor="#0d1117",
            plot_bgcolor="#0d1117",
            font=dict(color="#c9d1d9"),
            showlegend=False,
            hovermode="closest",
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        ),
    )
    return fig.to_html(full_html=True, include_plotlyjs="cdn")


def save_graph(findings: dict) -> Path:
    domain = findings.get("domain", "unknown")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = GRAPHS_DIR / f"{domain}_{ts}_graph.html"
    path.write_text(generate_graph_html(findings), encoding="utf-8")
    return path

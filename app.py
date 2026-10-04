import streamlit as st
import requests
import json
from pyvis.network import Network
import streamlit.components.v1 as components

# Config Halaman
st.set_page_config(page_title="SecOps GraphCopilot", layout="wide")

st.title("🛡️ SecOps GraphCopilot: Attack Path & Continuous Defense")

# Webhook URL dari n8n Cloud
N8N_WEBHOOK_URL = "https://eternaspacelab.app.n8n.cloud/webhook/secops-analyze"

# Sidebar Input
with st.sidebar:
    st.header("1. Ingestion Layer")
    uploaded_file = st.file_uploader("Upload Multi-Host Log (JSON)", type=["json"])
    analyze_btn = st.button("Analyze & Map Incident", type="primary")

def render_graph(graph_data):
    # Buat instance network
    net = Network(height="550px", width="100%", bgcolor="#0F172A", font_color="white", directed=True)
    
    # Konfigurasi visual SOC Dashboard (Hierarchical Layout & Text Badge Background)
    options = {
        "nodes": {
            "borderWidth": 2,
            "borderWidthSelected": 4,
            "shadow": True,
            "font": {
                "size": 13,
                "face": "monospace",
                "color": "#F8FAFC",
                "background": "#1E293B",  # Box latar belakang teks node
                "strokeWidth": 2,
                "strokeColor": "#0F172A"
            }
        },
        "edges": {
            "color": {"color": "#F59E0B", "highlight": "#EF4444"},
            "arrows": {"to": {"enabled": True, "scaleFactor": 0.8}},
            "font": {
                "size": 11,
                "face": "sans-serif",
                "color": "#38BDF8",       # Warna teks cyan yang terang
                "background": "#1E293B",  # Mencegah teks bertabrakan dengan garis panah!
                "strokeWidth": 0,
                "align": "horizontal"
            },
            "smooth": {"type": "cubicBezier", "roundness": 0.2}
        },
        "layout": {
            "hierarchical": {
                "enabled": True,
                "direction": "LR",        # LR = Left-to-Right (Alur Kill Chain Kronologis)
                "sortMethod": "directed",
                "nodeSpacing": 180,
                "levelSeparation": 220
            }
        },
        "physics": {
            "hierarchicalRepulsion": {
                "centralGravity": 0.0,
                "springLength": 120,
                "nodeDistance": 180,
                "damping": 0.09
            },
            "solver": "hierarchicalRepulsion"
        }
    }
    
    # Apply konfigurasi JSON ke Pyvis
    net.set_options(json.dumps(options))
    
    # Render Nodes
    for node in graph_data["nodes"]:
        node_color = node.get("color", "#3B82F6")
        net.add_node(
            node["id"], 
            label=node["label"], 
            color={
                "background": node_color,
                "border": "#FFFFFF",
                "highlight": {"background": node_color, "border": "#F59E0B"}
            },
            size=24,
            shape="ellipse"
        )
        
    # Render Edges
    for edge in graph_data["edges"]:
        net.add_edge(
            edge["from"], 
            edge["to"], 
            label=f" {edge['label']} "  # Spasi padding agar teks tidak terlalu mepet
        )
    
    net.save_graph("graph.html")
    with open("graph.html", "r", encoding="utf-8") as f:
        html = f.read()
    components.html(html, height=570)

if analyze_btn and uploaded_file is not None:
    logs_data = json.load(uploaded_file)
    
    with st.spinner("Analyzing log artifacts & extracting attack graph via Cloud Engine..."):
        try:
            res = requests.post(N8N_WEBHOOK_URL, json=logs_data)
            data = res.json()
            
            # Key Metrics Header
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Patient Zero", data["summary"]["patient_zero"])
            m2.metric("Affected Hosts", data["summary"]["affected_hosts_count"])
            m3.metric("Severity Level", data["summary"]["severity"])
            m4.metric("Est. MTTR Saved", "90%")
            
            st.divider()
            
            # Tabs View
            tab1, tab2, tab3 = st.tabs(["🕸️ Attack Path & Blast Radius", "📝 Incident Narrative", "🛡️ Continuous Defense Engine"])
            
            with tab1:
                st.subheader("Visual Blast Radius & Pergerakan Peretas")
                render_graph(data["graph"])
                
            with tab2:
                st.subheader("Executive Summary")
                st.write(data["summary"]["narrative"])
                st.subheader("Chronological Timeline")
                st.table(data["timeline"])
                
            with tab3:
                st.subheader("Auto-Generated Sigma Detection Rule")
                st.code(data["defense"]["sigma_rule"], language="yaml")
                st.download_button("Download .YML Rule", data["defense"]["sigma_rule"], file_name="sigma_rule.yml")
                
                st.subheader("Validation Script (Atomic Red Team)")
                st.code(data["defense"]["atomic_script"], language="powershell")

        except Exception as e:
            st.error(f"Gagal memproses data: {str(e)}")

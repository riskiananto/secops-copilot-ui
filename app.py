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
    net = Network(height="500px", width="100%", bgcolor="#1E1E1E", font_color="white", directed=True)
    
    # Pengaturan Physics agar node saling menjauh & label tidak bertumpuk
    net.barnes_hut(
        gravity=-8000,           # Gaya tolak antar-node (makin minus, makin renggang)
        central_gravity=0.3,     # Menarik graf ke tengah canvas
        spring_length=250,       # Panjang garis/panah penghubung
        spring_strength=0.05,    # Kelenturan garis
        damping=0.09
    )
    
    # Tambahkan Nodes dengan ukuran font & jarak yang lebih jelas
    for node in graph_data["nodes"]:
        net.add_node(
            node["id"], 
            label=node["label"], 
            color=node.get("color", "#97C2FC"),
            size=25,
            font={"size": 14, "color": "white"}
        )
        
    # Tambahkan Edges (Panah Pergerakan Serangan)
    for edge in graph_data["edges"]:
        net.add_edge(
            edge["from"], 
            edge["to"], 
            title=edge["label"], 
            label=edge["label"],
            color="#FFD700",      # Warna garis kuning emas agar kontras
            arrows="to",
            font={"size": 12, "align": "top", "color": "#00FFFF"} # Warna label garis cyan
        )
    
    net.save_graph("graph.html")
    with open("graph.html", "r", encoding="utf-8") as f:
        html = f.read()
    components.html(html, height=520)

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

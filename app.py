import json
import datetime
import requests
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
import re

# 1. Konfigurasi Halaman
st.set_page_config(
    page_title="SecOps AI Copilot - Incident Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# 2. Inisialisasi Session State
if "incidents_db" not in st.session_state:
    st.session_state["incidents_db"] = []

if "selected_incident_id" not in st.session_state:
    st.session_state["selected_incident_id"] = None

# 3. Fungsi Sanitasi & Render Mermaid (PERBARUI BAGIAN INI)
def sanitize_mermaid_id(raw_id: str) -> str:
    clean = re.sub(r'[^a-zA-Z0-9_]', '_', str(raw_id))
    if clean and clean[0].isdigit():
        clean = f"node_{clean}"
    return clean or "node_unk"

def sanitize_mermaid_label(raw_label: str) -> str:
    if not raw_label:
        return ""
    clean = str(raw_label)
    # Hapus backslash, double quotes, dan newline yang merusak sintaks Mermaid
    clean = clean.replace('\\', '/').replace('"', "'").replace("\n", " ").replace("\r", "")
    clean = re.sub(r'[\[\]\{\}\(\)]', '', clean)
    return clean.strip()

def render_mermaid(graph_data):
    if not graph_data:
        st.warning("Data grafik kosong.")
        return

    mermaid_code = ""

    # HANDLING KASUS A: LLM mengembalikan graph sebagai String Mentah (e.g. "graph TD\n...")
    if isinstance(graph_data, str):
        raw_str = graph_data.strip()
        raw_str = re.sub(r'^```(mermaid)?\s*', '', raw_str, flags=re.IGNORECASE)
        raw_str = re.sub(r'\s*```$', '', raw_str)
        
        if not raw_str.startswith("graph "):
            raw_str = "graph TD\n" + raw_str
        mermaid_code = raw_str

    # HANDLING KASUS B: LLM mengembalikan JSON Object (nodes & edges)
    elif isinstance(graph_data, dict):
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])

        if not nodes and not edges:
            st.warning("Data nodes dan edges pada grafik kosong.")
            return

        mermaid_lines = ["graph TD"]
        id_map = {}

        for idx, node in enumerate(nodes):
            if isinstance(node, dict):
                raw_id = str(node.get("id", f"node_{idx}"))
                label = sanitize_mermaid_label(node.get("label", raw_id))
                color = str(node.get("color", "#1E88E5")).strip()
            else:
                raw_id = str(node)
                label = sanitize_mermaid_label(raw_id)
                color = "#1E88E5"

            clean_id = sanitize_mermaid_id(raw_id)
            id_map[raw_id] = clean_id

            if not color.startswith("#"):
                color = "#1E88E5"

            mermaid_lines.append(f'    {clean_id}["{label}"]')
            mermaid_lines.append(f'    style {clean_id} fill:{color},stroke:#333,stroke-width:2px,color:#fff')

        for edge in edges:
            if isinstance(edge, dict):
                raw_from = str(edge.get("from", ""))
                raw_to = str(edge.get("to", ""))
                label = sanitize_mermaid_label(edge.get("label", ""))
            else:
                continue

            from_id = id_map.get(raw_from, sanitize_mermaid_id(raw_from))
            to_id = id_map.get(raw_to, sanitize_mermaid_id(raw_to))

            if from_id and to_id and from_id != "node_unk" and to_id != "node_unk":
                if label:
                    mermaid_lines.append(f'    {from_id} -- "{label}" --> {to_id}')
                else:
                    mermaid_lines.append(f'    {from_id} --> {to_id}')

        mermaid_code = "\n".join(mermaid_lines)

    # Render HTML Component
    html_content = f"""
    <div style="background-color: #0E1117; padding: 15px; border-radius: 8px;">
        <pre class="mermaid">
{mermaid_code}
        </pre>
    </div>
    <script type="module">
        import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
        mermaid.initialize({{ startOnLoad: true, theme: 'dark' }});
    </script>
    """
    components.html(html_content, height=500, scrolling=True)

# ---------------------------------------------------------
# SIDEBAR: Pengiriman Log Baru & Konfigurasi
# ---------------------------------------------------------
with st.sidebar:
    st.header("⚙️ Ingestion & Config")
    n8n_url = st.text_input(
        "n8n Webhook URL",
        value="http://localhost:5678/webhook/secops-analyze"
    )
    
    st.divider()
    st.subheader("📥 Analisis Log Baru")
    uploaded_file = st.file_uploader(
        "Unggah Log (.json, .log, .txt)",
        type=["json", "log", "txt"]
    )
    
    if uploaded_file is not None:
        if st.button("🚀 Process & Append Incident", type="primary", use_container_width=True):
            raw_content = uploaded_file.read().decode("utf-8", errors="ignore")
            with st.spinner("Mengirim ke n8n..."):
                try:
                    response = requests.post(
                        n8n_url,
                        json={"log_data": raw_content, "file_name": uploaded_file.name},
                        headers={"Content-Type": "application/json"},
                        timeout=180
                    )
                    if response.status_code == 200:
                        analysis_result = response.json()
                        
                        # Generate ID & Timestamp untuk DB In-Memory
                        inc_id = f"INC-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
                        inc_entry = {
                            "id": inc_id,
                            "timestamp": datetime.datetime.now(),
                            "file_name": uploaded_file.name,
                            "severity": analysis_result.get("summary", {}).get("severity", "MEDIUM").upper(),
                            "patient_zero": analysis_result.get("summary", {}).get("patient_zero", "Unknown"),
                            "affected_count": analysis_result.get("summary", {}).get("affected_hosts_count", 0),
                            "details": analysis_result
                        }
                        st.session_state["incidents_db"].insert(0, inc_entry)
                        st.success(f"Insiden {inc_id} berhasil didaftarkan!")
                    else:
                        st.error(f"HTTP Error {response.status_code}: {response.text}")
                except Exception as e:
                    st.error(f"Koneksi Gagal: {str(e)}")

# ---------------------------------------------------------
# MAIN PANEL
# ---------------------------------------------------------
st.title("🛡️ SecOps AI Monitoring & Incident Response")

# JIKA MODE DRILL-DOWN AKTIF
if st.session_state["selected_incident_id"] is not None:
    # Cari insiden berdasarkan ID
    selected_inc = next((item for item in st.session_state["incidents_db"] if item["id"] == st.session_state["selected_incident_id"]), None)
    
    if selected_inc:
        col_back, col_title = st.columns([1, 5])
        with col_back:
            if st.button("⬅️ Kembali ke Overview", use_container_width=True):
                st.session_state["selected_incident_id"] = None
                st.rerun()
                
        with col_title:
            st.subheader(f"🔍 Drill-Down Detail: {selected_inc['id']} ({selected_inc['file_name']})")

        data = selected_inc["details"]
        
        tab_summary, tab_graph, tab_timeline, tab_defense = st.tabs([
            "📊 Executive Summary",
            "🕸️ Attack Path Graph",
            "⏱️ Timeline Kejadian",
            "🛡️ Mitigasi & Deteksi"
        ])
        
        summary = data.get("summary", {})
        with tab_summary:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Patient Zero", summary.get("patient_zero", "N/A"))
            c2.metric("Host Terdampak", summary.get("affected_hosts_count", 0))
            sev = str(summary.get("severity", "UNKNOWN")).upper()
            color = "🔴" if sev in ["CRITICAL", "HIGH"] else ("🟡" if sev == "MEDIUM" else "🟢")
            c3.metric("Severity", f"{color} {sev}")
            c4.metric("Waktu Analisis", selected_inc["timestamp"].strftime("%Y-%m-%d %H:%M:%S"))
            
            st.markdown("### Narasi Analisis")
            st.info(summary.get("narrative", "Tidak ada narasi."))
            
        with tab_graph:
            st.markdown("### Rekonstruksi Skema Serangan")
            graph_data = data.get("graph", {})
            if graph_data.get("nodes"):
                render_mermaid(graph_data)
            else:
                st.warning("Data grafik tidak tersedia.")
                
        with tab_timeline:
            st.markdown("### Kronologi Kejadian")
            timeline = data.get("timeline", [])
            if timeline:
                st.dataframe(timeline, use_container_width=True)
            else:
                st.info("Data timeline kosong.")
                
        with tab_defense:
            defense = data.get("defense", {})
            col_sig, col_act = st.columns(2)
            with col_sig:
                st.markdown("### Sigma Detection Rule")
                st.code(defense.get("sigma_rule", ""), language="yaml")
            with col_act:
                st.markdown("### Atomic Remediation Script")
                st.code(defense.get("atomic_script", ""), language="bash")

# ---------------------------------------------------------
# JIKA MODE OVERVIEW DASHBOARD AKTIF
# ---------------------------------------------------------
else:
    st.subheader("📈 Attack Overview & Monitoring Dashboard")
    
    # --- Time Range & Severity Filter ---
    col_f1, col_f2, col_f3 = st.columns([2, 2, 2])
    with col_f1:
        date_range = st.date_input(
            "Rentang Waktu Log",
            value=(datetime.date.today() - datetime.timedelta(days=7), datetime.date.today())
        )
    with col_f2:
        selected_severity = st.multiselect(
            "Filter Severity",
            options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        )
    with col_f3:
        search_query = st.text_input("Cari Host / IP / Patient Zero", value="")

    # Filtering Data
    filtered_db = []
    for inc in st.session_state["incidents_db"]:
        inc_date = inc["timestamp"].date()
        
        # Validasi Rentang Tanggal
        in_date_range = True
        if isinstance(date_range, tuple) and len(date_range) == 2:
            in_date_range = date_range[0] <= inc_date <= date_range[1]
            
        # Validasi Severity & Keyword
        in_sev = inc["severity"] in selected_severity
        in_search = (search_query.lower() in inc["patient_zero"].lower()) or (search_query.lower() in inc["id"].lower())
        
        if in_date_range and in_sev and in_search:
            filtered_db.append(inc)

    # --- Section Top Metrics ---
    m1, m2, m3, m4 = st.columns(4)
    total_incidents = len(filtered_db)
    crit_high_count = sum(1 for i in filtered_db if i["severity"] in ["CRITICAL", "HIGH"])
    total_hosts = sum(i["affected_count"] for i in filtered_db)
    patient_zeros = len(set(i["patient_zero"] for i in filtered_db if i["patient_zero"] != "Unknown"))

    m1.metric("Total Insiden Terdeteksi", total_incidents)
    m2.metric("Critical / High Alerts", crit_high_count, delta_color="inverse")
    m3.metric("Total Host Terdampak", total_hosts)
    m4.metric("Unique Patient Zeros", patient_zeros)

    st.divider()

    # --- Section Visualisasi Tren ---
    if filtered_db:
        st.markdown("### 📊 Tren Frekuensi Serangan")
        df_chart = pd.DataFrame([
            {"Timestamp": i["timestamp"], "Severity": i["severity"], "Count": 1}
            for i in filtered_db
        ])
        df_chart.set_index("Timestamp", inplace=True)
        # Resample harian untuk grafik tren
        trend_data = df_chart.groupby([pd.Grouper(freq="D"), "Severity"]).count().unstack(fill_value=0)
        trend_data.columns = trend_data.columns.droplevel(0)
        st.bar_chart(trend_data)
    
    st.divider()

    # --- Section Tabel Insiden & Drill-down Trigger ---
    st.markdown("### 📋 Daftar Insiden Terdeteksi")
    
    if not filtered_db:
        st.info("Belum ada data insiden dalam rentang waktu/filter ini. Unggah log baru via sidebar.")
    else:
        # Menampilkan Tabel dengan Tombol Action Drill-Down
        for idx, inc in enumerate(filtered_db):
            with st.container():
                c_id, c_time, c_pz, c_sev, c_host, c_act = st.columns([2, 2, 2, 1.5, 1.5, 2])
                c_id.write(f"**{inc['id']}**\n\n_{inc['file_name']}_")
                c_time.write(inc["timestamp"].strftime("%Y-%m-%d %H:%M"))
                c_pz.write(f"`{inc['patient_zero']}`")
                
                # Badge Severity
                sev_color = "🔴" if inc['severity'] in ["CRITICAL", "HIGH"] else ("🟡" if inc['severity'] == "MEDIUM" else "🟢")
                c_sev.write(f"{sev_color} {inc['severity']}")
                
                c_host.write(f"{inc['affected_count']} Host")
                
                # Button Drill-Down
                if c_act.button("🔎 Inspect Attack Path", key=f"btn_{inc['id']}"):
                    st.session_state["selected_incident_id"] = inc["id"]
                    st.rerun()
            st.divider()

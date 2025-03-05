import streamlit as st
import pandas as pd
import re

########################################################
# 1) Load CSV Paths from Streamlit Secrets
########################################################
try:
    fortinet_file_path = st.secrets["FORTINET_CSV_URL"]
    paloalto_file_path = st.secrets["PALOALTO_CSV_URL"]
    sonicwall_file_path = st.secrets["SONICWALL_CSV_URL"]
    sophos_file_path   = st.secrets["SOPHOS_CSV_URL"]
except KeyError as e:
    st.error(f"Missing secret: {e}. Please configure in Streamlit Cloud → Secrets.")
    st.stop()

########################################################
# 2) READ THE CSV FILES
########################################################
def load_csv_data(file_url, vendor_name):
    """Safely load CSV data. Return an empty DataFrame if there's an error."""
    try:
        return pd.read_csv(file_url)
    except Exception as e:
        st.error(f"Could not load {vendor_name} data: {e}")
        return pd.DataFrame()

fortinet_data = load_csv_data(fortinet_file_path, "Fortinet")
paloalto_data = load_csv_data(paloalto_file_path, "Palo Alto")
sonicwall_data = load_csv_data(sonicwall_file_path, "SonicWall")
sophos_data   = load_csv_data(sophos_file_path, "Sophos")

########################################################
# 3) VENDOR-SPECIFIC COLUMNS
########################################################
FORTINET_COLS = [
    "Firewall Throughput (Gbps)",
    "IPS Throughput (Gbps)",
    "Threat Protection Throughput (Gbps)",
    "NGFW Throughput (Gbps)",
    "IPsec VPN Throughput (Gbps)"
]

PALOALTO_COLS = [
    "Firewall Throughput (Gbps)",
    "Threat Protection Throughput (Gbps)",
    "IPsec VPN Throughput (Gbps)"
]

SONICWALL_COLS = [
    "Firewall Throughput (Gbps)",
    "IPS Throughput (Gbps)",
    "Threat Protection Throughput (Gbps)",
    "IPsec VPN Throughput (Gbps)"
]

ALL_COLUMNS = list(set(FORTINET_COLS + PALOALTO_COLS + SONICWALL_COLS))

########################################################
# 4) HELPER: EXTRACT HIGHEST FROM SLASH-STRINGS
########################################################
def extract_max_throughput(value):
    if isinstance(value, str):
        nums = [float(num) for num in re.findall(r"\d+\.?\d*", value)]
        return max(nums) if nums else None
    return value

########################################################
# 5) PARSE + CONVERT (slash -> numeric)
########################################################
def parse_and_convert(df, col_list):
    for c in col_list:
        if c in df.columns:
            df[c] = df[c].apply(extract_max_throughput)
            df[c] = pd.to_numeric(df[c], errors='coerce')

parse_and_convert(fortinet_data, FORTINET_COLS)
parse_and_convert(paloalto_data, PALOALTO_COLS)
parse_and_convert(sonicwall_data, SONICWALL_COLS)
parse_and_convert(sophos_data, ALL_COLUMNS)

########################################################
# 6) UI Improvements (CSS)
########################################################
st.markdown("""
    <style>
    /* Compact table styling */
    table {
        font-size: 14px !important;
        border-collapse: collapse !important;
        width: 100% !important;
    }
    th, td {
        padding: 8px !important;
        text-align: center !important;
        white-space: nowrap !important;  /* Prevent word splitting */
    }
    select {
        font-size: 16px !important;
        padding: 8px !important;
        width: 100% !important;
    }
    </style>
    """, unsafe_allow_html=True)

########################################################
# 7) UI Title & Vendor Selection
########################################################
st.markdown(
    """
    <h1 style='text-align: center; color: green;'>🔥 Firewall Comparison Tool</h1>
    <h4 style='text-align: right;'>✅ Developed by Rajeesh</h4>
    """,
    unsafe_allow_html=True
)
st.write("Select a vendor and model to find the best equivalent Sophos model.")

vendors = ["Fortinet", "Palo Alto", "SonicWall"]
selected_vendor = st.selectbox("Select a Vendor", vendors)

if selected_vendor == "Fortinet":
    use_df, use_cols = fortinet_data, FORTINET_COLS
elif selected_vendor == "Palo Alto":
    use_df, use_cols = paloalto_data, PALOALTO_COLS
elif selected_vendor == "SonicWall":
    use_df, use_cols = sonicwall_data, SONICWALL_COLS
else:
    use_df, use_cols = pd.DataFrame(), []

if use_df.empty or "Model" not in use_df.columns:
    st.warning(f"No models found for {selected_vendor}.")
    st.stop()

selected_model = st.selectbox(f"Select a {selected_vendor} Model", use_df["Model"].dropna().unique())
comp_row = use_df.loc[use_df["Model"] == selected_model].iloc[0]

st.write("## 🔍 Selected Model Details")
st.table(comp_row.to_frame().T)

########################################################
# 8) Compare Button
########################################################
if st.button("Compare Model"):
    mask_any = pd.Series([False]*len(sophos_data), index=sophos_data.index)

    for i, s_row in sophos_data.iterrows():
        for c in use_cols:
            if c in comp_row and c in s_row and pd.notnull(comp_row[c]) and pd.notnull(s_row[c]):
                if s_row[c] >= comp_row[c]:
                    mask_any[i] = True
                    break

    filtered_sophos = sophos_data[mask_any]

    if filtered_sophos.empty:
        st.error("⚠️ No suitable Sophos model found. Please consult StarLiNK Presales Consultant.")
        st.stop()

    idx_min = filtered_sophos["Firewall Throughput (Gbps)"].idxmin()
    chosen_model = filtered_sophos.loc[idx_min]

    st.success(f"✅ Best match found: {chosen_model['Model']}")

    ########################################################
    # 9) Side-by-Side Table Layout
    ########################################################
    col1, col2 = st.columns(2)

    with col1:
        st.write("## 🔹 Selected Model")
        st.table(comp_row.to_frame().T)

    with col2:
        st.write("## 🔹 Suggested Sophos Model")
        st.table(chosen_model.to_frame().T)

    ########################################################
    # 10) Manual Selection
    ########################################################
    st.markdown("### ✍️ Manually Select a Sophos Model")
    manual_select = st.checkbox("Manually select Sophos model?")
    if manual_select:
        chosen_sophos_model = st.selectbox("Choose a Sophos Model", sophos_data["Model"].dropna().unique())
        if chosen_sophos_model:
            chosen_model = sophos_data.loc[sophos_data["Model"] == chosen_sophos_model].iloc[0]
            st.write("## 🎯 Chosen Sophos Model")
            st.table(chosen_model.to_frame().T)

# 11) MANUAL LOGIC
########################################################
else:
    st.write("## Select a Sophos Model Manually")
    chosen_sophos_model = st.selectbox("Choose a Sophos Model", sophos_data["Model"].dropna().unique())

    if chosen_sophos_model:
        chosen_model = sophos_data.loc[sophos_data["Model"] == chosen_sophos_model].iloc[0]

        st.write("## Chosen Sophos Model")
        st.table(chosen_model.to_frame().T)

        st.write("## Matching Score")
        dev_table = build_matching_table(
            selected_vendor,  
            comp_row,
            chosen_model,
            chosen_sophos_model,
            use_cols
        )
        st.table(dev_table)

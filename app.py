import streamlit as st
import pandas as pd
import re

########################################################
# 1) CSV PATHS (EDIT THESE)
fortinet_file_path = "C:/Users/RajeeshNair/OneDrive - StarLink/Desktop/CyberSecurityComparison/Fortinet FW Models.csv"
paloalto_file_path = "C:/Users/RajeeshNair/OneDrive - StarLink/Desktop/CyberSecurityComparison/PaloAlto Spec.csv"
sophos_file_path   = "C:/Users/RajeeshNair/OneDrive - StarLink/Desktop/CyberSecurityComparison/Sophos_XGS_All_Models_Performance.csv"

########################################################
# 2) READ THE CSV FILES
try:
    fortinet_data = pd.read_csv(fortinet_file_path)
except Exception as e:
    st.error(f"Could not load Fortinet data: {e}")
    fortinet_data = pd.DataFrame()

try:
    paloalto_data = pd.read_csv(paloalto_file_path)
except Exception as e:
    st.error(f"Could not load Palo Alto data: {e}")
    paloalto_data = pd.DataFrame()

try:
    sophos_data = pd.read_csv(sophos_file_path)
except Exception as e:
    st.error(f"Could not load Sophos data: {e}")
    sophos_data = pd.DataFrame()

########################################################
# 3) VENDOR-SPECIFIC COLUMNS
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

# We'll parse the union of these for Sophos as well
ALL_COLUMNS = list(set(FORTINET_COLS + PALOALTO_COLS))

########################################################
# 4) HELPER: EXTRACT HIGHEST FROM SLASH-STRINGS
# e.g. "39 / 39 / 26.5" => 39.0
########################################################
def extract_max_throughput(value):
    if isinstance(value, str):
        nums = [float(num) for num in re.findall(r"\d+\.?\d*", value)]
        return max(nums) if nums else None
    return value

# We'll parse each relevant column for each vendor DF

########################################################
# 5) PARSE HIGHEST VALUE + CONVERT TO NUMERIC
########################################################
def parse_and_convert(df, col_list):
    for c in col_list:
        if c in df.columns:
            # parse slash-based strings => highest
            df[c] = df[c].apply(extract_max_throughput)
            # then convert to numeric
            df[c] = pd.to_numeric(df[c], errors='coerce')

# Parse for Fortinet, PaloAlto, then unify for Sophos
parse_and_convert(fortinet_data, FORTINET_COLS)
parse_and_convert(paloalto_data, PALOALTO_COLS)
parse_and_convert(sophos_data, ALL_COLUMNS)

########################################################
# 6) UI Title
########################################################
st.markdown(
    """
    <h1 style='text-align: center; color: green;'>Firewall Comparison Tool</h1>
    <h4 style='text-align: right;'>Developed by Rajeesh</h4>
    """,
    unsafe_allow_html=True
)
st.write("Select a vendor and model to find the best equivalent Sophos model.")

########################################################
# 7) CHOOSE A VENDOR
########################################################
vendors = ["Fortinet", "Palo Alto", "SonicWall"]
selected_vendor = st.selectbox("Select a Vendor", vendors)

if selected_vendor == "Fortinet":
    use_df = fortinet_data
    use_cols = FORTINET_COLS
elif selected_vendor == "Palo Alto":
    use_df = paloalto_data
    use_cols = PALOALTO_COLS
else:
    # SonicWall => fallback
    use_df = pd.DataFrame()
    use_cols = []

if selected_vendor == "SonicWall":
    st.warning("Please connect to StarLiNK Presales Consultant.")
    st.stop()

# If empty => no data
if use_df.empty:
    st.warning(f"No {selected_vendor} data found.")
    st.stop()

if "Model" not in use_df.columns or use_df["Model"].dropna().empty:
    st.warning(f"No models found in {selected_vendor} data.")
    st.stop()

selected_model = st.selectbox(f"Select a {selected_vendor} Model", use_df["Model"].dropna().unique())

comp_row = use_df.loc[use_df["Model"] == selected_model].iloc[0]

st.write(f"## Selected {selected_vendor} Model Details")
st.table(comp_row.to_frame().T)

########################################################
# 8) Manual vs Automatic selection of Sophos
########################################################
manual_select = st.checkbox("Manually select Sophos model?")

########################################################
# Helper to build matching score table
########################################################
def build_matching_table(vendor_name, vendor_row, sophos_row, sophos_model_name, relevant_cols):
    dev_dict = {}
    for c in relevant_cols:
        v_val = vendor_row.get(c, None)
        s_val = sophos_row.get(c, None)
        if pd.notnull(v_val) and v_val != 0 and pd.notnull(s_val):
            ratio = (s_val / v_val) * 100
            ratio_str = f"{ratio:.1f}%"
        else:
            ratio_str = "N/A"
        dev_dict[c] = [v_val, s_val, ratio_str]

    table = pd.DataFrame(
        dev_dict,
        index=[
            f"{selected_model} Value",       # e.g. FG-70F Value
            f"{sophos_model_name} Value",   # e.g. XGS88 Value
            "Matching (%)"
        ]
    )
    return table

########################################################
# 9) AUTO LOGIC (if manual_select==False)
########################################################
if not manual_select:
    # filter sophos => ANY col >= comp_row
    mask_any = pd.Series([False]*len(sophos_data), index=sophos_data.index)

    for i, s_row in sophos_data.iterrows():
        for c in use_cols:
            if c not in comp_row or c not in s_row:
                continue
            f_val = comp_row[c]
            so_val= s_row[c]
            if pd.notnull(f_val) and pd.notnull(so_val):
                if so_val >= f_val:
                    mask_any[i] = True
                    break

    filtered_sophos = sophos_data[mask_any]

    if filtered_sophos.empty:
        st.write("Please connect to StarLiNK Presales Consultant..")
        st.stop()

    # among these, pick minimal firewall throughput
    if "Firewall Throughput (Gbps)" not in filtered_sophos.columns:
        st.write("No 'Firewall Throughput (Gbps)' col in filtered set.")
        st.stop()

    sub = filtered_sophos[ filtered_sophos["Firewall Throughput (Gbps)"].notnull() ]
    if sub.empty:
        st.write("No valid firewall throughput in the filtered set.")
        st.stop()

    idx_min = sub["Firewall Throughput (Gbps)"].idxmin()
    chosen_model = sub.loc[idx_min]

    st.write("## Suggested Sophos Model")
    st.table(chosen_model.to_frame().T)

    st.write("## Matching Score")
    dev_table = build_matching_table(
        selected_vendor,     # e.g. 'Fortinet' or 'Palo Alto'
        comp_row,
        chosen_model,
        chosen_model["Model"],
        use_cols
    )
    st.table(dev_table)

########################################################
# 10) MANUAL LOGIC
########################################################
else:
    st.write("## Select a Sophos Model Manually")
    if "Model" not in sophos_data.columns or sophos_data["Model"].dropna().empty:
        st.error("No Sophos data available!")
        st.stop()

    chosen_sophos_model = st.selectbox("Choose a Sophos Model", sophos_data["Model"].dropna().unique())

    if chosen_sophos_model:
        chosen_model = sophos_data.loc[sophos_data["Model"] == chosen_sophos_model].iloc[0]

        st.write("## Chosen Sophos Model")
        st.table(chosen_model.to_frame().T)

        st.write("## Matching Score")
        dev_table = build_matching_table(
            selected_vendor,   # 'Fortinet' or 'Palo Alto'
            comp_row,
            chosen_model,
            chosen_sophos_model,
            use_cols
        )
        st.table(dev_table)

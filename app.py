import streamlit as st
import pandas as pd
import re

################################################################################
# STEP 1: Load data from secrets into st.session_state once
################################################################################
def extract_max_throughput(value):
    """Extracts highest float from strings like '39 / 39 / 26.5'."""
    if isinstance(value, str):
        nums = [float(num) for num in re.findall(r"\d+\.?\d*", value)]
        return max(nums) if nums else None
    return value

def parse_and_convert(df, col_list):
    """Convert slash-based string columns into numeric floats."""
    for c in col_list:
        if c in df.columns:
            df[c] = df[c].apply(extract_max_throughput)
            df[c] = pd.to_numeric(df[c], errors='coerce')

FORTINET_COLS = [
    "Firewall Throughput (Gbps)",
    "IPS Throughput (Gbps)",
    "Threat Protection Throughput (Gbps)",
    "NGFW Throughput (Gbps)",
    "IPsec VPN Throughput (Gbps)",
]
PALOALTO_COLS = [
    "Firewall Throughput (Gbps)",
    "Threat Protection Throughput (Gbps)",
    "IPsec VPN Throughput (Gbps)",
]
ALL_COLUMNS = list(set(FORTINET_COLS + PALOALTO_COLS))


def load_vendor_data():
    """Loads and parses CSVs from secrets, then saves them to session_state."""
    if "fortinet_data" not in st.session_state:
        try:
            fortinet_df = pd.read_csv(st.secrets["FORTINET_CSV_URL"])
        except Exception as e:
            st.error(f"Could not load Fortinet data: {e}")
            fortinet_df = pd.DataFrame()
        parse_and_convert(fortinet_df, FORTINET_COLS)
        st.session_state["fortinet_data"] = fortinet_df

    if "paloalto_data" not in st.session_state:
        try:
            paloalto_df = pd.read_csv(st.secrets["PALOALTO_CSV_URL"])
        except Exception as e:
            st.error(f"Could not load Palo Alto data: {e}")
            paloalto_df = pd.DataFrame()
        parse_and_convert(paloalto_df, PALOALTO_COLS)
        st.session_state["paloalto_data"] = paloalto_df

    if "sophos_data" not in st.session_state:
        try:
            sophos_df = pd.read_csv(st.secrets["SOPHOS_CSV_URL"])
        except Exception as e:
            st.error(f"Could not load Sophos data: {e}")
            sophos_df = pd.DataFrame()
        parse_and_convert(sophos_df, ALL_COLUMNS)
        st.session_state["sophos_data"] = sophos_df

# Load data ONCE per session
load_vendor_data()

fortinet_data = st.session_state["fortinet_data"]
paloalto_data = st.session_state["paloalto_data"]
sophos_data   = st.session_state["sophos_data"]

################################################################################
# STEP 2: Build the UI
################################################################################
st.markdown(
    """
    <h1 style='text-align: center; color: green;'>Firewall Comparison Tool</h1>
    <h4 style='text-align: right;'>Developed by Rajeesh</h4>
    """,
    unsafe_allow_html=True
)
st.write("Select a vendor and model to find the best equivalent Sophos model.")

vendors = ["Fortinet", "Palo Alto", "SonicWall"]

# We'll wrap vendor & model selection in a form
with st.form("vendor_selection"):
    selected_vendor = st.selectbox("Select a Vendor", vendors)
    submit_vendor = st.form_submit_button("Confirm Vendor")

if not submit_vendor:
    st.stop()  # Wait until user picks a vendor

################################################################################
# STEP 3: Decide which DF & columns to use
################################################################################
if selected_vendor == "Fortinet":
    use_df = fortinet_data
    use_cols = FORTINET_COLS
elif selected_vendor == "Palo Alto":
    use_df = paloalto_data
    use_cols = PALOALTO_COLS
else:
    # SonicWall => fallback
    st.warning("Please connect to StarLiNK Presales Consultant.")
    st.stop()

if use_df.empty:
    st.warning(f"No {selected_vendor} data found.")
    st.stop()

if "Model" not in use_df.columns or use_df["Model"].dropna().empty:
    st.warning(f"No models found in {selected_vendor} data.")
    st.stop()

################################################################################
# STEP 4: Model selection and Manual vs Automatic logic
################################################################################
with st.form("model_selection"):
    selected_model = st.selectbox(
        f"Select a {selected_vendor} Model",
        use_df["Model"].dropna().unique()
    )
    manual_select = st.checkbox("Manually select Sophos model?")
    submit_model = st.form_submit_button("Compare")

if not submit_model:
    st.stop()  # Wait for user to choose a model & confirm

comp_row = use_df.loc[use_df["Model"] == selected_model].iloc[0]
st.write(f"## Selected {selected_vendor} Model Details")
st.table(comp_row.to_frame().T)

################################################################################
# Helper to build matching score table
################################################################################
def build_matching_table(vendor_model_name, vendor_row, sophos_row, sophos_model_name, relevant_cols):
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
            f"{vendor_model_name} Value",   # e.g. FG-70F Value
            f"{sophos_model_name} Value",   # e.g. XGS88 Value
            "Matching (%)"
        ]
    )
    return table

################################################################################
# AUTO LOGIC
################################################################################
if not manual_select:
    # Vectorized approach: ANY column in use_cols >= comp_row
    # Build a combined boolean mask
    mask_any = False
    for c in use_cols:
        # if the column doesn't exist or comp_row is missing, skip
        if c not in comp_row or c not in sophos_data.columns:
            continue
        fort_val = comp_row[c]
        mask_any = mask_any | (sophos_data[c] >= fort_val)

    filtered_sophos = sophos_data[mask_any]

    if filtered_sophos.empty:
        st.write("Please connect to StarLiNK Presales Consultant..")
        st.stop()

    if "Firewall Throughput (Gbps)" not in filtered_sophos.columns:
        st.write("No 'Firewall Throughput (Gbps)' col in filtered set.")
        st.stop()

    sub = filtered_sophos[filtered_sophos["Firewall Throughput (Gbps)"].notnull()]
    if sub.empty:
        st.write("No valid firewall throughput in the filtered set.")
        st.stop()

    idx_min = sub["Firewall Throughput (Gbps)"].idxmin()
    chosen_model = sub.loc[idx_min]

    st.write("## Suggested Sophos Model")
    st.table(chosen_model.to_frame().T)

    st.write("## Matching Score")
    dev_table = build_matching_table(
        selected_model,  # e.g. 'FG-70F' or 'PA-220'
        comp_row,
        chosen_model,
        chosen_model["Model"],
        use_cols
    )
    st.table(dev_table)

################################################################################
# MANUAL LOGIC
################################################################################
else:
    st.write("## Select a Sophos Model Manually")
    if "Model" not in sophos_data.columns or sophos_data["Model"].dropna().empty:
        st.error("No Sophos data available!")
        st.stop()

    chosen_sophos_model = st.selectbox(
        "Choose a Sophos Model",
        sophos_data["Model"].dropna().unique()
    )
    if chosen_sophos_model:
        chosen_model = sophos_data.loc[sophos_data["Model"] == chosen_sophos_model].iloc[0]

        st.write("## Chosen Sophos Model")
        st.table(chosen_model.to_frame().T)

        st.write("## Matching Score")
        dev_table = build_matching_table(
            selected_model,
            comp_row,
            chosen_model,
            chosen_sophos_model,
            use_cols
        )
        st.table(dev_table)

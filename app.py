import streamlit as st
import pandas as pd
import re

##############################################################################
# HELPER 1: EXTRACT MAX THROUGHPUT FROM STRINGS LIKE "39 / 39 / 26.5"
##############################################################################
def extract_max_throughput(value):
    if isinstance(value, str):
        nums = [float(num) for num in re.findall(r"\d+\.?\d*", value)]
        return max(nums) if nums else None
    return value

##############################################################################
# HELPER 2: PARSE & CONVERT COLUMNS (Slash-based strings -> numeric floats)
##############################################################################
def parse_and_convert(df, col_list):
    for c in col_list:
        if c in df.columns:
            df[c] = df[c].apply(extract_max_throughput)
            df[c] = pd.to_numeric(df[c], errors='coerce')

##############################################################################
# RELEVANT COLUMNS FOR EACH VENDOR
##############################################################################
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
ALL_COLUMNS = list(set(FORTINET_COLS + PALOALTO_COLS))

##############################################################################
# STEP 1: LOAD CSVs FROM SECRETS INTO SESSION_STATE ONCE
##############################################################################
def load_csvs_into_session():
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

# Load data once per user session
load_csvs_into_session()

fortinet_data = st.session_state["fortinet_data"]
paloalto_data = st.session_state["paloalto_data"]
sophos_data   = st.session_state["sophos_data"]

##############################################################################
# UI Title
##############################################################################
st.markdown(
    """
    <h1 style='text-align: center; color: green;'>Firewall Comparison Tool</h1>
    <h4 style='text-align: right;'>Developed by Rajeesh</h4>
    """,
    unsafe_allow_html=True
)
st.write("Select a vendor and model to find the best equivalent Sophos model.")

##############################################################################
# SINGLE FORM FOR VENDOR & MODEL SELECTION
##############################################################################
with st.form("selection_form"):
    # 1) Pick Vendor
    vendors = ["Fortinet", "Palo Alto", "SonicWall"]
    selected_vendor = st.selectbox("Select a Vendor", vendors)
    
    # 2) If vendor is SonicWall => fallback
    if selected_vendor == "Fortinet":
        use_df  = fortinet_data
        use_cols = FORTINET_COLS
    elif selected_vendor == "Palo Alto":
        use_df  = paloalto_data
        use_cols = PALOALTO_COLS
    else:
        # SonicWall => fallback
        use_df  = pd.DataFrame()
        use_cols = []

    # 3) If vendor DF is empty => warn
    if selected_vendor == "SonicWall":
        st.warning("Please connect to StarLiNK Presales Consultant.")
    elif use_df.empty:
        st.warning(f"No {selected_vendor} data found.")
    else:
        # 4) Select Model
        model_list = use_df["Model"].dropna().unique() if "Model" in use_df.columns else []
        selected_model = st.selectbox(f"Select a {selected_vendor} Model", model_list)

    # 5) Manual or Automatic approach
    manual_select = st.checkbox("Manually select Sophos model?")

    # 6) Press the Compare button
    compare_button = st.form_submit_button("Compare")

##############################################################################
# AFTER SUBMIT
##############################################################################
if not compare_button:
    st.stop()  # Wait until user clicks Compare

# if user clicked Compare, proceed
if selected_vendor == "SonicWall" or use_df.empty:
    st.stop()

# check if Model was selected
if "Model" not in use_df.columns or len(model_list) == 0:
    st.stop()

# get competitor row
comp_row = use_df.loc[use_df["Model"] == selected_model].iloc[0]

st.write(f"## Selected {selected_vendor} Model Details")
st.table(comp_row.to_frame().T)

##############################################################################
# HELPER: BUILD MATCHING TABLE
##############################################################################
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
            f"{vendor_model_name} Value",
            f"{sophos_model_name} Value",
            "Matching (%)"
        ]
    )
    return table

##############################################################################
# AUTO LOGIC => ANY col >= competitor, pick minimal firewall throughput
##############################################################################
if not manual_select:
    # vectorized approach
    mask_any = False
    for c in use_cols:
        if c not in comp_row or c not in sophos_data.columns:
            continue
        f_val = comp_row[c]
        mask_any = mask_any | (sophos_data[c] >= f_val)

    filtered_sophos = sophos_data[mask_any]

    if filtered_sophos.empty:
        st.write("Please connect to StarLiNK Presales Consultant..")
        st.stop()

    if "Firewall Throughput (Gbps)" not in filtered_sophos.columns:
        st.write("No 'Firewall Throughput (Gbps)' col in the filtered set.")
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
        selected_model,
        comp_row,
        chosen_model,
        chosen_model["Model"],
        use_cols
    )
    st.table(dev_table)

##############################################################################
# MANUAL LOGIC => user picks from all Sophos
##############################################################################
else:
    st.write("## Select a Sophos Model Manually")
    if "Model" not in sophos_data.columns or sophos_data["Model"].dropna().empty:
        st.error("No Sophos data available!")
        st.stop()

    # user picks from entire sophos data
    chosen_sophos_model = st.selectbox("Choose a Sophos Model", sophos_data["Model"].dropna().unique())
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

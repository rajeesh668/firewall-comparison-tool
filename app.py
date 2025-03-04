import streamlit as st
import pandas as pd
import re

##############################################################################
# 1) HELPER: EXTRACT MAX THROUGHPUT
##############################################################################
def extract_max_throughput(value):
    if isinstance(value, str):
        nums = [float(num) for num in re.findall(r"\\d+\\.?\\d*", value)]
        return max(nums) if nums else None
    return value

def parse_and_convert(df, cols):
    """Parse slash-based strings into numeric floats for columns in cols."""
    for c in cols:
        if c in df.columns:
            df[c] = df[c].apply(extract_max_throughput)
            df[c] = pd.to_numeric(df[c], errors='coerce')

##############################################################################
# 2) RELEVANT COLUMNS
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
# 3) LOAD CSV ONCE INTO st.session_state
##############################################################################
def load_csvs_once():
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

load_csvs_once()

fortinet_data = st.session_state["fortinet_data"]
paloalto_data = st.session_state["paloalto_data"]
sophos_data   = st.session_state["sophos_data"]

##############################################################################
# 4) BUILD MATCHING TABLE
##############################################################################
def build_matching_table(vendor_model, vendor_row, sophos_row, sophos_model_name, relevant_cols):
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

    return pd.DataFrame(
        dev_dict,
        index=[
            f"{vendor_model} Value",  
            f"{sophos_model_name} Value",
            "Matching (%)"
        ]
    )

##############################################################################
# 5) UI TITLE
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
# 6) SELECT VENDOR & MODEL (ONE FORM)
##############################################################################
with st.form("main_form"):
    vendors = ["Fortinet", "Palo Alto", "SonicWall"]
    selected_vendor = st.selectbox("Select a Vendor", vendors)
    submit_vendor = st.form_submit_button("Confirm Vendor")

if selected_vendor == "SonicWall":
    st.warning("Please connect to StarLiNK Presales Consultant.")
    st.stop()

# Decide which DF & columns to use
if selected_vendor == "Fortinet":
    use_df = fortinet_data
    use_cols = FORTINET_COLS
elif selected_vendor == "Palo Alto":
    use_df = paloalto_data
    use_cols = PALOALTO_COLS
else:
    use_df = pd.DataFrame()
    use_cols = []

if use_df.empty:
    st.warning(f"No {selected_vendor} data found.")
    st.stop()

if "Model" not in use_df.columns or use_df["Model"].dropna().empty:
    st.warning(f"No models found in {selected_vendor} data.")
    st.stop()

##############################################################################
# 7) Now choose model & compare
##############################################################################
model_list = use_df["Model"].dropna().unique()
chosen_model = st.selectbox(f"Select a {selected_vendor} Model", model_list)
compare_button = st.button("Compare Model")

if not compare_button:
    st.stop()

comp_row = use_df.loc[use_df["Model"] == chosen_model].iloc[0]

st.write(f"## Selected {selected_vendor} Model Details")
st.table(comp_row.to_frame().T)

##############################################################################
# 8) AUTO SELECT => ANY Column >= comp_row => pick minimal firewall throughput
##############################################################################
mask_any = False
for c in use_cols:
    if c not in comp_row or c not in sophos_data.columns:
        continue
    mask_any = mask_any | (sophos_data[c] >= comp_row[c])

filtered_sophos = sophos_data[mask_any]

if filtered_sophos.empty:
    st.write("Please connect to StarLiNK Presales Consultant..")
    st.stop()

if "Firewall Throughput (Gbps)" not in filtered_sophos.columns:
    st.write("No 'Firewall Throughput (Gbps)' col in filtered set.")
    st.stop()

sub = filtered_sophos[ filtered_sophos["Firewall Throughput (Gbps)"].notnull() ]
if sub.empty:
    st.write("No valid firewall throughput in the filtered set.")
    st.stop()

idx_min = sub["Firewall Throughput (Gbps)"].idxmin()
auto_chosen = sub.loc[idx_min]

st.write("## Auto-Suggested Sophos Model")
st.table(auto_chosen.to_frame().T)

st.write("## Matching Score")
auto_table = build_matching_table(
    chosen_model,
    comp_row,
    auto_chosen,
    auto_chosen["Model"],
    use_cols
)
st.table(auto_table)

##############################################################################
# 9) MANUAL SELECTION: Only after auto result
##############################################################################
st.write("---")
st.write("### Alternatively, manually select a Sophos model?")
manual_select = st.checkbox("Manually select & override the above suggestion")

if manual_select:
    # user picks from entire sophos_data
    if "Model" not in sophos_data.columns or sophos_data["Model"].dropna().empty:
        st.error("No Sophos data available!")
        st.stop()

    chosen_sophos_model = st.selectbox("Choose a Sophos Model", sophos_data["Model"].dropna().unique())
    override_button = st.button("Use This Model Instead")

    if override_button:
        chosen_override = sophos_data.loc[sophos_data["Model"] == chosen_sophos_model].iloc[0]
        st.write("## Manually Chosen Sophos Model")
        st.table(chosen_override.to_frame().T)

        st.write("## Matching Score (Manual Override)")
        override_table = build_matching_table(
            chosen_model,
            comp_row,
            chosen_override,
            chosen_sophos_model,
            use_cols
        )
        st.table(override_table)

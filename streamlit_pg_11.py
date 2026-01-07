import os
import hashlib
import time

import pandas as pd
import streamlit as st
from sqlalchemy import create_engine, text

# -------------------------------------------------
# BASIC CONFIG
# -------------------------------------------------
st.set_page_config(page_title="🎟️ Event Management System", layout="wide")

# --- CSS: center align table content and loading spinner ---
st.markdown("""
    <style>
    [data-testid="stTable"] td, [data-testid="stTable"] th {
        text-align: center !important;
    }
    div[data-testid="stDataFrame"] div[class^="st-"] {
        text-align: center !important;
    }
    .stDataFrame th {
        text-align: center !important;
    }
    .loading-spinner {
        display: flex;
        justify-content: center;
        align-items: center;
        flex-direction: column;
        padding: 2rem;
    }
    .spinner {
        border: 4px solid #f3f3f3;
        border-top: 4px solid #3498db;
        border-radius: 50%;
        width: 50px;
        height: 50px;
        animation: spin 1s linear infinite;
        margin-bottom: 1rem;
    }
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    </style>
""", unsafe_allow_html=True)

# -------------------------------------------------
# SESSION STATE
# -------------------------------------------------
if "active_tab" not in st.session_state:
    st.session_state.active_tab = "📊 Dashboard"
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "user_role" not in st.session_state:
    st.session_state.user_role = None
if "processing" not in st.session_state:
    st.session_state.processing = False

# -------------------------------------------------
# CONSTANTS / HELPERS
# -------------------------------------------------
def _get_password(key: str) -> str | None:
    # Try secrets -> env -> None
    return (
        st.secrets.get("app_passwords", {}).get(key)
        if "app_passwords" in st.secrets
        else os.getenv(key.upper())
    )

ADMIN_RESET_PASSWORD = _get_password("admin_reset") or _get_password("admin")
MENU_UPDATE_PASSWORD = _get_password("menu_update") or _get_password("admin")
DEFAULT_ADMIN_PASSWORD = _get_password("default_admin") or "admin123"

def hash_password(password: str) -> str:
    """Hash password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()

def now_ts() -> str:
    """Return ISO 8601 timestamp with timezone to keep ordering reliable."""
    return pd.Timestamp.now(tz="UTC").isoformat()

# -------------------------------------------------
# DB CONNECTION & CACHED LOAD
# -------------------------------------------------
@st.cache_resource
def get_engine():
    db_url = st.secrets["connections"]["postgresql"]["url"]
    return create_engine(db_url, pool_pre_ping=True, pool_recycle=1800)

def init_users_table():
    """Initialize users and permissions tables if they don't exist."""
    engine = get_engine()
    with engine.begin() as conn:
        # Create users table
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS app_users (
                username VARCHAR(100) PRIMARY KEY,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) NOT NULL DEFAULT 'guest',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        
        # Create permissions table
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS user_permissions (
                username VARCHAR(100) REFERENCES app_users(username) ON DELETE CASCADE,
                tab_name VARCHAR(50) NOT NULL,
                can_view BOOLEAN DEFAULT FALSE,
                can_edit BOOLEAN DEFAULT FALSE,
                PRIMARY KEY (username, tab_name)
            )
        """))
        
        # Create default admin user if not exists
        admin_hash = hash_password(DEFAULT_ADMIN_PASSWORD)
        conn.execute(text("""
            INSERT INTO app_users (username, password_hash, role)
            VALUES ('admin', :admin_hash, 'admin')
            ON CONFLICT (username) DO NOTHING
        """), {"admin_hash": admin_hash})
        
        # Set default admin permissions (full access)
        tabs = ["Dashboard", "Sales", "Visitors", "Edit Menu"]
        for tab in tabs:
            conn.execute(text("""
                INSERT INTO user_permissions (username, tab_name, can_view, can_edit)
                VALUES ('admin', :tab, TRUE, TRUE)
                ON CONFLICT (username, tab_name) DO UPDATE
                SET can_view = TRUE, can_edit = TRUE
            """), {"tab": tab})
        
        # Set default permissions for 'bulk_upload' feature
        conn.execute(text("""
            INSERT INTO user_permissions (username, tab_name, can_view, can_edit)
            VALUES ('admin', 'Bulk Upload', TRUE, TRUE)
            ON CONFLICT (username, tab_name) DO UPDATE
            SET can_view = TRUE, can_edit = TRUE
        """))

def load_users():
    """Load users from database."""
    try:
        engine = get_engine()
        users_df = pd.read_sql("SELECT * FROM app_users", engine)
        return users_df
    except Exception:
        return pd.DataFrame(columns=["username", "password_hash", "role"])

def load_permissions():
    """Load permissions from database."""
    try:
        engine = get_engine()
        perms_df = pd.read_sql("SELECT * FROM user_permissions", engine)
        return perms_df
    except Exception:
        return pd.DataFrame(columns=["username", "tab_name", "can_view", "can_edit"])

def save_user(username: str, password: str, role: str):
    """Save or update user."""
    engine = get_engine()
    password_hash = hash_password(password)
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO app_users (username, password_hash, role)
            VALUES (:username, :password_hash, :role)
            ON CONFLICT (username) DO UPDATE
            SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role
        """), {"username": username, "password_hash": password_hash, "role": role})

def save_permission(username: str, tab_name: str, can_view: bool, can_edit: bool):
    """Save or update permission."""
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO user_permissions (username, tab_name, can_view, can_edit)
            VALUES (:username, :tab_name, :can_view, :can_edit)
            ON CONFLICT (username, tab_name) DO UPDATE
            SET can_view = EXCLUDED.can_view, can_edit = EXCLUDED.can_edit
        """), {"username": username, "tab_name": tab_name, "can_view": can_view, "can_edit": can_edit})

def authenticate_user(username: str, password: str) -> tuple[bool, str]:
    """Authenticate user and return (success, role)."""
    try:
        engine = get_engine()
        password_hash = hash_password(password)
        with engine.connect() as conn:
            result = pd.read_sql(
                text("SELECT role FROM app_users WHERE username = :username AND password_hash = :password_hash"),
                conn,
                params={"username": username, "password_hash": password_hash}
            )
        if not result.empty:
            return True, result.iloc[0]["role"]
        return False, None
    except Exception:
        return False, None

def get_user_permissions(username: str) -> dict:
    """Get permissions for a user."""
    try:
        engine = get_engine()
        with engine.connect() as conn:
            perms_df = pd.read_sql(
                text("SELECT tab_name, can_view, can_edit FROM user_permissions WHERE username = :username"),
                conn,
                params={"username": username}
            )
        permissions = {}
        for _, row in perms_df.iterrows():
            permissions[row["tab_name"]] = {
                "can_view": bool(row["can_view"]),
                "can_edit": bool(row["can_edit"])
            }
        return permissions
    except Exception:
        return {}

def check_permission(username: str, tab_name: str, action: str = "view") -> bool:
    """Check if user has permission for a tab."""
    if not username:
        return False
    permissions = get_user_permissions(username)
    if tab_name not in permissions:
        return False
    if action == "view":
        return permissions[tab_name]["can_view"]
    elif action == "edit":
        return permissions[tab_name]["can_edit"]
    return False

def show_loading_spinner(message: str = "Processing..."):
    """Display loading spinner."""
    st.markdown(f"""
        <div class="loading-spinner">
            <div class="spinner"></div>
            <p style="font-size: 1.2em; color: #3498db;">{message}</p>
        </div>
    """, unsafe_allow_html=True)

# Initialize users table
try:
    init_users_table()
except Exception as e:
    st.warning(f"Could not initialize users table: {str(e)}")

@st.cache_data(ttl=60, show_spinner=False)
def load_all_data():
    engine = get_engine()
    tickets_df = pd.read_sql("SELECT * FROM tickets", engine)
    menu_df = pd.read_sql("SELECT * FROM menu", engine)

    # Normalize column names - check for case-insensitive matches and common variations
    column_map = {}
    for col in tickets_df.columns:
        col_lower = col.lower().strip()
        # Map TicketID variations
        if col_lower in ["ticketid", "ticket_id"] and col != "TicketID":
            column_map[col] = "TicketID"
        # Map other columns
        elif col_lower == "visitor_seats" and col != "Visitor_Seats":
            column_map[col] = "Visitor_Seats"
        elif col_lower == "sold" and col != "Sold":
            column_map[col] = "Sold"
        elif col_lower == "visited" and col != "Visited":
            column_map[col] = "Visited"
        elif col_lower == "customer" and col != "Customer":
            column_map[col] = "Customer"
        elif col_lower == "admit" and col != "Admit":
            column_map[col] = "Admit"
        elif col_lower == "seq" and col != "Seq":
            column_map[col] = "Seq"
        elif col_lower == "timestamp" and col != "Timestamp":
            column_map[col] = "Timestamp"
        elif col_lower == "type" and col != "Type":
            column_map[col] = "Type"
        elif col_lower == "category" and col != "Category":
            column_map[col] = "Category"
    
    if column_map:
        tickets_df = tickets_df.rename(columns=column_map)
    
    # Handle empty table after normalization
    if tickets_df.empty:
        # Return empty dataframe with required columns
        tickets_df = pd.DataFrame(columns=["TicketID", "Category", "Type", "Admit", "Seq", "Sold", "Visited", "Customer", "Visitor_Seats", "Timestamp"])
        return tickets_df, menu_df
    
    # Verify TicketID column exists (required) - only check if table is not empty
    if "TicketID" not in tickets_df.columns:
        available_cols = ', '.join(tickets_df.columns.tolist())
        raise ValueError(
            f"TicketID column is required but not found in tickets table. "
            f"Available columns: {available_cols}. "
            f"Please ensure your database table has a 'TicketID' or 'ticket_id' column."
        )
    
    # Normalize / clean - use safe column access
    if "Visitor_Seats" in tickets_df.columns:
        tickets_df["Visitor_Seats"] = pd.to_numeric(tickets_df["Visitor_Seats"], errors="coerce").fillna(0).astype(int)
    else:
        tickets_df["Visitor_Seats"] = 0
    
    if "Sold" in tickets_df.columns:
        tickets_df["Sold"] = tickets_df["Sold"].fillna(False).astype(bool)
    else:
        tickets_df["Sold"] = False
    
    if "Visited" in tickets_df.columns:
        tickets_df["Visited"] = tickets_df["Visited"].fillna(False).astype(bool)
    else:
        tickets_df["Visited"] = False
    
    if "Customer" in tickets_df.columns:
        tickets_df["Customer"] = tickets_df["Customer"].fillna("").astype(str)
    else:
        tickets_df["Customer"] = ""
    
    if "Admit" in tickets_df.columns:
        tickets_df["Admit"] = pd.to_numeric(tickets_df["Admit"], errors="coerce").fillna(1).astype(int)
    else:
        tickets_df["Admit"] = 1
    
    if "Seq" in tickets_df.columns:
        tickets_df["Seq"] = pd.to_numeric(tickets_df["Seq"], errors="coerce")
    else:
        tickets_df["Seq"] = None
    
    # Process TicketID - ensure it's string and zero-padded to 4 digits
    tickets_df["TicketID"] = tickets_df["TicketID"].astype(str).str.zfill(4)
    
    if "Timestamp" in tickets_df.columns:
        tickets_df["Timestamp"] = tickets_df["Timestamp"].astype(str)
    else:
        tickets_df["Timestamp"] = None
    
    # Ensure Type and Category columns exist (required for Dashboard)
    if "Type" not in tickets_df.columns:
        tickets_df["Type"] = ""
    if "Category" not in tickets_df.columns:
        tickets_df["Category"] = ""

    return tickets_df, menu_df

def save_tickets_df(tickets_df: pd.DataFrame):
    """Persist all tickets; optimized write."""
    engine = get_engine()
    with engine.begin() as conn:
        tickets_df.to_sql(
            "tickets", con=conn, if_exists="replace", index=False,
            method="multi", chunksize=1000
        )
    # Clear cache so next reload gets fresh DB; local variable already updated so UI stays fresh.
    st.cache_data.clear()

def save_menu_df(menu_df: pd.DataFrame):
    engine = get_engine()
    with engine.begin() as conn:
        menu_df.to_sql(
            "menu", con=conn, if_exists="replace", index=False,
            method="multi", chunksize=1000
        )
    st.cache_data.clear()

def save_both(tickets_df: pd.DataFrame, menu_df: pd.DataFrame):
    engine = get_engine()
    with engine.begin() as conn:
        tickets_df.to_sql("tickets", con=conn, if_exists="replace", index=False, method="multi", chunksize=1000)
        menu_df.to_sql("menu", con=conn, if_exists="replace", index=False, method="multi", chunksize=1000)
    st.cache_data.clear()

def custom_sort(df: pd.DataFrame) -> pd.DataFrame:
    """Sort by Seq with 0/None last."""
    if "Seq" not in df.columns:
        return df
    sort_key = df["Seq"].apply(lambda x: float("inf") if pd.isna(x) or x in [0, "0"] else float(x))
    return df.assign(_k=sort_key).sort_values("_k").drop(columns="_k")

def get_next_available_ticket_id(tickets_df: pd.DataFrame, ticket_type: str, category: str) -> str | None:
    """Get next available ticket ID for given type and category."""
    avail = tickets_df[
        (tickets_df["Type"] == ticket_type) & 
        (tickets_df["Category"] == category) & 
        (~tickets_df["Sold"])
    ]["TicketID"].tolist()
    return avail[0] if avail else None

# -------------------------------------------------
# LOGIN PAGE
# -------------------------------------------------
if not st.session_state.authenticated:
    st.title("🎟️ Event Management System")
    st.markdown("---")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.subheader("Login")
        with st.form("login_form"):
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            login_button = st.form_submit_button("Login", use_container_width=True)
            
            if login_button:
                if username and password:
                    with st.spinner("Authenticating..."):
                        success, role = authenticate_user(username, password)
                        if success:
                            st.session_state.authenticated = True
                            st.session_state.current_user = username
                            st.session_state.user_role = role
                            st.success("✅ Login successful!")
                            time.sleep(0.5)
                            st.rerun()
                        else:
                            st.error("❌ Invalid username or password")
                else:
                    st.warning("Please enter both username and password")
        
        st.info("💡 Default admin credentials: username: `admin`, password: `admin123`")
    
    st.stop()

# Load data once at start; keep references updated after actions to avoid reruns
try:
    tickets, menu = load_all_data()
except Exception as e:
    st.error(f"Error loading data: {str(e)}")
    # Create empty dataframes as fallback
    tickets = pd.DataFrame(columns=["TicketID", "Category", "Type", "Admit", "Seq", "Sold", "Visited", "Customer", "Visitor_Seats", "Timestamp"])
    menu = pd.DataFrame()
    st.exception(e)

# Get user permissions
user_permissions = get_user_permissions(st.session_state.current_user)

# -------------------------------------------------
# SIDEBAR
# -------------------------------------------------
with st.sidebar:
    st.header("User Info")
    st.write(f"**User:** {st.session_state.current_user}")
    st.write(f"**Role:** {st.session_state.user_role}")
    
    if st.button("🚪 Logout", use_container_width=True):
        st.session_state.authenticated = False
        st.session_state.current_user = None
        st.session_state.user_role = None
        st.rerun()
    
    st.divider()
    st.header("Admin Settings")
    
    # Permission Management (Admin only)
    if st.session_state.user_role == "admin":
        with st.expander("👥 User & Permission Management", expanded=False):
            users_df = load_users()
            perms_df = load_permissions()
            
            st.subheader("Add/Edit User")
            with st.form("user_form"):
                new_username = st.text_input("Username")
                new_password = st.text_input("Password", type="password")
                new_role = st.selectbox("Role", ["admin", "standard", "guest"])
                submit_user = st.form_submit_button("Save User")
                
                if submit_user:
                    if new_username and new_password:
                        save_user(new_username, new_password, new_role)
                        st.success(f"✅ User '{new_username}' saved")
                        st.rerun()
                    else:
                        st.error("Username and password required")
            
            st.divider()
            st.subheader("Manage Permissions")
            if not users_df.empty:
                selected_user = st.selectbox("Select User", users_df["username"].tolist())
                tabs_list = ["Dashboard", "Sales", "Visitors", "Edit Menu", "Bulk Upload"]
                
                perms_dict = {}
                for tab in tabs_list:
                    user_tab_perms = perms_df[
                        (perms_df["username"] == selected_user) & 
                        (perms_df["tab_name"] == tab)
                    ]
                    if not user_tab_perms.empty:
                        perms_dict[tab] = {
                            "can_view": bool(user_tab_perms.iloc[0]["can_view"]),
                            "can_edit": bool(user_tab_perms.iloc[0]["can_edit"])
                        }
                    else:
                        perms_dict[tab] = {"can_view": False, "can_edit": False}
                
                with st.form("permission_form"):
                    for tab in tabs_list:
                        st.write(f"**{tab}**")
                        col1, col2 = st.columns(2)
                        with col1:
                            can_view = st.checkbox("Can View", value=perms_dict[tab]["can_view"], key=f"view_{tab}_{selected_user}")
                        with col2:
                            can_edit = st.checkbox("Can Edit", value=perms_dict[tab]["can_edit"], key=f"edit_{tab}_{selected_user}")
                    
                    submit_perms = st.form_submit_button("Save Permissions")
                    if submit_perms:
                        for tab in tabs_list:
                            save_permission(
                                selected_user, 
                                tab, 
                                st.session_state[f"view_{tab}_{selected_user}"],
                                st.session_state[f"edit_{tab}_{selected_user}"]
                            )
                        st.success(f"✅ Permissions updated for '{selected_user}'")
                        st.rerun()
    
    # Debug info (can be removed later)
    with st.expander("🔍 Debug Info", expanded=False):
        st.write(f"**Tickets loaded:** {len(tickets)} rows")
        if not tickets.empty:
            st.write(f"**Columns:** {', '.join(tickets.columns.tolist())}")

    if st.button("🔄 Refresh Data", use_container_width=True):
        st.session_state.processing = True
        st.cache_data.clear()
        # Reload in-memory for immediate UI update after refresh
        try:
            tickets, menu = load_all_data()
            st.session_state.processing = False
            st.toast("Data refreshed")
        except Exception as e:
            st.session_state.processing = False
            st.error(f"Error refreshing data: {str(e)}")
            st.exception(e)

    admin_pass_input = st.text_input("Reset Database Password", type="password")

    if st.button("🚨 Reset Database", use_container_width=True):
        if not ADMIN_RESET_PASSWORD:
            st.error("Admin password not configured. Set in `st.secrets['app_passwords']['admin_reset']`.")
        elif admin_pass_input == ADMIN_RESET_PASSWORD:
            st.session_state.processing = True
            # Reset relevant columns
            tickets.loc[:, ["Sold", "Visited"]] = False
            tickets.loc[:, ["Customer"]] = ""
            tickets.loc[:, ["Visitor_Seats"]] = 0
            tickets.loc[:, ["Timestamp"]] = None
            save_tickets_df(tickets)
            st.session_state.processing = False
            st.success("✅ Database has been reset.")
            st.rerun()
        else:
            st.error("❌ Incorrect Admin Password")

# Show loading spinner if processing
if st.session_state.processing:
    show_loading_spinner("System is busy processing...")

# -------------------------------------------------
# TABS
# -------------------------------------------------
tab_labels = ["📊 Dashboard", "💰 Sales", "🚶 Visitors", "⚙️ Edit Menu"]
tabs = st.tabs(tab_labels)

# -------------------------------------------------
# 1. DASHBOARD
# -------------------------------------------------
with tabs[0]:
    if not check_permission(st.session_state.current_user, "Dashboard", "view"):
        st.error("❌ You do not have permission to view this tab.")
    else:
        st.subheader("Inventory & Visitor Analytics")

        df = tickets.copy()

        if df.empty:
            st.info("No tickets found.")
        else:
            summary = (
                df.groupby(["Seq", "Type", "Category", "Admit"], dropna=False)
                .agg(
                    Total_Tickets=("TicketID", "count"),
                    Tickets_Sold=("Sold", "sum"),
                    Total_Visitors=("Visitor_Seats", "sum"),
                )
                .reset_index()
            )

            summary["Total_Seats"] = summary["Total_Tickets"] * summary["Admit"]
            summary["Seats_sold"] = summary["Tickets_Sold"] * summary["Admit"]
            summary["Balance_Tickets"] = summary["Total_Tickets"] - summary["Tickets_Sold"]
            summary["Balance_Seats"] = summary["Total_Seats"] - summary["Seats_sold"]
            summary["Balance_Visitors"] = summary["Seats_sold"] - summary["Total_Visitors"]

            column_order = [
                "Seq", "Type", "Category", "Admit", "Total_Tickets", "Tickets_Sold",
                "Total_Seats", "Seats_sold", "Total_Visitors", "Balance_Tickets",
                "Balance_Seats", "Balance_Visitors"
            ]

            summary = custom_sort(summary[column_order])

            totals = pd.DataFrame([summary.select_dtypes(include="number").sum(numeric_only=True)])
            totals["Seq"] = "Total"
            # Fill non-numeric columns where needed
            totals["Type"] = ""
            totals["Category"] = ""
            summary_final = pd.concat([summary, totals], ignore_index=True)

            st.dataframe(summary_final, hide_index=True, use_container_width=True, height=450)

# -------------------------------------------------
# 2. SALES
# -------------------------------------------------
with tabs[1]:
    if not check_permission(st.session_state.current_user, "Sales", "view"):
        st.error("❌ You do not have permission to view this tab.")
    else:
        st.subheader("Sales Management")
        col_in, col_out = st.columns([1, 1.2])

        with col_in:
            sale_tab = st.radio("Action", ["Manual", "Bulk Upload", "Reverse Sale"], horizontal=True, key="sale_action")

            # ---------- Manual Sale ----------
            if sale_tab == "Manual":
                if not check_permission(st.session_state.current_user, "Sales", "edit"):
                    st.error("❌ You do not have permission to edit sales.")
                else:
                    s_type = st.radio("Type", ["Public", "Guest"], horizontal=True, key="sale_type")
                    s_cat_options = menu.loc[menu["Type"] == s_type, "Category"].dropna().unique().tolist()
                    s_cat = st.selectbox("Category", s_cat_options, key="sale_cat")

                    avail = tickets[(tickets["Type"] == s_type) & (tickets["Category"] == s_cat) & (~tickets["Sold"])]["TicketID"].tolist()

                    if avail:
                        with st.form("sale_form", clear_on_submit=True):
                            tid = st.selectbox("Ticket ID", avail, key="sale_tid")
                            cust = st.text_input("Customer Name", key="sale_customer")
                            confirm = st.form_submit_button("Confirm Sale")
                            if confirm:
                                st.session_state.processing = True
                                idx_list = tickets.index[tickets["TicketID"] == tid].tolist()
                                if idx_list:
                                    idx = idx_list[0]
                                    tickets.at[idx, "Sold"] = True
                                    tickets.at[idx, "Customer"] = cust
                                    tickets.at[idx, "Timestamp"] = now_ts()
                                    save_tickets_df(tickets)
                                    st.session_state.processing = False
                                    st.success(f"✅ Ticket {tid} sold to {cust}.")
                                    
                                    # Show next available ticket ID
                                    next_tid = get_next_available_ticket_id(tickets, s_type, s_cat)
                                    if next_tid:
                                        st.info(f"📋 Next available Ticket ID: **{next_tid}**")
                                    else:
                                        st.info("📋 No more available tickets in this category.")
                                    st.rerun()
                                else:
                                    st.session_state.processing = False
                                    st.error("Ticket not found.")
                    else:
                        st.info("No available tickets in this category.")
                        # Show next available ticket ID even if none available
                        next_tid = get_next_available_ticket_id(tickets, s_type, s_cat)
                        if next_tid:
                            st.info(f"📋 Next available Ticket ID: **{next_tid}**")

            # ---------- BULK UPLOAD ----------
            elif sale_tab == "Bulk Upload":
                if not check_permission(st.session_state.current_user, "Bulk Upload", "view"):
                    st.error("❌ You do not have permission to access Bulk Upload.")
                elif not check_permission(st.session_state.current_user, "Bulk Upload", "edit"):
                    st.error("❌ You do not have permission to edit via Bulk Upload.")
                else:
                    st.info("📋 Upload Excel/CSV with columns: `Ticket_ID`, `Customer`")
                    uploaded_file = st.file_uploader("Choose Excel/CSV file", type=["csv", "xlsx", "xls"], key="bulk_uploader")

                    if uploaded_file is not None:
                        try:
                            if uploaded_file.name.lower().endswith(".csv"):
                                bulk_df = pd.read_csv(uploaded_file)
                            else:
                                bulk_df = pd.read_excel(uploaded_file)

                            st.write("**Preview:**")
                            st.dataframe(bulk_df.head(), use_container_width=True)

                            required_cols = {"Ticket_ID", "Customer"}
                            if not required_cols.issubset(set(bulk_df.columns)):
                                st.error(f"❌ File must have columns: {', '.join(sorted(required_cols))}")
                            else:
                                # Normalize
                                bulk_df["Ticket_ID"] = bulk_df["Ticket_ID"].astype(str).str.zfill(4)
                                bulk_df["Customer"] = bulk_df["Customer"].astype(str).str.strip()

                                # Validate duplicates and unknowns before applying
                                dupes = bulk_df["Ticket_ID"][bulk_df["Ticket_ID"].duplicated()].unique().tolist()
                                id_to_index = {tid: i for i, tid in enumerate(tickets["TicketID"].tolist())}
                                unknown = [tid for tid in bulk_df["Ticket_ID"].unique() if tid not in id_to_index]
                                already_sold = [
                                    tid for tid in bulk_df["Ticket_ID"].unique()
                                    if tid in id_to_index and tickets.at[id_to_index[tid], "Sold"]
                                ]

                                if dupes:
                                    st.error(f"❌ Duplicate Ticket_IDs in file: {', '.join(dupes[:5])}{'...' if len(dupes) > 5 else ''}")
                                if unknown:
                                    st.warning(f"⚠️ Unknown Ticket_IDs: {', '.join(unknown[:5])}{'...' if len(unknown) > 5 else ''}")
                                if already_sold:
                                    st.info(f"ℹ️ Already sold Ticket_IDs will be overwritten: {', '.join(already_sold[:5])}{'...' if len(already_sold) > 5 else ''}")

                                if not dupes and not unknown:
                                    if st.button("✅ Process Bulk Sale", key="bulk_process"):
                                        st.session_state.processing = True
                                        success_count = 0
                                        overwrite_count = 0
                                        for _, row in bulk_df.iterrows():
                                            tid = row["Ticket_ID"]
                                            cust = row["Customer"]
                                            idx = id_to_index.get(tid)
                                            if idx is None:
                                                continue
                                            # Overwrite if already sold (as per requirement)
                                            if tickets.at[idx, "Sold"]:
                                                overwrite_count += 1
                                            tickets.at[idx, "Sold"] = True
                                            tickets.at[idx, "Customer"] = cust
                                            tickets.at[idx, "Timestamp"] = now_ts()
                                            success_count += 1

                                        save_tickets_df(tickets)
                                        st.session_state.processing = False

                                        if success_count > 0:
                                            msg = f"✅ {success_count} tickets processed successfully."
                                            if overwrite_count > 0:
                                                msg += f" ({overwrite_count} overwritten)"
                                            st.success(msg)
                                        st.rerun()
                        except Exception as e:
                            st.error(f"❌ File read error: {str(e)}")

            # ---------- Reverse Sale ----------
            elif sale_tab == "Reverse Sale":
                if not check_permission(st.session_state.current_user, "Sales", "edit"):
                    st.error("❌ You do not have permission to reverse sales.")
                else:
                    r_type = st.radio("Type", ["Public", "Guest"], horizontal=True, key="rev_type")
                    r_cat_options = menu.loc[menu["Type"] == r_type, "Category"].dropna().unique().tolist()
                    r_cat = st.selectbox("Category", r_cat_options, key="rev_cat")

                    sold_tickets = tickets[(tickets["Type"] == r_type) & (tickets["Category"] == r_cat) & (tickets["Sold"])]["TicketID"].tolist()

                    if sold_tickets:
                        with st.form("reverse_sale_form"):
                            tid = st.selectbox("Ticket ID to reverse", sold_tickets, key="rev_tid")
                            confirm = st.form_submit_button("Reverse Sale")
                            if confirm:
                                st.session_state.processing = True
                                idx_list = tickets.index[tickets["TicketID"] == tid].tolist()
                                if idx_list:
                                    idx = idx_list[0]
                                    tickets.at[idx, "Sold"] = False
                                    tickets.at[idx, "Customer"] = ""
                                    tickets.at[idx, "Visited"] = False
                                    tickets.at[idx, "Visitor_Seats"] = 0
                                    tickets.at[idx, "Timestamp"] = None
                                    save_tickets_df(tickets)
                                    st.session_state.processing = False
                                    st.success(f"✅ Sale reversed for Ticket {tid}.")
                                    st.rerun()
                                else:
                                    st.session_state.processing = False
                                    st.error("Ticket not found.")
                    else:
                        st.info("No sold tickets to reverse in this category.")

        with col_out:
            st.write("**Recent Sales History**")
            recent_sales = tickets[tickets["Sold"]].copy()
            if not recent_sales.empty:
                # Sort by Timestamp (string), robustly handling None
                recent_sales["Timestamp_sort"] = pd.to_datetime(recent_sales["Timestamp"], errors="coerce")
                recent_sales = recent_sales.sort_values("Timestamp_sort", ascending=False).drop(columns="Timestamp_sort")
                recent_sales.insert(0, "Sno", range(1, len(recent_sales) + 1))
                st.dataframe(
                    recent_sales[["Sno", "TicketID", "Category", "Customer", "Timestamp"]],
                    hide_index=True, use_container_width=True
                )
            else:
                st.info("No sales recorded yet.")

# -------------------------------------------------
# 3. VISITORS
# -------------------------------------------------
with tabs[2]:
    if not check_permission(st.session_state.current_user, "Visitors", "view"):
        st.error("❌ You do not have permission to view this tab.")
    else:
        st.subheader("Visitor Entry Management")
        v_in, v_out = st.columns([1, 1.2])

        with v_in:
            v_action = st.radio("Action", ["Entry", "Reverse Entry"], horizontal=True, key="vis_action")

            if v_action == "Entry":
                if not check_permission(st.session_state.current_user, "Visitors", "edit"):
                    st.error("❌ You do not have permission to edit visitor entries.")
                else:
                    v_type = st.radio("Entry Type", ["Public", "Guest"], horizontal=True, key="vis_type")
                    v_cat_options = menu.loc[menu["Type"] == v_type, "Category"].dropna().unique().tolist()
                    v_cat = st.selectbox("Entry Category", v_cat_options, key="vis_cat")

                    elig = tickets[(tickets["Type"] == v_type) & (tickets["Category"] == v_cat) &
                                   (tickets["Sold"]) & (~tickets["Visited"])]["TicketID"].tolist()

                    if elig:
                        with st.form("checkin_form"):
                            tid = st.selectbox("Select Ticket ID", elig, key="vis_tid")
                            # Pull current admit for the selected ticket
                            max_v = int(tickets.loc[tickets["TicketID"] == tid, "Admit"].values[0])
                            v_count = st.number_input("Confirmed Visitors", min_value=1, max_value=max_v, value=max_v, step=1, key="vis_count")
                            confirm = st.form_submit_button("Confirm Entry")
                            if confirm:
                                st.session_state.processing = True
                                idx_list = tickets.index[tickets["TicketID"] == tid].tolist()
                                if idx_list:
                                    idx = idx_list[0]
                                    tickets.at[idx, "Visited"] = True
                                    tickets.at[idx, "Visitor_Seats"] = int(v_count)
                                    tickets.at[idx, "Timestamp"] = now_ts()
                                    save_tickets_df(tickets)
                                    st.session_state.processing = False
                                    st.success(f"✅ Entry confirmed for Ticket {tid}.")
                                    
                                    # Show next available ticket ID
                                    next_elig = tickets[
                                        (tickets["Type"] == v_type) & 
                                        (tickets["Category"] == v_cat) &
                                        (tickets["Sold"]) & 
                                        (~tickets["Visited"])
                                    ]["TicketID"].tolist()
                                    if next_elig:
                                        st.info(f"📋 Next available Ticket ID: **{next_elig[0]}**")
                                    else:
                                        st.info("📋 No more eligible tickets for entry.")
                                    st.rerun()
                                else:
                                    st.session_state.processing = False
                                    st.error("Ticket not found.")
                    else:
                        st.info("No eligible tickets for entry.")
                        # Show next available ticket ID even if none available
                        next_elig = tickets[
                            (tickets["Type"] == v_type) & 
                            (tickets["Category"] == v_cat) &
                            (tickets["Sold"]) & 
                            (~tickets["Visited"])
                        ]["TicketID"].tolist()
                        if next_elig:
                            st.info(f"📋 Next available Ticket ID: **{next_elig[0]}**")

            else:  # Reverse Entry
                if not check_permission(st.session_state.current_user, "Visitors", "edit"):
                    st.error("❌ You do not have permission to reverse visitor entries.")
                else:
                    rv_type = st.radio("Entry Type", ["Public", "Guest"], horizontal=True, key="rev_vis_type")
                    rv_cat_options = menu.loc[menu["Type"] == rv_type, "Category"].dropna().unique().tolist()
                    rv_cat = st.selectbox("Entry Category", rv_cat_options, key="rev_vis_cat")

                    visited_tickets = tickets[(tickets["Type"] == rv_type) & (tickets["Category"] == rv_cat) &
                                              (tickets["Visited"])]["TicketID"].tolist()

                    if visited_tickets:
                        with st.form("reverse_entry_form"):
                            tid = st.selectbox("Ticket ID to modify", visited_tickets, key="rev_vis_tid")

                            editable_cats = {"FAMILY SILVER", "FAMILY BRONZE"}
                            allow_edit = str(rv_cat).strip().upper() in editable_cats

                            if allow_edit:
                                max_admit = int(tickets.loc[tickets["TicketID"] == tid, "Admit"].values[0])
                                current_seats = int(tickets.loc[tickets["TicketID"] == tid, "Visitor_Seats"].fillna(0).values[0])
                                if current_seats < 1:
                                    current_seats = max_admit
                                new_seats = st.number_input("Confirmed Visitors (can be < Admit)",
                                                            min_value=0, max_value=max_admit, value=current_seats, step=1,
                                                            key="rev_vis_count")
                                confirm_update = st.form_submit_button("Update Entry")
                                if confirm_update:
                                    st.session_state.processing = True
                                    idx_list = tickets.index[tickets["TicketID"] == tid].tolist()
                                    if idx_list:
                                        idx = idx_list[0]
                                        if new_seats == 0:
                                            tickets.at[idx, "Visited"] = False
                                            tickets.at[idx, "Visitor_Seats"] = 0
                                            tickets.at[idx, "Timestamp"] = None
                                            st.success(f"✅ Entry removed for Ticket {tid}.")
                                        else:
                                            tickets.at[idx, "Visited"] = True
                                            tickets.at[idx, "Visitor_Seats"] = int(new_seats)
                                            tickets.at[idx, "Timestamp"] = now_ts()
                                            st.success(f"✅ Entry updated for Ticket {tid} with {new_seats} visitors.")
                                        save_tickets_df(tickets)
                                        st.session_state.processing = False
                                        st.rerun()
                                    else:
                                        st.session_state.processing = False
                                        st.error("Ticket not found.")
                            else:
                                st.info("This category will fully reverse the entry.")
                                confirm_reverse = st.form_submit_button("Reverse Entry")
                                if confirm_reverse:
                                    st.session_state.processing = True
                                    idx_list = tickets.index[tickets["TicketID"] == tid].tolist()
                                    if idx_list:
                                        idx = idx_list[0]
                                        tickets.at[idx, "Visited"] = False
                                        tickets.at[idx, "Visitor_Seats"] = 0
                                        tickets.at[idx, "Timestamp"] = None
                                        save_tickets_df(tickets)
                                        st.session_state.processing = False
                                        st.success(f"✅ Entry reversed for Ticket {tid}.")
                                        st.rerun()
                                    else:
                                        st.session_state.processing = False
                                        st.error("Ticket not found.")
                    else:
                        st.info("No visitor entries to reverse.")

        with v_out:
            st.write("**Recent Visitors**")
            recent_visitors = tickets[tickets["Visited"]].copy()
            if not recent_visitors.empty:
                recent_visitors["Timestamp_sort"] = pd.to_datetime(recent_visitors["Timestamp"], errors="coerce")
                recent_visitors = recent_visitors.sort_values("Timestamp_sort", ascending=False).drop(columns="Timestamp_sort")
                recent_visitors.insert(0, "Sno", range(1, len(recent_visitors) + 1))
                st.dataframe(
                    recent_visitors[["Sno", "TicketID", "Category", "Customer", "Visitor_Seats", "Timestamp"]],
                    hide_index=True, use_container_width=True
                )
            else:
                st.info("No visitors recorded yet.")

# -------------------------------------------------
# 4. EDIT MENU
# -------------------------------------------------
with tabs[3]:
    if not check_permission(st.session_state.current_user, "Edit Menu", "view"):
        st.error("❌ You do not have permission to view this tab.")
    else:
        st.subheader("Menu & Series Configuration")

        menu_display = custom_sort(menu.copy())

        # Auto-calc Alloc and Total_Capacity based on Series (e.g., "1-50")
        def recompute_menu_fields(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
            df = df.copy()
            errors: list[str] = []
            for index, row in df.iterrows():
                try:
                    series = str(row.get("Series", "")).strip()
                    admit = int(row.get("Admit", 1))
                    if "-" in series:
                        start, end = map(int, series.split("-"))
                        count = max((end - start) + 1, 0)
                        df.at[index, "Alloc"] = count
                        df.at[index, "Total_Capacity"] = count * admit
                    else:
                        errors.append(f"Row {index + 1}: Series must be in 'start-end' format.")
                except Exception:
                    errors.append(f"Row {index + 1}: Invalid Series '{row.get('Series')}'.")
            return df, errors

        menu_display, _ = recompute_menu_fields(menu_display)

        if check_permission(st.session_state.current_user, "Edit Menu", "edit"):
            edited_menu = st.data_editor(
                menu_display,
                hide_index=True,
                use_container_width=True,
                key="menu_editor",
                num_rows="dynamic"
            )
        else:
            st.info("❌ You have view-only access. You cannot edit the menu.")
            edited_menu = menu_display

        st.divider()
        menu_pass_input = st.text_input("Enter Menu Update Password", type="password")

        if st.button("Update Database Menu", key="menu_update_btn"):
            if not check_permission(st.session_state.current_user, "Edit Menu", "edit"):
                st.error("❌ You do not have permission to edit the menu.")
            elif not MENU_UPDATE_PASSWORD:
                st.error("Menu password not configured. Set in `st.secrets['app_passwords']['menu_update']`.")
            elif menu_pass_input == MENU_UPDATE_PASSWORD:
                st.session_state.processing = True
                # Build tickets from edited menu + preserve existing tickets if present
                new_tickets_list: list[dict] = []
                # Pre-map existing tickets for quick reuse (as plain dicts for DataFrame compatibility)
                existing_map = {row["TicketID"]: row.to_dict() for _, row in tickets.iterrows()}

                for _, m_row in edited_menu.iterrows():
                    try:
                        series = str(m_row.get("Series", "")).strip()
                        if "-" in series:
                            start, end = map(int, series.split("-"))
                            for tid in range(start, end + 1):
                                tid_str = str(tid).zfill(4)
                                if tid_str in existing_map:
                                    new_tickets_list.append(existing_map[tid_str])
                                else:
                                    new_tickets_list.append({
                                        "TicketID": tid_str,
                                        "Category": m_row.get("Category", ""),
                                        "Type": m_row.get("Type", ""),
                                        "Admit": int(m_row.get("Admit", 1)),
                                        "Seq": m_row.get("Seq"),
                                        "Sold": False,
                                        "Visited": False,
                                        "Customer": "",
                                        "Visitor_Seats": 0,
                                        "Timestamp": None
                                    })
                    except Exception:
                        # Skip malformed rows
                        continue

                final_tickets_df = pd.DataFrame(new_tickets_list)
                # Persist both
                edited_menu_clean, menu_errors = recompute_menu_fields(edited_menu)

                if menu_errors:
                    st.session_state.processing = False
                    st.error("❌ Cannot save menu due to errors:")
                    for err in menu_errors:
                        st.write(f"- {err}")
                else:
                    save_both(final_tickets_df, edited_menu_clean)

                    # Update in-memory references for immediate UI consistency
                    tickets = final_tickets_df
                    menu = edited_menu_clean

                    st.session_state.processing = False
                    st.success("✅ Menu and Inventory synchronized.")
                    st.rerun()
            else:
                st.error("❌ Incorrect Menu Password")

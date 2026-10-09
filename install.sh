#!/usr/bin/env bash
set -e

# WARD Management & Installation CLI Tool
REPO_URL="https://github.com/h4m1dr/ward.git"
DEFAULT_INSTALL_DIR="/opt/ward"
SERVICE_NAME="ward"

# Color constants
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check if the script is run as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[-] Error: Please run this script as root.${NC}"
        exit 1
    fi
}

# Get the current installation directory from systemd or use default
get_install_dir() {
    if [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]; then
        DIR=$(grep "WorkingDirectory=" "/etc/systemd/system/${SERVICE_NAME}.service" | cut -d'=' -f2 | tr -d ' ')
        if [ -n "$DIR" ] && [ -d "$DIR" ]; then
            echo "$DIR"
            return
        fi
    fi
    echo "$DEFAULT_INSTALL_DIR"
}

# Generate or update the systemd service file
generate_service_file() {
    local target_dir="$1"
    cat << EOF > "/etc/systemd/system/${SERVICE_NAME}.service"
[Unit]
Description=WARD Watchdog for Applications, Resources & Directories
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${target_dir}
ExecStart=/usr/bin/python3 ${target_dir}/server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

# Safe helper function to update JSON config without shell injection risks
update_config() {
    local config_file="$1"
    local key="$2"
    local value="$3"
    local is_int="$4" # "true" if the value should be an integer

    python3 -c '
import json, sys
try:
    with open(sys.argv[1], "r") as f:
        data = json.load(f)
    
    if sys.argv[4] == "true":
        data[sys.argv[2]] = int(sys.argv[3])
    else:
        data[sys.argv[2]] = sys.argv[3]
        
    with open(sys.argv[1], "w") as f:
        json.dump(data, f, indent=2)
except Exception as e:
    print("Error updating config:", e)
    sys.exit(1)
' "$config_file" "$key" "$value" "$is_int"
}

# 1. Full Automated Installation
install_ward() {
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}       WARD Clean Installation        ${NC}"
    echo -e "${BLUE}======================================${NC}"

    echo -e "${CYAN}[+] Installing system dependencies...${NC}"
    apt-get update -qq && apt-get install -y -qq git python3 curl

    echo ""
    read -p "Enter Target Directory [Default: ${DEFAULT_INSTALL_DIR}]: " USER_DIR
    INSTALL_DIR=${USER_DIR:-"$DEFAULT_INSTALL_DIR"}

    read -p "Enter Panel Display Name [Default: WARD Monitor]: " CUSTOM_NAME
    CUSTOM_NAME=${CUSTOM_NAME:-"WARD Monitor"}

    read -p "Enter Internal Service Port [Default: 54321]: " CUSTOM_PORT
    CUSTOM_PORT=${CUSTOM_PORT:-54321}

    read -p "Enter Domain / Subdomain (Optional for reference): " CUSTOM_DOMAIN
    CUSTOM_DOMAIN=${CUSTOM_DOMAIN:-"localhost"}

    read -s -p "Set Web Admin Password [Default: admin1234]: " ADMIN_PASS
    echo ""
    ADMIN_PASS=${ADMIN_PASS:-"admin1234"}

    # Clone or reset repository
    if [ -d "$INSTALL_DIR/.git" ]; then
        echo -e "${CYAN}[+] Resetting local directory in ${INSTALL_DIR}...${NC}"
        cd "$INSTALL_DIR"
        git fetch origin main
        git reset --hard origin/main
        git pull origin main
    else
        echo -e "${CYAN}[+] Cloning repository into ${INSTALL_DIR}...${NC}"
        mkdir -p "$INSTALL_DIR"
        git clone "$REPO_URL" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
    fi

    # Generate password hash
    PASS_HASH=$(echo -n "$ADMIN_PASS" | sha256sum | awk '{print $1}')

    # Safely generate config.json using Python to avoid heredoc escaping issues
    echo -e "${CYAN}[+] Generating config.json safely...${NC}"
    python3 -c '
import json, sys, hashlib
config = {
    "panel_name": sys.argv[1],
    "panel_port": int(sys.argv[2]),
    "domain": sys.argv[3],
    "auth_enabled": True,
    "admin_password_hash": sys.argv[4],
    "telegram": {"bot_token": "", "chat_id": ""},
    "monitored_services": ["nginx", "ssh"],
    "monitored_ports": [80, 443, 22],
    "blocked_ports_trigger": [21, 23, 3306, 5432, 6379],
    "monitored_directories": {"system_cache": "/var/cache", "tmp": "/tmp"},
    "monitored_apps": ["dockerd", "xray"],
    "scheduled_tasks": []
}
with open("config.json", "w") as f:
    json.dump(config, f, indent=2)
' "$CUSTOM_NAME" "$CUSTOM_PORT" "$CUSTOM_DOMAIN" "$PASS_HASH"

    # Configure update script & command alias
    if [ -f "$INSTALL_DIR/update.sh" ]; then
        chmod +x "$INSTALL_DIR/update.sh"
        ln -sf "$INSTALL_DIR/update.sh" /usr/local/bin/ward-update
    fi

    echo -e "${CYAN}[+] Configuring systemd daemon...${NC}"
    generate_service_file "$INSTALL_DIR"
    systemctl enable --now "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"

    echo ""
    echo -e "${GREEN}======================================${NC}"
    echo -e "${GREEN}[√] WARD installed successfully!${NC}"
    echo -e "Panel Name : ${CYAN}${CUSTOM_NAME}${NC}"
    echo -e "Local Port : ${CYAN}${CUSTOM_PORT}${NC}"
    echo -e "Directory  : ${CYAN}${INSTALL_DIR}${NC}"
    echo -e "Status     : ${GREEN}Active (running)${NC}"
    echo ""
    echo -e "${YELLOW}[!] If using Nginx Reverse Proxy, set:${NC}"
    echo -e "${YELLOW}    proxy_pass http://127.0.0.1:${CUSTOM_PORT};${NC}"
    echo -e "${YELLOW}[!] Quick updater registered: run 'ward-update' anytime.${NC}"
    echo -e "${GREEN}======================================${NC}"
}

# 2. Modify & Edit Configuration
edit_ward_config() {
    INSTALL_DIR=$(get_install_dir)
    CONFIG_FILE="${INSTALL_DIR}/config.json"

    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${RED}[-] Error: Configuration file not found at ${CONFIG_FILE}.${NC}"
        return
    fi

    echo -e "${YELLOW}======================================${NC}"
    echo -e "${YELLOW}       Edit WARD Configuration        ${NC}"
    echo -e "${YELLOW}======================================${NC}"
    echo "1) Change Panel Title"
    echo "2) Change Listening Port"
    echo "3) Change Admin Password"
    echo "4) Move Installation Directory"
    echo "5) Return to Main Menu"
    read -p "Select option [1-5]: " edit_opt

    case $edit_opt in
        1)
            read -p "Enter New Panel Title: " NEW_TITLE
            if [ -n "$NEW_TITLE" ]; then
                update_config "$CONFIG_FILE" "panel_name" "$NEW_TITLE" "false"
                systemctl restart "$SERVICE_NAME"
                echo -e "${GREEN}[√] Panel title updated and service restarted.${NC}"
            fi
            ;;
        2)
            read -p "Enter New Service Port: " NEW_PORT
            if [[ "$NEW_PORT" =~ ^[0-9]+$ ]]; then
                update_config "$CONFIG_FILE" "panel_port" "$NEW_PORT" "true"
                systemctl restart "$SERVICE_NAME"
                echo -e "${GREEN}[√] Port changed to ${NEW_PORT}. Remember to update Nginx proxy_pass!${NC}"
            else
                echo -e "${RED}[-] Invalid port number.${NC}"
            fi
            ;;
        3)
            read -s -p "Enter New Admin Password: " NEW_PASS
            echo ""
            if [ -n "$NEW_PASS" ]; then
                NEW_HASH=$(echo -n "$NEW_PASS" | sha256sum | awk '{print $1}')
                update_config "$CONFIG_FILE" "admin_password_hash" "$NEW_HASH" "false"
                systemctl restart "$SERVICE_NAME"
                echo -e "${GREEN}[√] Admin password updated successfully.${NC}"
            fi
            ;;
        4)
            read -p "Enter New Target Directory path: " NEW_DIR
            if [ -n "$NEW_DIR" ] && [ "$NEW_DIR" != "$INSTALL_DIR" ]; then
                systemctl stop "$SERVICE_NAME"
                mkdir -p "$(dirname "$NEW_DIR")"
                mv "$INSTALL_DIR" "$NEW_DIR"
                generate_service_file "$NEW_DIR"
                if [ -f "$NEW_DIR/update.sh" ]; then
                    chmod +x "$NEW_DIR/update.sh"
                    ln -sf "$NEW_DIR/update.sh" /usr/local/bin/ward-update
                fi
                systemctl daemon-reload # Crucial step added
                systemctl restart "$SERVICE_NAME"
                echo -e "${GREEN}[√] Project moved to ${NEW_DIR} and service reconfigured.${NC}"
            fi
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}[-] Invalid option.${NC}"
            ;;
    esac
}

# 3. Status Check, Restart & Log Viewer
check_and_debug() {
    INSTALL_DIR=$(get_install_dir)
    CONFIG_FILE="${INSTALL_DIR}/config.json"

    echo -e "${CYAN}======================================${NC}"
    echo -e "${CYAN}     Status, Health & Log Center      ${NC}"
    echo -e "${CYAN}======================================${NC}"
    echo "1) Check Service Status"
    echo "2) Restart Service"
    echo "3) View Real-Time Service Logs (journalctl)"
    echo "4) Print Current Configuration Summary"
    echo "5) Return to Main Menu"
    read -p "Select option [1-5]: " db_opt

    case $db_opt in
        1)
            systemctl status "$SERVICE_NAME" --no-pager
            ;;
        2)
            systemctl restart "$SERVICE_NAME"
            echo -e "${GREEN}[√] Service ${SERVICE_NAME} restarted.${NC}"
            ;;
        3)
            echo -e "${YELLOW}[!] Displaying last 40 log lines (Press Ctrl+C to exit)...${NC}"
            journalctl -u "$SERVICE_NAME" -n 40 -f
            ;;
        4)
            if [ -f "$CONFIG_FILE" ]; then
                echo -e "${CYAN}--- Configuration: ${CONFIG_FILE} ---${NC}"
                cat "$CONFIG_FILE"
                echo ""
            else
                echo -e "${RED}[-] Configuration file not found.${NC}"
            fi
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}[-] Invalid selection.${NC}"
            ;;
    esac
}

# 4. Uninstall WARD completely
uninstall_ward() {
    INSTALL_DIR=$(get_install_dir)

    echo -e "${RED}======================================${NC}"
    echo -e "${RED}       Uninstall & Purge WARD         ${NC}"
    echo -e "${RED}======================================${NC}"
    read -p "Are you sure you want to completely remove WARD? [y/N]: " confirm

    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}[+] Stopping and disabling service...${NC}"
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true

        echo -e "${YELLOW}[+] Removing systemd service unit & updater alias...${NC}"
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        rm -f /usr/local/bin/ward-update
        systemctl daemon-reload

        echo -e "${YELLOW}[+] Deleting installation files from ${INSTALL_DIR}...${NC}"
        rm -rf "$INSTALL_DIR"

        echo -e "${GREEN}[√] WARD has been completely removed from your system.${NC}"
    else
        echo -e "${BLUE}[*] Uninstall cancelled.${NC}"
    fi
}

# Interactive CLI Main Menu
main_menu() {
    check_root
    while true; do
        echo ""
        echo -e "${CYAN}======================================${NC}"
        echo -e "${CYAN}     WARD System Management Menu      ${NC}"
        echo -e "${CYAN}======================================${NC}"
        echo "1) Install WARD (Clean Setup)"
        echo "2) Edit Configuration (Port, Title, Path, Password)"
        echo "3) Service Health, Restart & Journalctl Logs"
        echo "4) Uninstall WARD Completely"
        echo "5) Exit"
        read -p "Select an option [1-5]: " main_choice

        case $main_choice in
            1) install_ward ;;
            2) edit_ward_config ;;
            3) check_and_debug ;;
            4) uninstall_ward ;;
            5) echo -e "${GREEN}Goodbye!${NC}"; exit 0 ;;
            *) echo -e "${RED}[-] Invalid option, please choose between 1 and 5.${NC}" ;;
        esac
    done
}

main_menu

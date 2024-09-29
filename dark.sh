#!/bin/bash

# Проверка, выполняется ли скрипт от имени root
if [ "$EUID" -ne 0 ]; then
    echo "Пожалуйста, запустите скрипт с правами суперпользователя (root)."
    exit 1
fi

# Функция для создания SSH-аккаунта
create_ssh_account() {
    read -p "Введите имя пользователя: " username
    read -s -p "Введите пароль: " password
    echo

    # Создание нового пользователя с запрещённой оболочкой
    useradd -m -s /bin/false "$username"
    echo "$username:$password" | chpasswd

    # Создание .ssh директории и установка прав
    mkdir -p /home/$username/.ssh
    chmod 700 /home/$username/.ssh
    chown -R $username:$username /home/$username/.ssh

    echo "Пользователь $username успешно создан."

    # Настройка SSH-сервера для прослушивания на портах 80 и 443
    SSHD_CONFIG="/etc/ssh/sshd_config"

    # Резервное копирование оригинального файла конфигурации
    cp $SSHD_CONFIG "${SSHD_CONFIG}.bak"

    # Добавление портов 80 и 443 для прослушивания, если они еще не добавлены
    if ! grep -q "Port 80" $SSHD_CONFIG; then
        echo "Port 80" >> $SSHD_CONFIG
    fi

    if ! grep -q "Port 443" $SSHD_CONFIG; then
        echo "Port 443" >> $SSHD_CONFIG
    fi

    # Перезапуск SSH-сервиса для применения изменений
    systemctl restart sshd

    # Открытие портов 80 и 443 в брандмауэре (если используется ufw)
    if command -v ufw &> /dev/null; then
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw reload
        echo "Порты 80 и 443 открыты в ufw."
    else
        echo "ufw не установлен, пропускаем настройку брандмауэра."
    fi

    # Вывод информации о подключении
    IP_ADDRESS=$(hostname -I | awk '{print $1}')
    echo "SSH аккаунт создан!"
    echo "Полная информация для подключения:"
    echo "$IP_ADDRESS:80@$username:$password"
    echo "$IP_ADDRESS:443@$username:$password"
}

# Функция для изменения баннера SSH
change_ssh_banner() {
    echo "Введите текст для баннера (используйте \\n для новой строки):"
    read -r banner_text

    echo "Выберите цвет баннера (введите число):
    1. Красный
    2. Зеленый
    3. Желтый
    4. Синий
    5. Магента
    6. Циан
    7. Белый"
    read -p "Введите номер цвета: " color_choice

    # Установка цвета баннера
    case $color_choice in
        1) color_code="31" ;;  # Красный
        2) color_code="32" ;;  # Зеленый
        3) color_code="33" ;;  # Желтый
        4) color_code="34" ;;  # Синий
        5) color_code="35" ;;  # Магента
        6) color_code="36" ;;  # Циан
        7) color_code="37" ;;  # Белый
        *) color_code="37" ;;  # По умолчанию белый
    esac

    # Создание баннера
    BANNER_FILE="/etc/ssh/banner.txt"
    {
        echo -e "\e[${color_code}m**************************************************"
        echo -e "$banner_text"
        echo -e "**************************************************\e[0m"
    } > $BANNER_FILE

    # Настройка баннера в sshd_config
    SSHD_CONFIG="/etc/ssh/sshd_config"
    if ! grep -q "Banner" $SSHD_CONFIG; then
        echo "Banner $BANNER_FILE" >> $SSHD_CONFIG
    fi

    # Перезапуск SSH-сервиса для применения изменений
    systemctl restart sshd

    echo "Баннер успешно изменен."
}

# Функция для управления SSH-аккаунтами
manage_ssh_accounts() {
    echo "Управление SSH аккаунтами:"
    echo "1. Просмотреть всех пользователей"
    echo "2. Удалить пользователя"
    read -p "Выберите опцию: " option

    case $option in
        1)
            echo "Список всех SSH пользователей:"
            awk -F':' '$7 == "/bin/false" {print $1}' /etc/passwd
            ;;
        2)
            read -p "Введите имя пользователя для удаления: " del_user
            userdel -r $del_user
            echo "Пользователь $del_user удален."
            ;;
        *)
            echo "Неверный выбор."
            ;;
    esac
}

# Главное меню
while true; do
    echo "Меню:"
    echo "1: Создать SSH аккаунт"
    echo "2: Изменить баннер"
    echo "3: Управление SSH аккаунтами"
    echo "4: Выйти"
    read -p "Выберите опцию: " choice

    case $choice in
        1) create_ssh_account ;;
        2) change_ssh_banner ;;
        3) manage_ssh_accounts ;;
        4) exit 0 ;;
        *) echo "Неверный выбор. Попробуйте снова." ;;
    esac
done
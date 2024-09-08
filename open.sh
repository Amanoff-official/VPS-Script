#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

sh_ver="2.3"

file=$(echo -e "${filepath}"|awk -F "$0" '{print $1}')

tgid="-4587383173" # Auto-backup çatyň ID-sy (Habarlaşma hukuklary gerek)
bot_api="7384056832:AAF9xQBfyBsjNpMH67Ljvs-13DXmNdjxgpw" # Botyň tokeni (BotFather tarapyndan berilýär)
backup_serv_id="$(cat /etc/openvpn/server/client-common.txt | sed -n 4p | cut -d ' ' -f 2)" # Konfigurasiýadan serweriň domenini alyň
tg2id="-1002473623834" # Açarlar üçin ugradyş ediji toparyň ID-sy
admls="6015656957" # Adminiň ID-si

Deal1="Official_amanoff"
Deal2="EmirHalalHyzmat"
Deal3="Vpn_Unlock"
Deal4="Yetmis_7servers"
Deal5="anonym_decryptor"

Green="\033[32m" && Red="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Purple="\033[35m" && Yellow="\033[33m" && Font_default="\033[0m" && Blue='\033[34m' && Ocean='\033[36m'
Info="${Green}[Maglumat]${Font_default}"
Error="${Red}[Ýalňyş]${Font_default}"
Tip="${Green}[Bellik]${Font_default}"
Separator_1="——————————————————————————————"

# Debian ulanýanlaryň bash däl-de, sh bilen işleýändigini ýüze çykaryň
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'Bu gurujy "sh" däl-de, "bash" bilen işlemeli.'
	exit
fi

# Giriş jümlesini ýatyryň. Bir setirdäki täze setir girizmesi bolan ýagdaýynda gerek
read -N 999999 -t 0.001

# OpenVZ 6-ny ýüze çykaryň
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
	echo "Sistemanyň köne kernel wersiýasy bu gurujy bilen gabat gelmeýär."
	exit
fi

# Operasion sistemasyny ýüze çykaryň
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	group_name="nogroup"
elif [[ -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -oE '[0-9]+' /etc/centos-release | head -1)
	group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	group_name="nobody"
else
	echo "Bu gurujy goldanmaýan VPS-da işleýär ýaly.
	Goldanýan VPS-lar: Ubuntu, Debian, CentOS we Fedora."
	exit
fi

# Ubuntu 18.04 we ýokary wersiýalary talap edýär
if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	echo "Bu installer üçin Ubuntu 18.04 ýa-da ýokary wersiýasy gerek."
	exit
fi

# Debian 9 we ýokary wersiýalary talap edýär
if [[ "$os" == "debian" && "$os_version" -lt 9 ]]; then
	echo "Bu installer üçin Debian 9 ýa-da ýokary wersiýasy gerek."
	exit
fi

# CentOS 7 we ýokary wersiýalary talap edýär
if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
	echo "Bu installer üçin CentOS 7 ýa-da ýokary wersiýasy gerek."
	exit
fi

# $PATH-da sbin direktorýasynyň ýoklugyny barlaň
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH sbin girizilenok. "su -" ulanyp synap görüň.'
	exit
fi

# Administrator hukuklary bilen işledilmese, ýalňyş
if [[ "$EUID" -ne 0 ]]; then
	echo "Bu installer-y root hukugy bilen işletmeli."
	exit
fi

# TUN enjamynyň elýeterli däldigini barlaň
if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
	echo "Ulgamda TUN enjamy ýok. Bu gurnaýjyny işletmezden ozal TUN açyk bolmaly."
	exit
fi

# Täze müşderi döretmek
new_client () {
	# Custome edilen client.ovpn faýly döredilýär
	{
	cat /etc/openvpn/server/client-common.txt
	echo "<ca>"
	cat /etc/openvpn/server/easy-rsa/pki/ca.crt
	echo "</ca>"
	echo "<cert>"
	sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
	echo "</cert>"
	echo "<key>"
	cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
	echo "</key>"
	echo "<tls-crypt>"
	sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
	echo "</tls-crypt>"
	} > ~/"$client".ovpn
}

# Admin parolyny girizmek
Parol () {
echo "ROOT parolyny giriziň:"
	read -e -p "Parol: " paroladm
	[[ -z "${paroladm}" ]] && paroladm="1"
	if [[ ${paroladm} == "qwerty123" ]]; then
		echo "~~~Elýeterlilik berildi!~~~"
	else
	echo "Sen kim?! Bu ýere näme üçin girdiň?" && exit 
	fi
}

# Sistemi barlaň
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
	bit=`uname -m`
}

# Crontab wagtyny bellemegiň usuly
Set_crontab(){
		echo -e "Trafiki arassalamak üçin wagt intervalyny giriziň
 === Format düşündirilişi ===
 * * * * * Minut, sagat, gün, aý, hepdel
 ${Green} 0 2 1 * * ${Font_default} Aýyň 1-y 2 sagat bolanyny aňladýar
 ${Green} 0 2 15 * * ${Font_default} Aýyň 15-i 2 sagat bolanyny aňladýar
 ${Green} 0 2 */7 * * ${Font_default} Her 7 günüň içinde 2 sagat
 ${Green} 0 2 * * 0 ${Font_default} Her ýekşenbe güni
 ${Green} 0 2 * * 3 ${Font_default} Her çarşenbe güni" && echo
	read -e -p "(Adatça: 0 2 1 * * - her aýyň 1-y sagat 2-de):" Crontab_time
	[[ -z "${Crontab_time}" ]] && Crontab_time="0 2 1 * *"
}

# Autobekap başlatmak
Autobak_cron_start(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ov.sh/d" "$file/crontab.bak"
	echo -e "\n${Crontab_time} bash ov.sh autobak" >> "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ov.sh")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} Autobekap ${Red}başlamady${Font_default}" && exit 1
	else
		echo -e "${Info} Autobekap üstünlikli ${Green}başlady${Font_default}"
		curl -s -X POST https://api.telegram.org/bot"$bot_api"/sendMessage -d chat_id="$tgid" -d text="OpenVPN serweriniň autobekapy $backup_serv_id üstünlikli başlady"
	fi
}

# Autobekapy duruzmak
Autobak_cron_stop(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ov.sh/d" "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ov.sh")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} Autobekapy duruzmak başartmady" && exit 1
	else
		echo -e "${Info} Autobekap üstünlikli ${Green}duruzuldy${Font_default}"
		curl -s -X POST https://api.telegram.org/bot"$bot_api"/sendMessage -d chat_id="$tgid" -d text="OpenVPN serweriniň autobekapy $backup_serv_id üstünlikli duruzuldy"
	fi
}

# Autobekap wagtyny üýtgetmek
Autobak_cron_modify(){
	Set_crontab
	Autobak_cron_stop
	Autobak_cron_start
}
# Autobekapy el bilen başlatmak
Autobak(){
	zip -r openvpn.zip /etc/openvpn
	backupURL="$(curl -F "file=@/root/openvpn.zip" https://file.io | jq '.link')"
	curl -s -X POST https://api.telegram.org/bot"$bot_api"/sendMessage -d chat_id="$tgid" -d text="OpenVPN serweriniň bekapy $backup_serv_id üstünlikli amala aşyryldy: $(date) Bekap URL: $backupURL"
	rm /root/openvpn.zip
}

# Autobekap menýusy
AutobakMenu(){
	echo && echo -e "
${Purple}|————————————————————————————————————|${Font_default} 
${Purple}|${Font_default}${Purple}——— Buýrugy Saýlaň ——${Font_default}${Purple}|${Font_default}
${Purple}|1.${Font_default} ${Red} Autobekapy başlatmak  ${Font_default}           ${Purple}|${Font_default}
${Purple}|2.${Font_default} ${Red} Autobekapy duruzmak ${Font_default}           ${Purple}|${Font_default}
${Purple}|3.${Font_default} ${Red} Autobekapyň wagtyny üýtgetmek ${Font_default}  ${Purple}|${Font_default}
${Purple}|————————————————————————————————————|${Font_default}" && echo
	read -e -p "(Adatça: Ýatyr):" cronbak_modify
	[[ -z "${cronbak_modify}" ]] && echo "Ýatyr..." && exit 1
	if [[ ${cronbak_modify} == "1" ]]; then
		Set_crontab
		Autobak_cron_start
	elif [[ ${cronbak_modify} == "2" ]]; then
		Autobak_cron_stop
	elif [[ ${cronbak_modify} == "3" ]]; then
		Set_crontab
		Autobak_cron_modify
	else
		echo -e "${Error} Dogry nomeri giriziň (1-3)" && exit 1
	fi
}

# Täze ulanyjy döretmek
NewOpenUser(){
	echo -e "
${Purple}|————————————————————————————————————|${Font_default} 
${Purple}|${Font_default}${Purple}—— Tegi saýlaň ——${Font_default}${Purple}|${Font_default}
${Purple}|1.${Font_default} ${Red}𝑨𝒎𝒂𝒏𝒐𝒇𝒇 𝒐𝒇𝒇𝒊𝒄𝒊𝒂𝒍  ${Font_default}
${Purple}|2.${Font_default} ${Red}۞Emir_Service_Org ${Font_default}
${Purple}|3.${Font_default} ${Red}  ፝⃟ ⃝⃕🗝𝐕𝐩𝐧 𝐔𝐧𝐥𝐨𝐜𝐤『🇹🇲』 ${Font_default}
${Purple}|4.${Font_default} ${Red}Yetmis_7 𝕏 ${Font_default}
${Purple}|5.${Font_default} ${Red}𝐴𝑛𝑜𝑛𝑦𝑚𝑜𝑢𝑠𑜞꯭᭄ً ${Font_default}
${Purple}|6.${Font_default} ${Green}Tegsyz döretmek ${Font_default}
${Purple}|————————————————————————————————————|${Font_default}"
	read -e -p "Tegi saýlaň (Adatça: Tegsyz): " adminacc
	[[ -z "${adminacc}" ]] && adminacc="6"
	if [[ ${adminacc} == "1" ]]; then
		admacc="$Deal1"
	elif [[ ${adminacc} == "2" ]]; then
		admacc="$Deal2"
	elif [[ ${adminacc} == "3" ]]; then
		admacc="$Deal3"
	elif [[ ${adminacc} == "4" ]]; then
		admacc="$Deal4"
	elif [[ ${adminacc} == "5" ]]; then
		admacc="$Deal5"
	elif [[ ${adminacc} == "6" ]]; then
		admacc=
	else
		admacc=
	fi
	echo
	echo "Ulanyjy adyny oýlaň"
	read -p "Täze At: " nickname
	unsanitized_client=$(echo "${nickname}${admacc}")
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
		echo "$client: nädogry at."
		read -p "At: " unsanitized_client
		client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	done
	cd /etc/openvpn/server/easy-rsa/
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
	# Ulanyjy üçin .ovpn faýly dörediň
	new_client
	echo
	curl -v -F "chat_id=$tg2id" -F document=@/root/$client.ovpn https://api.telegram.org/bot$bot_api/sendDocument
	clear
	echo -e "${Green}Ulanyjy goşuldy. ${Ocean}Konfigurasiýa Telegram çata ugradyldy.Telegram çaty @hzm_hacker kanalda tapyp bilersiňiz.${Font_default}" 
	exit
}

# Ulanyjyny pozmak
DeleteUser(){
	number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ "$number_of_clients" = 0 ]]; then
		echo
		echo "${Red} Ulanyjy ýok ${Font_default}"
		exit
	fi
	echo
	echo "Pozuljak ulanyjy:"
	tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
	read -p "Ulanyjy: " client_number
	until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
		echo "$client_number: nädogry girizme"
		read -p "Ulanyjy: " client_number
	done
	client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
	echo
	read -p "Siz hakykatdanam $client ulanyjyny pozmak isleýärsiňizmi? [y/N]: " revoke
	until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
		echo "$revoke: nädogry girizme"
		read -p "Siz hakykatdanam $client ulanyjyny pozmak isleýärsiňizmi? [y/N]: " revoke
	done
	if [[ "$revoke" =~ ^[yY]$ ]]; then
		cd /etc/openvpn/server/easy-rsa/
		./easyrsa --batch revoke "$client"
		EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
		rm -f /etc/openvpn/server/crl.pem
		cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
		chown nobody:"$group_name" /etc/openvpn/server/crl.pem
		rm "/root/$client.ovpn"
		clear
		curl -s -X POST https://api.telegram.org/bot"$bot_api"/sendMessage -d chat_id="$tg2id" -d text="OpenVPN açary pozuldy: Ulanyjy: ${client} Serwer: ${backup_serv_id}" >> curl.tmp
		rm -r curl.tmp
		echo "$client pozuldy!"
		read -e -p "Beýleki ulanyjylary hem pozmak isleýärsiňizmi?[Y/n]:" delyn
		[[ -z ${delyn} ]] && delyn="y"
		if [[ ${delyn} == [Nn] ]]; then
			exit
		else
			echo -e "${Info} Ulanyjylary pozmak dowam edýär..."
			DeleteUser
		fi
	else
		echo
		echo "$client pozulmakdan ýüz öwürildi!"
	fi
	exit
}

# OpenVPN serwerini pozmak
DeleteServer(){
	echo
	read -p "OpenVPN-y pozmagy tassyklamak isleýärsiňizmi? [y/N]: " remove
	until [[ "$remove" =~ ^[yYnN]*$ ]]; do
		echo "$remove: nädogry saýlaw."
		read -p "Tassyklamak isleýärsiňizmi? [y/N]: " remove
	done
	if [[ "$remove" =~ ^[yY]$ ]]; then
		port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
		protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
		if systemctl is-active --quiet firewalld.service; then
			ipserv=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24' | grep -oE '[^ ]+$')
			firewall-cmd --remove-port="$port"/"$protocol"
			firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
			firewall-cmd --permanent --remove-port="$port"/"$protocol"
			firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
			firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ipserv"
			firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ipserv"
			if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
				ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
				firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
				firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
				firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
				firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
			fi
		else
			systemctl disable --now openvpn-iptables.service
			rm -f /etc/systemd/system/openvpn-iptables.service
		fi
		if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
			semanage port -d -t openvpn_port_t -p "$protocol" "$port"
		fi
		systemctl disable --now openvpn-server@server.service
		rm -rf /etc/openvpn/server
		rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
		rm -f /etc/sysctl.d/30-openvpn-forward.conf
		if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
			apt-get remove --purge -y openvpn
		else
			yum remove -y openvpn
		fi
		echo
		echo "OpenVPN pozuldy!"
	else
		echo
		echo "Pozmakdan ýüz öwürildi."
	fi
	exit
}

# Konfigurasiýa faýlyny saklamak
SaveConf(){
	read -p "Konfigurasiýa adyny giriziň:" userconf
	curl -F "file=@/root/$userconf.ovpn" https://file.io | jq '.link'
	echo "Ýokardaky URL-ny kopýalaň we brawzerde açyň."
}

# OpenVPN maglumat bazasyny ýüklemek
UploadDB(){
	zip -r openvpn.zip /etc/openvpn
	curl -F "file=@/root/openvpn.zip" https://file.io | jq '.link'
	rm /root/openvpn.zip
	clear
	echo "
——————————————————————————————————————————————————————————————
OpenVPN maglumat bazasy üstünlikli ýüklenildi. Ýokardaky URL-ny kopýalaň.
——————————————————————————————————————————————————————————————
	"
}

# Maglumat bazasyny ýükläp almak
DownloadDB(){
	sudo systemctl stop openvpn-server@server.service
	echo "
———————————————
Baglanyşyk giriziň
———————————————
"
	read -p "|Baglanyşyk:|  " dburl
	curl -o /root/openvpn.zip $dburl
	unzip openvpn.zip -d /
	rm /root/openvpn.zip
	clear
	echo "
———————————————————————————————————————
Maglumat bazasy üstünlikli ýüklendi
———————————————————————————————————————
"
	sudo systemctl restart openvpn-server@server.service
}

# Domen üýtgetmek
DomainChange(){
	echo -e "
${Purple}|———————————————————————————————————————————————————|${Font_default}
${Purple}|${Red}Siz hakykatdanam domeni üýtgetmek isleýärsiňizmi? [y/N]${Font_default}       ${Purple}|${Font_default}
${Purple}|———————————————————————————————————————————————————|${Font_default}" && echo
	read -e -p "(Adatça: n):" yn
	[[ -z ${yn} ]] && yn="n"
	if [[ ${yn} == [Yy] ]]; then
		echo -e "${Red}Täze domeni giriziň"
		read -p "Domen:" domainname
		echo -e "${Red}Ulanylan porty giriziň"
		read -p "Port: " port
		until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
			echo "$port: nädogry maglumat"
			read -p "Port: " port
		done
		cd /etc/openvpn/server
		sed -i "1s/.*/local ${domainname}/" "server.conf"
		sed -i "2s/.*/port ${port}/" "server.conf"
		sed -i "4s/.*/remote ${domainname} ${port}/" "client-common.txt"
		sudo systemctl restart openvpn-server@server.service
		clientlist="$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2)"
		for client in $clientlist
		do
			cd /etc/openvpn/server/easy-rsa/
			./easyrsa --batch revoke "$client"
			EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
			rm -f /etc/openvpn/server/crl.pem
			cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
			chown nobody:"$group_name" /etc/openvpn/server/crl.pem
			unsanitized_client="${client}"
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			cd /etc/openvpn/server/easy-rsa/
			EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
			# Täze .ovpn faýly dörediň
			new_client
		done
		clear
		sudo systemctl restart openvpn-server@server.service
		echo -e "${Green}Açarlar üstünlikli täzelendi!${Font_default}"
		echo -e "${Purple}Açarlar ${Red}Telegram${Font_default} çata ugradylsynmy? [y/N]${Font_default}"
		read -e -p "(Adatça: n):" yn
		[[ -z ${yn} ]] && yn="n"
		if [[ ${yn} == [Yy] ]]; then
			for client in $(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2)
			do
				cd /root
				curl -v -F "chat_id=$admls" -F document=@/root/$client.ovpn https://api.telegram.org/bot$bot_api/sendDocument
			done
			echo -e "${Green}Domen üýtgetmek tamamlanyldy!${Font_default}"
		else
			clear
			echo -e "${Green}Domen üýtgetmek tamamlanyldy!${Font_default}"
		fi
	fi
}

NewUser(){
    echo -e "
${Purple}|———————————————————————————————————————————————————|${Font_default}
${Purple}|${Red}Siz hakykatdanam täze root-ly ullanyjy ýasamak isleýäňmi? [Y/n]${Font_default}       ${Purple}|${Font_default}
${Purple}|———————————————————————————————————————————————————|${Font_default}" && echo
    read -e -p "(Adatça: y):" yn
    [[ -z ${yn} ]] && yn="y"
    
    if [[ ${yn} == [Yy] ]]; then
        echo -e "${Red}Täze ulanyjynyň adyny giriziň"
        read -p "Ulanyjy ady: " username

        # Kontrolla ulanyjy adynyň bardygyny
        if id "$username" &>/dev/null; then
            echo -e "${Red}Ulanyjy eýýäm bar!${Font_default}"
            return
        fi

        # Täze ulanyjyny dörediň
        sudo adduser "$username"
        
        # Ulanyja parol goýuň
        echo -e "${Red}Täze ulanyjy üçin parol giriziň"
        sudo passwd "$username"

        # Täze ulanyja root hukuklaryny beriň
        sudo usermod -aG sudo "$username"

        # Gözegçilik üçin maglumat
        echo -e "${Green}Ulanyjy üstünlikli döredildi we root hukuklary berildi!${Font_default}"

        # Ulanyjy döretmek tamamlanyldy
        echo -e "${Purple}Täze root-ly ulanyjy ýasamak tamamlanyldy!${Font_default}"
    else
        echo -e "${Red}Amal ýatyryldy.${Font_default}"
    fi
}

# Müşderi açar döretmek
ClientGenerator(){
	cd /root
	for user in $(cat userlist.txt)
	do
		unsanitized_client="${user}"
		client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
		cd /etc/openvpn/server/easy-rsa/
		EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
		new_client
		curl -v -F "chat_id=$admls" -F document=@/root/$client.ovpn https://api.telegram.org/bot$bot_api/sendDocument
		sleep 5
	done
	clear
	echo -e "${Green}Açar döretmek tamamlanyldy ${Ocean}Telegram çata konfigurasiýalar ugradyldy${Font_default}" 
	exit
}

# OpenVPN maglumat bazasyny ýüklemek we saklamak
BaseUpload(){
	if [[ "$howto" == "link" ]]; then
		echo -e "OpenVPN bazasy buluda ýüklenilýär..." && echo
		cd "/etc/"
		tar -czvf "openvpn.tar.gz" "openvpn" && clear
		link="$(curl -F "file=@/etc/openvpn.tar.gz" "https://file.io" | jq ".link")" && clear
		echo -e "Baza üstünlikli ýüklenildi. Baglanyşyk: ${link}"
		rm "openvpn.tar.gz"
	elif [[ "$howto" == "file" ]]; then
		echo -e "OpenVPN bazasy faýl görnüşinde ýüklenilýär..." && echo
		cd "/etc/"
		tar -czvf "openvpn.tar.gz" "openvpn" && clear
		curl -s -X POST https://api.telegram.org/bot"$bot_api"/sendMessage -d chat_id="$abakid" -d text="OpenVPN bazasy üstünlikli faýl görnüşinde ýüklenildi."
		curl -v -F "chat_id=$abakid" -F document=@/etc/openvpn.tar.gz https://api.telegram.org/bot$bot_api/sendDocument
		echo -e "OpenVPN bazasy Telegram çata ugradyldy!"
	else
		cd "/etc/"
		tar -czvf "openvpn.tar.gz" "openvpn" && clear
		link="$(curl -F "file=@/etc/openvpn.tar.gz" "https://file.io" | jq ".link")" && clear
		curl -s -X POST https://api.telegram.org/bot"$bot_api"/sendMessage -d chat_id="$abakid" -d text="OpenVPN serweriniň bekapy $backup_serv_id %0A Sene: $(date) %0A Baglanyşyk: $link "
		rm "openvpn.tar.gz"
	fi
}

# Maglumat bazasyny ýükläp saklamak menýusy
BaseUploadMenu(){
	echo -e "
Baza nädip ýüklemeli?
1. Buluda
2. Faýl görnüşinde"
	read -e -p "Adatça: 1" howtoupload
	[[ -z "${howtoupload}" ]] && echo "Ýatyr..." && exit 1
	if [[ ${howtoupload} == "1" ]]; then
		howto="link"
	elif [[ ${howtoupload} == "2" ]]; then
		howto="file"
	else 
		howto="link"
	fi
	BaseUpload
}

# Maglumat bazasyny ýükläp almak
BaseDownload(){
	echo -e "Siz hereketleriňize ynamyňyz barmy?"
	read -e -p "(Adatça: n):" yn
	[[ -z ${yn} ]] && yn="n"
	if [[ ${yn} == [Yy] ]]; then
		sudo systemctl stop openvpn-server@server.service
		read -e -p "Bazanyň baglanyşygyny giriziň:" link
		cd "/etc"
		curl -o "openvpn.tar.gz" "$link"
		rm -r "openvpn"
		tar -xzvf "openvpn.tar.gz" && clear
		sudo systemctl start openvpn-server@server.service
		echo -e "Baza üstünlikli ýüklenildi!"
	fi
}

# OpenVPN serweri gurmak
InstallServer(){
	echo 'OpenVPN gurujysyna hoş geldiňiz!'
	echo "Serweriň domenini giriziň"
	read -p "Domen: " ip
	echo "Serweriň IP adresini giriziň"
	read -p "IP:" ipserv
	echo "Haýsy OpenVPN protokolyny ulanmak isleýärsiňiz?"
	echo "   1) UDP (maslahat berilýär)"
	echo "   2) TCP"
	read -p "Protokol [1]: " protocol
	until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
		echo "$protocol: nädogry saýlaw."
		read -p "Protokol [1]: " protocol
	done
	case "$protocol" in
		1|"") 
		protocol=udp
		;;
		2) 
		protocol=tcp
		;;
	esac
	echo
	echo "Haýsy porty ulanmak isleýärsiňiz?"
	read -p "Port [1194]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: nädogry port."
		read -p "Port [1194]: " port
	done
	[[ -z "$port" ]] && port="1194"
	echo
	echo "DNS serwerini saýlaň [7 saýlaň!]"
	echo "   1) Sistemaly"
	echo "   2) Google"
	echo "   3) 1.1.1.1"
	echo "   4) OpenDNS"
	echo "   5) Quad9"
	echo "   6) AdGuard"
	echo "   7) Yandex DNS"
	read -p "DNS serweri [1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-7]$ ]]; do
		echo "$dns: nädogry saýlaw."
		read -p "DNS serweri [1]: " dns
	done
	echo
	echo "Ilkinji ulanyjynyň adyny giriziň:"
	read -p "At [client]: " unsanitized_client
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="client"
	echo
	echo "OpenVPN gurulmaga taýýar."
	# Firewally gurnama, zerur bolan ýagdaýynda
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			echo "Firewalld gurulýar."
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			firewall="iptables"
		fi
	fi
	read -n1 -r -p "Dowam etmek üçin islendik düwmä basyň..."
	# Wirtual gurşawda bolsa, LimitNPROC-i öçüriň
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
		apt-get update
		apt-get install -y openvpn openssl ca-certificates $firewall
	elif [[ "$os" = "centos" ]]; then
		yum install -y epel-release
		yum install -y openvpn openssl ca-certificates tar $firewall
	else
		dnf install -y openvpn openssl ca-certificates tar $firewall
	fi
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
	# easy-rsa gurnamak
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz'
	mkdir -p /etc/openvpn/server/easy-rsa/
	{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
	chown -R root:root /etc/openvpn/server/easy-rsa/
	cd /etc/openvpn/server/easy-rsa/
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	chmod o+x /etc/openvpn/server/
	openvpn --genkey --secret /etc/openvpn/server/tc.key
	echo "local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0" > /etc/openvpn/server/server.conf
	# IPv6 üçin
	if [[ -z "$ip6" ]]; then
		echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	else
		echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
		echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	fi
	echo 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server/server.conf
	# DNS konfigurasiýasy
	case "$dns" in
		1|"")
			if grep -q '^nameserver 127.0.0.53' "/etc/resolv.conf"; then
				resolv_conf="/run/systemd/resolve/resolv.conf"
			else
				resolv_conf="/etc/resolv.conf"
			fi
			grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
				echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
			done
		;;
		2)
			echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
		;;
		3)
			echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
		;;
		4)
			echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
		;;
		5)
			echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf
		;;
		6)
			echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server/server.conf
		;;
		7)	echo 'push "dhcp-option DNS 77.88.8.88"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 77.88.8.2"' >> /etc/openvpn/server/server.conf
	esac
	echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group $group_name
persist-key
persist-tun
verb 3
crl-verify crl.pem" >> /etc/openvpn/server/server.conf
	if [[ "$protocol" = "udp" ]]; then
		echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
	fi
	# IP forwardy açmak
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-forward.conf
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/30-openvpn-forward.conf
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	if systemctl is-active --quiet firewalld.service; then
		firewall-cmd --add-port="$port"/"$protocol"
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --add-port="$port"/"$protocol"
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ipserv"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ipserv"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
		fi
	else
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ipserv
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ipserv
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
			fi
	echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
	systemctl enable --now openvpn-iptables.service
	fi
	# SELinux açyk bolsa we aýratyn port saýlandy bolsa, bu gerek
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		# Semanage ýok bolsa gurnalyň
		if ! hash semanage 2>/dev/null; then
			if [[ "$os_version" -eq 7 ]]; then
				# Centos 7
				yum install -y policycoreutils-python
			else
				# CentOS 8 ýa-da Fedora
				dnf install -y policycoreutils-python-utils
			fi
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
	# Server NAT öňünde bolsa, dogry IP adresini ulanyň
	[[ -n "$public_ip" ]] && ip="$public_ip"
	# client-common.txt döredilýär, şeýlelik bilen soňraky ulanyjylar üçin şablon bar
	echo "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3" > /etc/openvpn/server/client-common.txt
	# OpenVPN hyzmatyny işjeňleşdiriň we başlaň
	systemctl enable --now openvpn-server@server.service
	# Maxsus client.ovpn döredýär
	new_client
	echo
	sudo apt-get --yes install curl
	sudo apt-get --yes install jq
	sudo apt-get --yes install zip
	sudo apt-get --yes install net-tools
	echo "Boldy!"
	echo
	echo "Ulanyjy konfigurasiýalary şunyň ýaly ýol bilen elýeterli:" ~/"$client.ovpn"
	echo "Täze ulanyjylar skripti täzeden başlatmak bilen goşulyp bilner."
}
#else
check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} Bu skript häzirki ${release} ulgamyny goldaýan däldir!" && exit 1
action=$1
if [[ "${action}" == "parol" ]]; then
	Parol
elif [[ "${action}" == "autobak" ]]; then
	Autobak
else
	clear
	echo -e " 
${Purple}|————————————————————————————————————|${Font_default}
${Purple}|${Font_default}${Purple}———————————${Font_default} Maglumat ${Purple}—————————————${Font_default}${Purple}|${Font_default}
${Purple}|${Font_default}${Red}Ýasan:${Yellow} 𝑨𝒎𝒂𝒏𝒐𝒇𝒇 𝒐𝒇𝒇𝒊𝒄𝒊𝒂𝒍 ${Green}            ${Font_default}${Green}|${Font_default}
${Purple}|${Font_default}${Red}Telegram:${Yellow} @hzm_hacker ${Blue}            ${Font_default}${Blue}|${Font_default}
${Purple}|${Font_default}${Red}Sene: ${Yellow}[$(date +"%d-%m-%Y")]${Purple}                  ${Font_default}${Purple}|${Font_default}
${Purple}|${Font_default}${Font_default}${Red}Skriptiň wersiýasy: ${Yellow}v${sh_ver}${Font_default}${Purple}                ${Font_default}${Purple}|${Font_default}
${Purple}|————————————————————————————————————|${Font_default}
${Purple}|${Font_default}${Purple}————————${Font_default} Skriptiň gurulmagy ${Purple}—————————${Font_default}${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}1.${Font_default} ${Red}OpenVPN gurmak${Font_default}               ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}2.${Font_default} ${Red}OpenVPN aýyrmak${Font_default}                  ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}————————${Font_default} Açarlary dolandyrmak ${Purple}————————${Font_default}${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}3.${Font_default} ${Red}Açar döretmek${Font_default}                     ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}4.${Font_default} ${Red}Açar aýyrmak${Font_default}                     ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}5.${Font_default} ${Red}Açar ýüklemek${Font_default}                     ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}———————————${Font_default} Database ${Purple}————————————${Font_default}${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}6.${Font_default} ${Red}Database çykarmak${Font_default}                   ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}7.${Font_default} ${Red}Database ýüklemek${Font_default}                   ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}8.${Font_default} ${Red}Avtomatiki bäkap goýmak${Font_default}             ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}————————${Font_default} Skripti dolandyrmak ${Purple}———————${Font_default}${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}9.${Font_default} ${Red}OpenVPN açmak${Font_default}                 ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}10.${Font_default} ${Red}OpenVPN aýyrmak${Font_default}               ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}11.${Font_default} ${Red}OpenVPN täzeden başlamagy${Font_default}           ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}12.${Font_default} ${Red}Domeni üýtgetmek${Font_default}                   ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}13.${Font_default} ${Red}Täze root-ly ullanyjy ýasamak${Font_default}                   ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}14.${Font_default} ${Red}Awtomatik aýyrmak menýsy${Font_default}               ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}15.${Font_default} ${Red}Çykmak${Font_default}                           ${Purple}|${Font_default}
${Purple}|————————————————————————————————————|${Font_default} 
	 "
	read -p "Işlem: " option
	case "$option" in
		1)
		InstallServer
		;;
		2)
		DeleteServer
		;;
		3)
		NewOpenUser
		;;
		4)
		DeleteUser
		;;
		5)
		SaveConf
		;;
		6)
		UploadDB
		;;
		7)
		DownloadDB
		;;
		8)
		AutobakMenu
		;;
		9)
		sudo systemctl start openvpn-server@server.service
		echo -e "${Red}OpenVPN ${Green}başladyldy${Font_default}"
		;;
		10)
		sudo systemctl stop openvpn-server@server.service
		echo -e "${Red}OpenVPN ${Red}toxtady${Font_default}"
		;;
		11)
		sudo systemctl restart openvpn-server@server.service
		echo -e "${Red}OpenVPN ${Yellow}täzeden başlanýar${Font_default}"
		;;
		12)
		DomainChange
		;;
		13)
		NewUser
		;;
		13)
		AutoDelMenu
		;;
		14)
		exit
		;;
		15)
		ClientGenerator
		;;
		16)
		BaseUploadMenu
		;;
	esac
fi

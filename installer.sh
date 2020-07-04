#!/bin/bash
#
# Terima kasih untuk NyR dan Skiddow
# https://github.com/Nyr/openvpn-install
#
# Copyright (c) 2020 LV. Released under the MIT License.


# Deteksi pengguna Debian menjalankan script dengan "sh" bukannya bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo "Script ini harus dijalankan dengan bash, bukan sh"
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "Maaf, kamu harus menjalankan ini sebagai root"
	exit
fi

if [[ ! -e /dev/net/tun ]]; then
	echo "Perangkat TUN tidak tersedia
Kamu harus mengaktifkan TUN sebelum menjalankan script ini"
	exit
fi

if [[ -e /etc/debian_version ]]; then
	OS=debian
	GROUPNAME=nogroup
	RCLOCAL='/etc/rc.local'
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	GROUPNAME=nobody
	RCLOCAL='/etc/rc.d/rc.local'
else
	echo "Sepertinya kamu menjalankan installer ini bukan di Debian, Ubuntu atau CentOS"
	exit
fi

newclient () {
	# Membuat client.ovpn
	cp /etc/openvpn/client-common.txt ~/$1.ovpn
	echo "<ca>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1.ovpn
	echo "</ca>" >> ~/$1.ovpn
	echo "<cert>" >> ~/$1.ovpn
	sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1.ovpn
	echo "</cert>" >> ~/$1.ovpn
	echo "<key>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1.ovpn
	echo "</key>" >> ~/$1.ovpn
	echo "<tls-auth>" >> ~/$1.ovpn
	sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/ta.key >> ~/$1.ovpn
	echo "</tls-auth>" >> ~/$1.ovpn
}

if [[ -e /etc/openvpn/server.conf ]]; then
	while :
	do
	clear
		echo "Sepertinya OpenVPN sudah terinstall."
		echo
		echo "Apa yang mau kamu lakukan?"
		echo "   1) Tambah user baru"
		echo "   2) Batalkan akses user yang sudah ada"
		echo "   3) Hapus OpenVPN"
		echo "   4) Keluar"
		read -p "Pilih jawaban [1-4]: " option
		case $option in
			1) 
			echo
			echo "Silakan beri nama certificate ini untuk client di OpenVPN GUI."
			echo "Maaf, gunakan satu kata saja, tidak usah pakai karakter selain alfabet."
			read -p "Name client: " -e CLIENT
			cd /etc/openvpn/easy-rsa/
			EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full $CLIENT nopass
			# Membuat client.ovpn
			newclient "$CLIENT"
			echo
			echo "Client $CLIENT berhasil dibuat, filenya bisa kamu unduh disini:" ~/"$CLIENT.ovpn"
			exit
			;;
			2)
			# Pilihan ini bisa didokumentasikan sedikit lebih baik dan bisa disederhanakan
			# ...tapi aku bisa bilang apa, Aku juga mau tidur
			NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
				echo
				echo "Kamu tidak punya client aktif!"
				exit
			fi
			echo
			echo "Coba pilih certificate client yang ada yang mau kamu batalkan aksesnya:"
			tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
				read -p "Pilih satu client [1]: " CLIENTNUMBER
			else
				read -p "Pilih satu client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
			fi
			CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
			echo
			read -p "Apa kamu yakin mau hapus akses untuk client $CLIENT? [y/N]: " -e REVOKE
			if [[ "$REVOKE" = 'y' || "$REVOKE" = 'Y' ]]; then
				cd /etc/openvpn/easy-rsa/
				./easyrsa --batch revoke $CLIENT
				EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
				rm -f /etc/openvpn/crl.pem
				cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
				# CRL dibaca dengan setiap koneksi client, ketika OpenVPN jatuh ke nobody
				chown nobody:$GROUPNAME /etc/openvpn/crl.pem
				echo
				echo "Certificate untuk client $CLIENT dibatalkan aksesnya!"
			else
				echo
				echo "Pembatalan certificate untuk client $CLIENT digagalkan!"
			fi
			exit
			;;
			3) 
			echo
			read -p "Apa kamu yakin mau menghapus OpenVPN? [y/N]: " -e REMOVE
			if [[ "$REMOVE" = 'y' || "$REMOVE" = 'Y' ]]; then
				PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
				PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
				if pgrep firewalld; then
					IP=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24 -j SNAT --to ' | cut -d " " -f 10)
					# Menggunakan keduanya baik aturan permanent atau tidak permanent untuk mencegah firewalld dimuat ulang.
					firewall-cmd --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
				else
					IP=$(grep 'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to ' $RCLOCAL | cut -d " " -f 14)
					iptables -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
					sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0\/24 ! -d 10.8.0.0\/24 -j SNAT --to /d' $RCLOCAL
					if iptables -L -n | grep -qE '^ACCEPT'; then
						iptables -D INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
						iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
						iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
						sed -i "/iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT/d" $RCLOCAL
						sed -i "/iptables -I FORWARD -s 10.8.0.0\/24 -j ACCEPT/d" $RCLOCAL
						sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
					fi
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$PORT" != '1194' ]]; then
					semanage port -d -t openvpn_port_t -p $PROTOCOL $PORT
				fi
				if [[ "$OS" = 'debian' ]]; then
					apt-get remove --purge -y openvpn
				else
					yum remove openvpn -y
				fi
				rm -rf /etc/openvpn
				rm -f /etc/sysctl.d/30-openvpn-forward.conf
				echo
				echo "OpenVPN dihapus!"
			else
				echo
				echo "Penghapusan dibatalkan!"
			fi
			exit
			;;
			4) exit;;
		esac
	done
else
	clear
	echo 'Selamat datang di installer OpenVPN "road warrior"!'
	echo
	# Instalasi OpenVPN dan pembuatan client pertama
	echo "Ada beberapa pertanyaan yang harus dijawab sebelum memulai instalasi."
	echo "Kamu bisa biarkan pilihan standardnya dan tekan enter kalau kamu setuju dengan pilihannya."
	echo
	echo "Pertama, masukkan alamat IPv4 untuk OpenVPN ini. Cek saja IP server kamu ini."
	echo "arahkan ke."
	# Deteksi otomatis alamat IP dan isi langsung untuk si user
	IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
	read -p "Alamat IP: " -e -i $IP IP
	# Kalau $IP adalah alamat IP private, maka servernya pasti dibelakang NAT
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "Server ini dibelakang NAT. Masukkan alamat IPv4 public atau hostname nya."
		read -p "Alamat IP public / hostname: " -e PUBLICIP
	fi
	echo
	echo "Protokol mana yang mau kamu gunakan untuk koneksi ke OpenVPN?"
	echo "   1) UDP (direkomendasikan)"
	echo "   2) TCP"
	read -p "Protokol [1-2]: " -e -i 1 PROTOCOL
	case $PROTOCOL in
		1) 
		PROTOCOL=udp
		;;
		2) 
		PROTOCOL=tcp
		;;
	esac
	echo
	echo "Kamu mau buka port nomor berapa untuk OpenVPN?"
	read -p "Port: " -e -i 1194 PORT
	echo
	echo "Kamu mau pakai DNS yang mana dengan VPN ini?"
	echo "   1) Pakai yang ada di sistem ini"
	echo "   2) 1.1.1.1"
	echo "   3) Google"
	echo "   4) OpenDNS"
	echo "   5) Verisign"
	read -p "DNS [1-5]: " -e -i 1 DNS
	echo
	echo "Terakhir, mau dikasi nama apa certificate untuk client ini?"
	echo "Tolong gunakan satu kata saja, tidak usah pakai karakter selain alfabet."
	read -p "Nama Client: " -e -i client CLIENT
	echo
	echo "Oke, semua yang dibutuhkan sudah lengkap. Kita siap buat instalasi server OpenVPN sekarang. INI AKAN LUMAYAN MAKAN WAKTU"
	read -n1 -r -p "Ketik sembarang di keyboard untuk melanjutkan..."
	if [[ "$OS" = 'debian' ]]; then
		apt-get update
		apt-get install openvpn iptables openssl ca-certificates -y
	else
		# Selain ini, distronya mungkin CentOS
		yum install epel-release -y
		yum install openvpn iptables openssl ca-certificates -y
	fi
	# Dapatkan easy-rsa
	EASYRSAURL='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.6/EasyRSA-unix-v3.0.6.tgz'
	wget -O ~/easyrsa.tgz "$EASYRSAURL" 2>/dev/null || curl -Lo ~/easyrsa.tgz "$EASYRSAURL"
	tar xzf ~/easyrsa.tgz -C ~/
	mv ~/EasyRSA-v3.0.6/ /etc/openvpn/
	mv /etc/openvpn/EasyRSA-v3.0.6/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -f ~/easyrsa.tgz
	cd /etc/openvpn/easy-rsa/
	# Buat PKI, siapkan CA dan server serta certificate client
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full $CLIENT nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	# Pindahkan file yang kita butuhkan
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn
	# CRL dibaca dengan setiap koneksi client, ketika OpenVPN jatuh ke nobody
	chown nobody:$GROUPNAME /etc/openvpn/crl.pem
	# Buat key untuk tls-auth
	openvpn --genkey --secret /etc/openvpn/ta.key
	# GBuat parameter DH
	openssl dhparam -out /etc/openvpn/dh2048.pem 2048
	# Buat server.conf
	echo "port $PORT
proto $PROTOCOL
dev tun
sndbuf 0
rcvbuf 0
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
auth SHA512
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server.conf
	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf
	# DNS
	case $DNS in
		1)
		# Letakkan resolv.conf dengan tepat
		# Dibutuhkan untuk systems menjalankan systemd-resolved
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# Dapatkan resolvers dari resolv.conf dan gunakan untuk OpenVPN
		grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
		done
		;;
		2)
		echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server.conf
		;;
		3)
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
		;;
		4)
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
		;;
		5)
		echo 'push "dhcp-option DNS 64.6.64.6"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 64.6.65.6"' >> /etc/openvpn/server.conf
		;;
	esac
	echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group $GROUPNAME
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem" >> /etc/openvpn/server.conf
	# Aktifkan net.ipv4.ip_alihkan ke system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-forward.conf
	# Aktifkan tanpa meunggu reboot atau restart service
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if pgrep firewalld; then
		# Gunakan keduanya baik aturan permanent atau tidak permanent untuk mencegah firewalld
		# dimuat ulang.
		# Kita tidak pakai --add-service=openvpn karna itu mungkin cuma bisa dengan
		# port standard dan protokol.
		firewall-cmd --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		# Siapkan NAT untuk subnet VPN
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
	else
		# Dibutuhkan untuk rc.local dengan beberapa distro systemd
		if [[ "$OS" = 'debian' && ! -e $RCLOCAL ]]; then
			echo '#!/bin/sh -e
exit 0' > $RCLOCAL
		fi
		chmod +x $RCLOCAL
		# Siapkan NAT untuk subnet VPN
		iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
		sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL
		if iptables -L -n | grep -qE '^(REJECT|DROP)'; then
			# Kalau iptables paling tidak satu aturan REJECT, maka asumsikan ini dibutuhkan.
			# Bukan pendekatan terbaik tapi aku tidak bisa nemukan cara lain dan ini tidak seharusnya
			# menyebabkan masalah.
			iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
			iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
			iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
			sed -i "1 a\iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
		fi
	fi
	# Kalau SELinux aktif dan port baru yang dipilih, kita perlu ini
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$PORT" != '1194' ]]; then
		# Install semanage kalau belum ada
		if ! hash semanage 2>/dev/null; then
			yum install policycoreutils-python -y
		fi
		semanage port -a -t openvpn_port_t -p $PROTOCOL $PORT
	fi
	# Dan terakhir, restart OpenVPN
	if [[ "$OS" = 'debian' ]]; then
		# Sedikit cek kebelakang untuk systemd
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
		else
			/etc/init.d/openvpn restart
		fi
	else
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
			systemctl enable openvpn@server.service
		else
			service openvpn restart
			chkconfig openvpn on
		fi
	fi
	# Kalau servernya dibelakang NAT, gunakan alamat IP yang benar
	if [[ "$PUBLICIP" != "" ]]; then
		IP=$PUBLICIP
	fi
	# client-common.txt dibuat jadi kita punya template untuk menambahkan user baru lagi nanti
	echo "client
dev tun
proto $PROTOCOL
sndbuf 0
rcvbuf 0
remote $IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
setenv opt block-outside-dns
key-direction 1
verb 3" > /etc/openvpn/client-common.txt
	# Buat client.ovpn
	newclient "$CLIENT"
	echo
	echo "Selesai!"
	echo
	mv ~/"$CLIENT.ovpn" /home/"$CLIENT.ovpn"
	echo "File berhasil dibuat, filenya bisa kamu unduh disini::" /home/"$CLIENT.ovpn"
	echo "Kalau mau menambahkan untuk perangkat lain, buat client baru dengan menjalankan script ini lagi!"
fi

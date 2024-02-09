import pyshark
import requests
import pymongo
from datetime import datetime


def insert_data_to_mongodb(src_ip, src_port, dst_ip, dst_port, protocol, result, times):
    # MongoDB'ye bağlanın (default olarak localhost:27017)
    client = pymongo.MongoClient("mongodb://localhost:27017/")

    # Veritabanını seçin (varsa, yoksa otomatik olarak oluşturulur)
    db = client["mydatabase"]

    # Koleksiyon adı
    collection = db["mycollection"]

    try:
        # Veriyi ekleyin
       # Veriyi oluştur
        data = {
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'protocol': protocol,
            'result': result,
            'time': times
        }
        
        # Veriyi MongoDB'ye ekle
        collection.insert_one(data)

        print("Veri başarıyla MongoDB'ye eklendi.")
    except Exception as e:
        print("Veri eklenirken bir hata oluştu:", e)
    finally:
        # Bağlantıyı kapatın
        client.close()


def send_prediction_request(data):
    # Flask API'sine istek gönder
    url = "http://127.0.0.1:5000/predict"  # Flask uygulamasının çalıştığı adresi ve portu kullanın
    response = requests.post(url, json=data)
    

    # İstek sonucunu ekrana yazdır
    print(f"Prediction Result: {response.json()}")
    return response.json()

# Trafik izleme başlat
capture = pyshark.LiveCapture('Wi-Fi')

# Verileri saklamak için bir list oluştur

print("Start-->")

# Trafik izleme döngüsü
for packet in capture.sniff_continuously():
    
    # Tarih ve saat bilgisini al
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]  # Milisaniyeyi dahil et, ancak son 3 hanesini kes

    #src_port = int(packet[protocol].srcport)
    if 'TCP' in packet:
        src_port = int(packet['TCP'].srcport)
    elif 'UDP' in packet:
        src_port = int(packet['UDP'].srcport)
    # Diğer taşıma katmanı protokollerini de burada ele alabilirsiniz
    else:
        src_port = 0  # Eğer taşıma katmanı protokolü bulunamazsa src_port'a None atayın veya uygun bir hata işlemi yapın

    #dst_port = int(packet[protocol].dstport)
    if 'TCP' in packet:
        dst_port = int(packet['TCP'].dstport)
    elif 'UDP' in packet:
        dst_port = int(packet['UDP'].dstport)
    # Diğer taşıma katmanı protokollerini de burada ele alabilirsiniz
    else:
        dst_port = 0  # Eğer taşıma katmanı protokolü bulunamazsa src_port'a None atayın veya uygun bir hata işlemi yapın


    if (dst_port == 5001):
        # Paketin kaynak ve hedef IP adreslerini alın
        # Paketin kaynak IP adresini alın
        if 'ip' in packet:
            src_ip = packet.ip.src
        elif 'ipv6' in packet:
            src_ip = packet.ipv6.src
        else:
            src_ip = "Unknown"

        # Paketin kaynak IP adresini alın
        if 'ip' in packet:
            dst_ip = packet.ip.dst
        elif 'ipv6' in packet:
            dst_ip = packet.ipv6.dst
        else:
            dst_ip = "Unknown"
        print("Source ip: ", src_ip)
        print("Destination ip: ", dst_ip)

        # Paketin transport layer protokolünü alın (TCP, UDP veya ICMP)
        protocol = packet.transport_layer

        # Paketin kaynak ve hedef port numaralarını alın
        
        # Paketin veri boyutunu alın
        src_bytes = len(packet)

        # Land flag kontrolü
        land = 1 if src_ip == dst_ip and src_port == dst_port else 0

        # Flag değerlerini alın
        flags = packet.tcp.flags if 'TCP' in packet else packet.ip.flags

        # Flag değerlerini string olarak alın
        flag_values = ''
        if flags:
            if len(flags) >= 7:  # flags değişkeni en az 7 karakter içeriyorsa
                if flags[0] == '1':
                    flag_values += 'FIN '
                if flags[1] == '1':
                    flag_values += 'SYN '
                if flags[2] == '1':
                    flag_values += 'RST '
                if flags[3] == '1':
                    flag_values += 'PSH '
                if flags[4] == '1':
                    flag_values += 'ACK '
                if flags[5] == '1':
                    flag_values += 'URG '
                if flags[6] == '1':
                    flag_values += 'ECE '
                if len(flags) > 7 and flags[7] == '1':
                    flag_values += 'CWR '
            else:
                flag_values = 'None'


        # Wrong fragment bilgisini alın
        flags_hex = packet.ip.flags
        wrong_fragment = int(flags_hex, 16) & 0x02

        # Urgent flag kontrolü
        if 'TCP' in packet:
            tcp_layer = packet['TCP']
            # TCP paketinin urg (Urgent) özelliğini kontrol et
            urgent = tcp_layer.urg if hasattr(tcp_layer, 'urg') else 0
        else:
            urgent = 0
        #urgent = packet.tcp.flags.urg if protocol == 'TCP' else 0
            
        # Hedef portuna göre hizmet türünü belirle
        if dst_port == '80':
            service = 'HTTP'
        elif dst_port == '443':
            service = 'HTTPS'
        elif dst_port == '21':
            service = 'FTP'
        elif dst_port == '22':
            service = 'SSH'
        elif dst_port == '23':
            service = 'Telnet'
        elif dst_port == '25':
            service = 'SMTP'
        elif dst_port == '53':
            service = 'DNS'
        elif dst_port in ('67', '68'):
            service = 'DHCP'
        elif dst_port in ('161', '162'):
            service = 'SNMP'
        elif dst_port == '110':
            service = 'POP3'
        elif dst_port == '143':
            service = 'IMAP'
        elif dst_port == '123':
            service = 'NTP'
        elif dst_port == '445':
            service = 'SMB'
        elif dst_port == '3389':
            service = 'RDP'
        else:
            service = 'Other'

        # Hot flag kontrolü (örneğin, bazı spesifik kelimelerin varlığı gibi)
        payload = packet.transport_layer if packet.transport_layer else ""
        hot = payload.count('entering a system directory') + payload.count('creating programs') + payload.count('executing programs')

        # Num_failed_logins: Count of failed login attempts.
        num_failed_logins = payload.count('failed login')

        # Logged_in Login Status: 1 if successfully logged in; 0 otherwise.
        logged_in = 1 if payload.count('logged in') else 0

        # Num_compromised: Number of “compromised’ ‘ conditions.
        num_compromised = payload.count('compromised')

        # Root_shell: 1 if root shell is obtained; 0 otherwise.
        root_shell = 1 if payload.count('root shell') else 0

        # Su_attempted: 1 if “su root” command attempted or used; 0 otherwise.
        su_attempted = 1 if payload.count('su root') else 0

        # Num_root: Number of “root” accesses or number of operations performed as a root in the connection.
        num_root = payload.count('root')

        # Num_file_creations: Number of file creation operations in the connection.
        num_file_creations = payload.count('file creation')

        # Num_shells: Number of shell prompts.
        num_shells = payload.count('shell prompt')

        # Num_access_files: Number of operations on access control files.
        num_access_files = payload.count('access file')

        # Num_outbound_cmds: Number of outbound commands in an ftp session.
        num_outbound_cmds = payload.count('outbound command')

        # Is_hot_login: 1 if the login belongs to the “hot” list i.e., root or admin; else 0.
        is_hot_login = 1 if logged_in and (root_shell or su_attempted) else 0

        # Is_guest_login: 1 if the login is a “guest” login; 0 otherwise.
        is_guest_login = 1 if payload.count('guest') else 0

        # Elde edilen verileri bir dictionary'e ekleyerek listeye ekleyin
        data = {
            #'src_ip': src_ip,
            #'dst_ip': dst_ip,
            'protocol_type': protocol,
            'src_port': src_port,
            'dst_port': dst_port,
            'src_bytes': src_bytes,
            'land': land,
            'flag':flag_values,
            'service': service,
            'wrong_fragment': wrong_fragment,
            'urgent': urgent,
            'hot': hot,
            'num_failed_logins': num_failed_logins,
            'logged_in': logged_in,
            'num_compromised': num_compromised,
            'root_shell': root_shell,
            'su_attempted': su_attempted,
            'num_root': num_root,
            'num_file_creations': num_file_creations,
            'num_shells': num_shells,
            'num_access_files': num_access_files,
            'num_outbound_cmds': num_outbound_cmds,
            'is_host_login': is_hot_login,
            'is_guest_login': is_guest_login
        }

        pre = send_prediction_request(data=data)
        
        insert_data_to_mongodb(src_ip, src_port, dst_ip, dst_port, protocol, pre.get('prediction')[0], timestamp)


    # Programı durdurmak istediğiniz zaman kullanıcıdan bir giriş alabilirsiniz
    #stop = input("Programı durdurmak için 'q' tuşuna basın, devam etmek için Enter tuşuna basın: ")
    #if stop.lower() == 'q':
    #    break

# Trafik izleme döngüsünden çıkın ve kaynağı serbest bırakın
capture.close()
from scapy.all import sniff, IP, ICMP, TCP, UDP, Raw
import requests

def extract_numeric_value(raw_data):
    try:
        numeric_value = int(raw_data)
        return numeric_value if 0 <= numeric_value <= 4 else 0
    except ValueError:
        return 0

def get_land_value(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet.sport if hasattr(packet, 'sport') else None
        dst_port = packet.dport if hasattr(packet, 'dport') else None

        land_value = 1 if src_ip == dst_ip and src_port == dst_port else 0
        return land_value

def get_service_type(payload):
    if "private" in payload.lower():
        return "private"
    elif "icmp" in payload.lower():
        return "icmp"
    elif "telnet" in payload.lower():
        return "telnet"
    elif "ftp" in payload.lower():
        return "ftp"
    elif "smtp" in payload.lower():
        return "smtp"
    elif "ldap" in payload.lower():
        return "ldap"
    elif "discard" in payload.lower():
        return "discard"
    elif "http" in payload.lower():
        return "http"
    elif "imap4" in payload.lower():
        return "imap4"
    elif "systat" in payload.lower():
        return "systat"
    elif "pop_3" in payload.lower():
        return "pop_3"
    elif "ftp_data" in payload.lower():
        return "ftp_data"
    else:
        return "other"

def get_protocol_type(packet):
    if IP in packet:
        if ICMP in packet:
            return "icmp"
        elif TCP in packet:
            return "tcp"
        elif UDP in packet:
            return "udp"
    return "other"


def send_prediction_request(data):
    # Flask API'sine istek gönder
    url = "http://127.0.0.1:5000/predict"  # Flask uygulamasının çalıştığı adresi ve portu kullanın
    response = requests.post(url, json=data)
    
    # İstek sonucunu ekrana yazdır
    print(f"Prediction Result: {response.json()}")


def packet_callback(packet):
    if IP in packet:

        protocol_type = get_protocol_type(packet)

        # Service türünü al
        service_type = get_service_type(packet.load.decode('utf-8', errors='ignore')) if packet.haslayer('Raw') else "other"

        logged_in = 0
        root_shell = 0
        su_attempted = 0

        if packet.haslayer("Raw"):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')

            # Payload içinde Num Failed Logins ara
            if "Num Failed Logins" in payload:
                import re
                match = re.search(r'Num Failed Logins: (\d+)', payload)
                if match:
                    num_failed_logins = int(match.group(1))

            logged_in = 1 if "logged in" in payload.lower() else 0
            root_shell = 1 if "root shell" in payload.lower() else 0
            su_attempted = 1 if "su attempted" in payload.lower() else 0

        timestamp = packet.time if hasattr(packet, 'time') else 0
        duration = timestamp - packet.time

        flag = packet.sprintf("%TCP.flags%") if protocol_type == "tcp" else 0
        src_bytes = int(packet.sprintf("%IP.len%"))
        dst_bytes = len(packet)
        land = get_land_value(packet)
        wrong_fragment = int(packet.sprintf("%IP.frag%"))
        
        # Urgent ve Hot değerlerini kontrol et
        urgent = packet.sprintf("%TCP.urg%") if protocol_type == "tcp" and packet.sprintf("%TCP.urg%") != '??' else 0
        hot = int(packet.sprintf("%TCP.window%") if protocol_type == "tcp" else 0)

        # Num Failed Logins değerini sayısal karakterlere dönüştür
        raw_payload = packet.load.decode('utf-8', errors='ignore') if packet.haslayer('Raw') else ''
        num_failed_logins = extract_numeric_value(raw_payload)
        
        input_data = prepare_input_data(protocol_type, service_type, logged_in, root_shell, duration, su_attempted, flag, src_bytes, dst_bytes, land, wrong_fragment, urgent, hot, num_failed_logins)
        
        # Flask API'sine istek gönder
        send_prediction_request(input_data)

def prepare_input_data(protocol_type, service_type, logged_in, root_shell, duration, su_attempted, flag, src_bytes, dst_bytes, land, wrong_fragment, urgent, hot, num_failed_logins):
    # Bu kısımda paketten gerekli bilgileri çıkartarak Flask API'sine gönderebilirsiniz
    # Örnek olarak sadece kaynak ve hedef IP adreslerini ve port numaralarını alıyoruz
    input_data = {
        'protocol_type': protocol_type,
        'service': service_type,
        'logged_in': logged_in,
        'root_shell': root_shell,
        'duration': duration,
        'su_attempted': su_attempted,
        'flag': flag,
        'src_bytes': src_bytes,
        'dst_bytes': dst_bytes,
        'land': land,
        'wrong_fragment': wrong_fragment,
        'urgent': urgent,
        'hot': hot,
        'num_failed_logins': num_failed_logins,
    }

    return input_data


# Tüm trafiği izle ve her paket için packet_callback fonksiyonunu çağır
sniff(prn=packet_callback, store=0)
# sniff(prn=packet_callback, filter="host localhost and port 8080", store=0)

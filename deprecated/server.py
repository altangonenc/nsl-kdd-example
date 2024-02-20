import socket
import joblib
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from flask import Flask, request, jsonify, json
import time

xgb_model = joblib.load('xgb_model.pkl')

def main():
    host = "192.168.1.32"
    port = 5001
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    server_socket.bind(server_address)
    server_socket.listen(1)

    print("Sunucu ayakta.")

    while True:
        conn, addr = server_socket.accept()
        
        print("Bağlantı alındı:", addr)
        start_time = time.time()
        time.sleep(2)
        data = conn.recv(1024)
        request = data.decode()        
        response_data = "geri donus aldin hadi yoluna bro."
        conn.sendall(response_data.encode())
        end_time = time.time()
        total_time = end_time - start_time
        dataD = {
            "src_bytes": len(request),
            "protocol_type": "tcp",
            "duration": total_time,
            "dst_bytes": len(response_data)
        }
        
        dataD = prepare_input_data(dataD)
        input_data = preprocess_data(dataD)
        prediction = xgb_model.predict(input_data)
        if prediction == True:
            print("Saldırı tespit edildi!".encode())
        else:
            print("Saldırı tespit edilmedi.".encode())


        print(input_data.to_string())
        # GUESS
        print(json.dumps({'prediction': prediction.tolist()}))


        conn.close()

def prepare_input_data(data):
    required_columns = [
        "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
        "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
        "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
        "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", 
        "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
        "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
    ]

    # eksik verileri 0 ile doldur
    for column in required_columns:
        if column not in data:
            data[column] = 0

    # sutunları doğru sırayla sırala
    data = {col: data[col] for col in required_columns}

    return data

def preprocess_data(data):
    # LabelEncoderlari her istek geldiginde olustur
    protocol_type_le = LabelEncoder()
    service_le = LabelEncoder()
    flag_le = LabelEncoder()

    # convert to DataFrame
    df = pd.DataFrame([data])
    
    # Label sütununu kaldir
    if 'label' in df.columns:
        df = df.drop(['label'], axis=1)
    
    # Label encoding 
    df['protocol_type'] = protocol_type_le.fit_transform(df['protocol_type'])
    df['service'] = service_le.fit_transform(df['service'])
    df['flag'] = flag_le.fit_transform(df['flag'])
    
    return df


if __name__ == "__main__":
    main()

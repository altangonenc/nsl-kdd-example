import socket
import joblib
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from flask import Flask, request, jsonify, json

xgb_model = joblib.load('xgb_model.pkl')

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 5000))
    s.listen(1)
    print("Sunucu ayakta.")

    while True:
        conn, addr = s.accept()
        print("Bağlantı alındı:", addr)

        data = conn.recv(1024)
        request = data.decode()
        
        dataD = {"src_bytes": len(request)}
        dataD = prepare_input_data(dataD)
        input_data = preprocess_data(dataD)
        prediction = xgb_model.predict(input_data)

        print(input_data.to_string())
        # GUESS
        print(json.dumps({'prediction': prediction.tolist()}))

        if prediction == True:
            conn.sendall("Saldırı tespit edildi!".encode())
        else:
            conn.sendall("Saldırı tespit edilmedi.".encode())

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

    # Eksik verileri 0 ile doldur
    for column in required_columns:
        if column not in data:
            data[column] = 0

    # Sütunları doğru sırayla sırala
    data = {col: data[col] for col in required_columns}

    return data

def preprocess_data(data):
    # LabelEncoder nesnelerini her istek geldiğinde oluştur
    protocol_type_le = LabelEncoder()
    service_le = LabelEncoder()
    flag_le = LabelEncoder()

    # Veriyi bir DataFrame'e çevir
    df = pd.DataFrame([data])
    
    # Label sütununu kaldır
    if 'label' in df.columns:
        df = df.drop(['label'], axis=1)
    
    # Label encoding işlemi
    df['protocol_type'] = protocol_type_le.fit_transform(df['protocol_type'])
    df['service'] = service_le.fit_transform(df['service'])
    df['flag'] = flag_le.fit_transform(df['flag'])
    
    return df


if __name__ == "__main__":
    main()

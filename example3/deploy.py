# Örnek Flask API
from flask import Flask, request, jsonify
import joblib
import pandas as pd
from sklearn.preprocessing import LabelEncoder

app = Flask(__name__)

# Modeli yükle
xgb_model = joblib.load('xgb_model.pkl')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    print("data -------> ")

    print(data)
    data = prepare_input_data(data)

    # Gelen veriyi modele uygun formata çevir
    input_data = preprocess_data(data)
    # Tahmin yap
    prediction = xgb_model.predict(input_data)
    # Tahmini JSON formatında döndür
    return jsonify({'prediction': prediction.tolist()})

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



if __name__ == '__main__':
    app.run(debug=True)
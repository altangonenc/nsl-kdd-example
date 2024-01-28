import pandas as pd
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
import joblib

# Veri setini yükleyin
train_data = pd.read_csv("/content/KDDTrain+.txt")
test_data = pd.read_csv("/content/KDDTest+.txt")

column_list = (["duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot",
          "num_failed_logins","logged_in","num_compromised","root_shell","su_attempted","num_root","num_file_creations","num_shells",
          "num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
          "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count", 
          "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
          "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"])

train_data.columns = column_list
test_data.columns  = column_list

# Eksik etiketleri kontrol et
missing_labels_in_test = set(test_data['label']) - set(train_data['label'])

# Eksik etiketlere sahip verileri çıkar
test_data = test_data[~test_data['label'].isin(missing_labels_in_test)]

# Binary Classification için label değerlerini güncelle
train_data['label'] = train_data['label'].apply(lambda x: 0 if x == 'normal' else 1)
test_data['label'] = test_data['label'].apply(lambda x: 0 if x == 'normal' else 1)

# Eğitim ve test veri setlerini ayırın
X_train = train_data.drop(['label'], axis=1)
y_train = train_data['label']

X_test = test_data.drop(['label'], axis=1)
y_test = test_data['label']

# Label encoding işlemi
protocol_type_le = LabelEncoder()
service_le = LabelEncoder()
flag_le = LabelEncoder()

X_train['protocol_type'] = protocol_type_le.fit_transform(X_train['protocol_type'])
X_train['service'] = service_le.fit_transform(X_train['service'])
X_train['flag'] = flag_le.fit_transform(X_train['flag'])

X_test['protocol_type'] = protocol_type_le.transform(X_test['protocol_type'])
X_test['service'] = service_le.transform(X_test['service'])
X_test['flag'] = flag_le.transform(X_test['flag'])

# XGBoost modelini oluşturun ve eğitin (parametreleri optimize etmek önemlidir)
# En iyi parametreler: {'learning_rate': 0.1, 'max_depth': 5, 'min_child_weight': 1, 'n_estimators': 200, 'subsample': 0.8}

xgb_model = XGBClassifier(learning_rate=0.1, max_depth=10, min_child_weight=1, n_estimators =200, subsample=0.8, random_state=42)
#En iyi parametreler: {'learning_rate': 0.1, 'max_depth': 5, 'min_child_weight': 1, 'n_estimators': 200, 'subsample': 0.8}

# Cross-validation ile modelin doğruluğunu değerlendirin
cross_val_scores = cross_val_score(xgb_model, X_train, y_train, cv=5, scoring='accuracy')
print("Cross-Validation Doğruluk Oranları:", cross_val_scores)
print("Ortalama Doğruluk Oranı:", cross_val_scores.mean())

# Modeli eğitelim
xgb_model.fit(X_train, y_train)

# Modeli dosyaya kaydet
joblib.dump(xgb_model, 'xgb_model.pkl')

# Test seti üzerinde modelin performansını değerlendirin
def evaluate_model(model, X, y):
    y_pred = model.predict(X)
    accuracy = accuracy_score(y, y_pred)
    report = classification_report(y, y_pred)
    matrix = confusion_matrix(y, y_pred)
    return accuracy, report, matrix

# Test seti üzerinde XGBoost modelinin performansını değerlendirin
xgb_accuracy, xgb_report, xgb_confusion_matrix = evaluate_model(xgb_model, X_test, y_test)
print("\nXGBoost Model Performansı:")
print(f"Doğruluk Oranı: {xgb_accuracy}")
print("Classification Report:\n", xgb_report)
print("Confusion Matrix:\n", xgb_confusion_matrix)

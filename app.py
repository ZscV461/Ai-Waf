from flask import Flask, jsonify
import os
import glob
import pandas as pd
import numpy as np
from urllib.parse import urlparse
from sklearn.preprocessing import LabelEncoder
import joblib
import re
from datetime import datetime

app = Flask(__name__)

# Load the saved RandomForestClassifier model
model_path = r"D:\Studing\Lectures_32\Firewall & WAF\Section\Project\model.pkl"
try:
    random_forest_model = joblib.load(model_path)
    print("Model loaded successfully from", model_path)
except FileNotFoundError:
    print(f"Error: {model_path} not found. Please ensure model.pkl exists.")
    exit(1)

# Feature extraction functions (unchanged)
def count_dot(url):
    return url.count('.')

def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')

def shortening_service(url):
    match = re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      r'tr\.im|link\.zip\.net', url)
    return 1 if match else 0

def count_http(url):
    return url.count('http')

def count_per(url):
    return url.count('%')

def count_ques(url):
    return url.count('?')

def count_hyphen(url):
    return url.count('-')

def count_equal(url):
    return url.count('=')

def url_length(url):
    return len(str(url))

def hostname_length(url):
    return len(urlparse(url).netloc)

def suspicious_words(url):
    score_map = {
        'error': 30, 'errorMsg': 30, 'id': 10, 'errorID': 30, 'SELECT': 50, 'FROM': 50, 'WHERE': 50,
        'DELETE': 50, 'USERS': 50, 'DROP': 50, 'CREATE': 50, 'INJECTED': 50, 'TABLE': 50, 'alert': 30,
        'javascript': 20, 'cookie': 25, '--': 30, '.exe': 30, '.php': 20, '.js': 10, 'admin': 10,
        'administrator': 10, r'\'': 30, 'password': 15, 'login': 15, 'incorrect': 20, 'pwd': 15,
        'tamper': 25, 'vaciar': 20, 'carrito': 25, 'wait': 30, 'delay': 35, 'set': 20, 'steal': 35,
        'hacker': 35, 'proxy': 35, 'location': 30, 'document.cookie': 40, 'document': 20, 'set-cookie': 40,
        'create': 40, 'cmd': 40, 'dir': 30, 'shell': 40, 'reverse': 30, 'bin': 20, 'cookiesteal': 40,
        'LIKE': 30, 'UNION': 35, 'include': 30, 'file': 20, 'tmp': 25, 'ssh': 40, 'exec': 30, 'cat': 25,
        'etc': 30, 'fetch': 25, 'eval': 30, 'malware': 45, 'ransomware': 45, 'phishing': 45, 'exploit': 45,
        'virus': 45, 'trojan': 45, 'backdoor': 45, 'spyware': 45, 'rootkit': 45, 'credential': 30,
        'inject': 30, 'script': 25, 'iframe': 25, 'src=': 25, 'onerror': 30, 'prompt': 20, 'confirm': 20,
        'eval': 25, 'expression': 30, r'function\(': 20, 'xmlhttprequest': 30, 'xhr': 20, 'window.': 20,
        'document.': 20, 'cookie': 25, 'click': 15, 'mouseover': 15, 'onload': 20, 'onunload': 20,
    }
    matches = re.findall(r'(?i)' + '|'.join(map(re.escape, score_map.keys())), url)
    return sum(score_map.get(match.lower(), 0) for match in matches)

def digit_count(url):
    return sum(1 for i in url if i.isnumeric())

def letter_count(url):
    return sum(1 for i in url if i.isalpha())

def count_special_characters(url):
    special_characters = re.sub(r'[a-zA-Z0-9\s]', '', url)
    return len(special_characters)

def number_of_parameters(url):
    params = urlparse(url).query
    return 0 if params == '' else len(params.split('&'))

def number_of_fragments(url):
    frags = urlparse(url).fragment
    return len(frags.split('#')) - 1 if frags else 0

def is_encoded(url):
    return int('%' in url.lower())

def unusual_character_ratio(url):
    total_characters = len(url)
    unusual_characters = re.sub(r'[a-zA-Z0-9\s\-._]', '', url)
    return len(unusual_characters) / total_characters if total_characters > 0 else 0

def apply_to_content(content, function):
    if pd.isna(content):
        return 0
    elif isinstance(content, str):
        return function(content)
    return 0

# Function to parse Unified2 log file
def parse_unified2_log(log_file):
    entries = []
    log_basename = os.path.basename(log_file)
    
    try:
        with open(log_file, 'rb') as f:
            content = f.read().decode('utf-8', errors='ignore')
        
        # Regular expression to match HTTP requests
        http_pattern = r'(GET|POST)\s+([^\s]+)\s+HTTP/1\.1.*?Host:\s*([^\r\n]+).*?(?:\r\n\r\n([^\r\n]*))?'
        matches = re.finditer(http_pattern, content, re.DOTALL)
        
        for match in matches:
            method = match.group(1)
            path = match.group(2)
            host = match.group(3).strip()
            body = match.group(4) or ''
            
            # Construct URL
            url = f"http://{host}{path}"
            
            # Extract content (query for GET, body for POST)
            content = urlparse(url).query if method == 'GET' else body
            
            # Use file modification time as timestamp
            file_mtime = os.path.getmtime(log_file)
            timestamp = datetime.fromtimestamp(file_mtime).strftime('%m/%d-%H:%M:%S.%f')
            
            entry = {
                'URL': url,
                'content': content,
                'Method': method,
                'Timestamp': timestamp,
                'LogFile': log_basename
            }
            entries.append(entry)
        
        if not entries:
            print(f"No HTTP requests found in {log_file}.")
        
    except Exception as e:
        print(f"Error parsing {log_file}: {e}")
    
    return entries

# Function to preprocess and extract features
def preprocess_input(data, method_encoder=None):
    if isinstance(data, dict):
        data = pd.DataFrame([data])
    
    for col in ['URL', 'content', 'Method']:
        if col not in data.columns:
            data[col] = '' if col in ['URL', 'content'] else 'GET'
    
    if method_encoder is None:
        method_encoder = LabelEncoder()
        data['Method_enc'] = method_encoder.fit_transform(data['Method'])
    else:
        data['Method_enc'] = method_encoder.transform(data['Method'])
    
    data['count_dot_url'] = data['URL'].apply(count_dot)
    data['count_dir_url'] = data['URL'].apply(no_of_dir)
    data['count_embed_domain_url'] = data['URL'].apply(no_of_embed)
    data['short_url'] = data['URL'].apply(shortening_service)
    data['count-http'] = data['URL'].apply(count_http)
    data['count%_url'] = data['URL'].apply(count_per)
    data['count?_url'] = data['URL'].apply(count_ques)
    data['count-_url'] = data['URL'].apply(count_hyphen)
    data['count=_url'] = data['URL'].apply(count_equal)
    data['url_length'] = data['URL'].apply(url_length)
    data['hostname_length_url'] = data['URL'].apply(hostname_length)
    data['sus_url'] = data['URL'].apply(suspicious_words)
    data['count-digits_url'] = data['URL'].apply(digit_count)
    data['count-letters_url'] = data['URL'].apply(letter_count)
    data['number_of_parameters_url'] = data['URL'].apply(number_of_parameters)
    data['number_of_fragments_url'] = data['URL'].apply(number_of_fragments)
    data['is_encoded_url'] = data['URL'].apply(is_encoded)
    data['special_count_url'] = data['URL'].apply(count_special_characters)
    data['unusual_character_ratio_url'] = data['URL'].apply(unusual_character_ratio)
    
    data['count_dot_content'] = data['content'].apply(lambda x: apply_to_content(x, count_dot))
    data['count_dir_content'] = data['content'].apply(lambda x: apply_to_content(x, no_of_dir))
    data['count_embed_domain_content'] = data['content'].apply(lambda x: apply_to_content(x, no_of_embed))
    data['count%_content'] = data['content'].apply(lambda x: apply_to_content(x, count_per))
    data['count?_content'] = data['content'].apply(lambda x: apply_to_content(x, count_ques))
    data['count-_content'] = data['content'].apply(lambda x: apply_to_content(x, count_hyphen))
    data['count=_content'] = data['content'].apply(lambda x: apply_to_content(x, count_equal))
    data['content_length'] = data['content'].apply(lambda x: apply_to_content(x, url_length))
    data['sus_content'] = data['content'].apply(lambda x: apply_to_content(x, suspicious_words))
    data['count_digits_content'] = data['content'].apply(lambda x: apply_to_content(x, digit_count))
    data['count_letters_content'] = data['content'].apply(lambda x: apply_to_content(x, letter_count))
    data['special_count_content'] = data['content'].apply(lambda x: apply_to_content(x, count_special_characters))
    data['is_encoded_content'] = data['content'].apply(lambda x: apply_to_content(x, is_encoded))
    data['unusual_character_ratio_content'] = data['content'].apply(lambda x: apply_to_content(x, unusual_character_ratio))
    
    features = ['count_dot_url', 'count_dir_url', 'count_embed_domain_url', 'count-http', 'count%_url',
                'count?_url', 'count-_url', 'count=_url', 'url_length', 'hostname_length_url', 'sus_url',
                'count-digits_url', 'count-letters_url', 'number_of_parameters_url', 'is_encoded_url',
                'special_count_url', 'unusual_character_ratio_url', 'Method_enc', 'count_dot_content',
                'count%_content', 'count-_content', 'count=_content', 'sus_content', 'count_digits_content',
                'count_letters_content', 'content_length', 'is_encoded_content', 'special_count_content']
    
    return data[features], method_encoder

# Function to make predictions
def predict(data, model, method_encoder=None):
    X, method_encoder = preprocess_input(data, method_encoder)
    predictions = model.predict(X)
    label_map = {0: 'Anomalous', 1: 'Normal'}
    return [label_map[pred] for pred in predictions], method_encoder

# Flask route to process logs and return results
@app.route('/process_logs', methods=['GET'])
def process_logs():
    log_dir = r"C:\Snort\log"
    
    # Find all Unified2 log files
    log_files = glob.glob(os.path.join(log_dir, "snort.log.*"))
    if not log_files:
        return jsonify({'error': f"No snort.log.* files found in {log_dir}. Please check the directory."}), 400
    
    # Parse Unified2 logs
    all_entries = []
    for log_file in log_files:
        entries = parse_unified2_log(log_file)
        if entries:
            all_entries.extend(entries)
    
    if not all_entries:
        return jsonify({'error': "No HTTP requests found in any log files. Check log content or Snort configuration."}), 400
    
    # Convert to DataFrame
    df = pd.DataFrame(all_entries)
    
    # Make predictions
    method_encoder = None
    predictions, method_encoder = predict(df, random_forest_model, method_encoder)
    
    # Add predictions to DataFrame
    df['Prediction'] = predictions
    
    # Prepare response
    results = df[['Timestamp', 'LogFile', 'URL', 'content', 'Method', 'Prediction']].to_dict(orient='records')
    summary = df['Prediction'].value_counts().to_dict()
    
    return jsonify({
        'results': results,
        'summary': summary,
        'message': f"Processed {len(all_entries)} HTTP requests from {len(log_files)} log files."
    })

# Serve the main page
@app.route('/')
def index():
    with open('index.html', 'r') as f:
        return f.read()

if __name__ == "__main__":
    app.run(debug=True)
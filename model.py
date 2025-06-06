# Model.py
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib
import re

# Load and preprocess data
df = pd.read_csv("D:/Studing/Lectures_32/Firewall & WAF/Section/Project/csic_database.csv")
df = df.drop(['User-Agent', 'Pragma', 'Cache-Control', 'Accept',
              'Accept-encoding', 'Accept-charset', 'language',
              'content-type'], axis=1)

X = df.copy()
y = X['Unnamed: 0']

# Encode labels
label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y)

# Feature extraction functions
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

# Apply feature extraction
X['count_dot_url'] = X['URL'].apply(count_dot)
X['count_dir_url'] = X['URL'].apply(no_of_dir)
X['count_embed_domain_url'] = X['URL'].apply(no_of_embed)
X['short_url'] = X['URL'].apply(shortening_service)
X['count-http'] = X['URL'].apply(count_http)
X['count%_url'] = X['URL'].apply(count_per)
X['count?_url'] = X['URL'].apply(count_ques)
X['count-_url'] = X['URL'].apply(count_hyphen)
X['count=_url'] = X['URL'].apply(count_equal)
X['url_length'] = X['URL'].apply(url_length)
X['hostname_length_url'] = X['URL'].apply(hostname_length)
X['sus_url'] = X['URL'].apply(suspicious_words)
X['count-digits_url'] = X['URL'].apply(digit_count)
X['count-letters_url'] = X['URL'].apply(letter_count)
X['number_of_parameters_url'] = X['URL'].apply(number_of_parameters)
X['number_of_fragments_url'] = X['URL'].apply(number_of_fragments)
X['is_encoded_url'] = X['URL'].apply(is_encoded)
X['special_count_url'] = X['URL'].apply(count_special_characters)
X['unusual_character_ratio_url'] = X['URL'].apply(unusual_character_ratio)

def apply_to_content(content, function):
    if pd.isna(content):
        return 0
    elif isinstance(content, str):
        return function(content)
    return 0

X['count_dot_content'] = X['content'].apply(lambda x: apply_to_content(x, count_dot))
X['count_dir_content'] = X['content'].apply(lambda x: apply_to_content(x, no_of_dir))
X['count_embed_domain_content'] = X['content'].apply(lambda x: apply_to_content(x, no_of_embed))
X['count%_content'] = X['content'].apply(lambda x: apply_to_content(x, count_per))
X['count?_content'] = X['content'].apply(lambda x: apply_to_content(x, count_ques))
X['count-_content'] = X['content'].apply(lambda x: apply_to_content(x, count_hyphen))
X['count=_content'] = X['content'].apply(lambda x: apply_to_content(x, count_equal))
X['content_length'] = X['content'].apply(lambda x: apply_to_content(x, url_length))
X['sus_content'] = X['content'].apply(lambda x: apply_to_content(x, suspicious_words))
X['count_digits_content'] = X['content'].apply(lambda x: apply_to_content(x, digit_count))
X['count_letters_content'] = X['content'].apply(lambda x: apply_to_content(x, letter_count))
X['special_count_content'] = X['content'].apply(lambda x: apply_to_content(x, count_special_characters))
X['is_encoded_content'] = X['content'].apply(lambda x: apply_to_content(x, is_encoded))
X['unusual_character_ratio_content'] = X['content'].apply(lambda x: apply_to_content(x, unusual_character_ratio))

# Encode Method
method_encoder = LabelEncoder()
X['Method_enc'] = method_encoder.fit_transform(X['Method'])

# Select features for training
features = ['count_dot_url', 'count_dir_url', 'count_embed_domain_url', 'count-http', 'count%_url',
            'count?_url', 'count-_url', 'count=_url', 'url_length', 'hostname_length_url', 'sus_url',
            'count-digits_url', 'count-letters_url', 'number_of_parameters_url', 'is_encoded_url',
            'special_count_url', 'unusual_character_ratio_url', 'Method_enc', 'count_dot_content',
            'count%_content', 'count-_content', 'count=_content', 'sus_content', 'count_digits_content',
            'count_letters_content', 'content_length', 'is_encoded_content', 'special_count_content']

X = X[features]

# Split data
x_tr, x_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Train RandomForestClassifier
random_forest_model = RandomForestClassifier(n_estimators=100, random_state=42)
random_forest_model.fit(x_tr, y_tr)

# Save the model to a .pkl file
joblib.dump(random_forest_model, r'D:\Studing\Lectures_32\Firewall & WAF\Section\Project\model.pkl')
print("Model saved to model.pkl")
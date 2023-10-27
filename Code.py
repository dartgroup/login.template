import requests
import re

def is_sql_injection(url, payload):
    """SQL enjeksiyon açığı olup olmadığını kontrol eder."""
    response = requests.get(url + payload)
    if re.search(r"SQL syntax", response.text):
        return ("SQL Injection", response.status_code, response.text)

def is_xss(url, payload):
    """XSS açığı olup olmadığını kontrol eder."""
    response = requests.get(url + payload)
    if re.search(r"<script>", response.text):
        return ("XSS", response.status_code, response.text)

def is_file_inclusion(url, payload):
    """Dosya dahil etme açığı olup olmadığını kontrol eder."""
    response = requests.get(url + payload)
    if re.search(r"file_get_contents\(", response.text):
        return ("File Inclusion", response.status_code, response.text)

def is_path_traversal(url, payload):
    """Yol geçişi açığı olup olmadığını kontrol eder."""
    response = requests.get(url + payload)
    if re.search(r"../", response.text):
        return ("Path Traversal", response.status_code, response.text)

def is_csrf(url, payload):
    """CSRF açığı olup olmadığını kontrol eder."""
    response = requests.post(url + payload)
    if response.cookies:
        return ("CSRF", response.status_code, response.text)
    else:
        return False

def is_session_fixation(url, payload):
    """Oturum sabitleme açığı olup olmadığını kontrol eder."""
    response = requests.post(url + payload)
    if response.cookies:
        return ("Session Fixation", response.status_code, response.text)
    else:
        return False

def is_open_redirect(url, payload):
    """Açık yönlendirme açığı olup olmadığını kontrol eder."""
    response = requests.get(url + payload)
    location_header = response.headers.get("Location")
    if location_header and location_header != url:
        return ("Open Redirect", response.status_code, response.text)
    else:
        return False

def is_cross_site_scripting(url, payload):
    """Çapraz site betikleme açığı olup olmadığını kontrol eder."""
    response = requests.get(url + payload)
    if re.search(r"<script>(.*?)</script>", response.text):
        return ("Cross-Site Scripting", response.status_code, response.text)

def is_clickjacking(url, payload):
    """Clickjacking açığı olup olmadığını kontrol eder."""
    response = requests.get(url + payload)
    if re.search(r"<iframe", response.text):
        return ("Clickjacking", response.status_code, response.text)

def is_information_leak(url, payload):
    """Bilgi sızıntısı açığı olup olmadığını kontrol eder."""
    response = requests.get(url + payload)
    if re.search(r"(password|secret|token)", response.text):
        return ("Information Leak", response.status_code, response.text)

def is_vulnerable(url):
    vulnerabilities = []
    for vulnerability, payload in [
        (is_sql_injection, "' or 1=1 --"),
        (is_xss, "<script>alert('XSS')</script>"),
        (is_file_inclusion, "/etc/passwd"),
        (is_path_traversal, "../../../../etc/passwd"),
        (is_csrf, "csrf_token=123"),
        (is_session_fixation, "session=123"),
        (is_open_redirect, "http://evil.com"),
        (is_cross_site_scripting, "<script>alert('XSS')</script>"),
        (is_clickjacking, '<iframe src="http://evil.com"></iframe>'),
        (is_information_leak, "password"),
        # Ek açık tespit fonksiyonlarını buraya ekleyin
    ]:
        result = vulnerability(url, payload)
        if result:
            vulnerabilities.append(f"{result[0]} açığı bulundu. Durum Kodu: {result[1]}\n Yanıt: {result[2]}")
    return vulnerabilities

def main():
    url = input("Taranacak URL'yi girin: ")
    vulnerabilities = is_vulnerable(url)
    if vulnerabilities:
        print("Aşağıdaki açıklar bulundu:")
        for vulnerability in vulnerabilities:
            print(vulnerability)
    else:
        print("Açık bulunamadı.")

if __name__ == "__main__":
    main()

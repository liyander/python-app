from app_clean import check_url_phishing_simple, check_email_phishing_simple

print('Testing URL...')
print(check_url_phishing_simple('https://www.google.com'))
print(check_url_phishing_simple('http://paypal-security-update.malicious.net'))
print('\nTesting Email...')
print(check_email_phishing_simple('Hello, this is a normal message about your meeting.'))
print(check_email_phishing_simple('URGENT! Your account will be suspended. Click https://paypal-verify.tk/account to verify now!'))

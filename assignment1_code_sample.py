import os
import pymysql
from urllib.request import urlopen

# 1
# Vulnerability: Database credentials are exposed by the hard coding. This can lead to unauthorized access to the database.
# OWASP: A02:2021-Cryptographic Failures
# Measurement: The database credentials should be stored in a secure or local location. For example, .env file should be utilized to store the credentials. Additionally, the .env file must be added to .gitignore to prevent uploading it to GitHub repository.
db_config = {
    'host': 'mydatabase.com',
    'user': 'admin',
    'password': 'secret123'
}

def get_user_input():
    # 2
    # Vulnerability: The user input dosen't have validation logic to prevent SQL injection. This can lead to SQL injection attacks.
    # OWASP: A03:2021-Injection
    # Measurement: The user input must be validated and sanitized to prevent SQL injection attacks. For example, the logic should have regex to allow only expected characters
    user_input = input('Enter your name: ')
    return user_input

def send_email(to, subject, body):
    # 3
    # Vulnerability: The send_email function is not secure because it uses the os.system() function to send an email. This can lead to command injection attacks.
    # OWASP: A03:2021-Injection
    # Measurement: The email function should utilize a secure Python library such as smtplib. The smtplib library allows sending emails securely. 
    os.system(f'echo {body} | mail -s "{subject}" {to}')

def get_data():
    # 4
    # Vulnerability: The get_data function is not secure because API url is exposed and it uses HTTP instead of HTTPS. Therefore, who can intercept the data during the transmission.
    # A02:2021-Cryptographic Failures
    # Measurement: The get_data function should use HTTPS instead of HTTP to secure the data transmission. Additionally, the API URL should be stored in a secure location.
    url = 'http://insecure-api.com/get-data'
    data = urlopen(url).read().decode()
    return data

def save_to_db(data):
    # 5
    # Vulnerability: The save_to_db function is not secure because query is using string concatenation to insert data into the database. This can lead to SQL injection attacks.
    # OWASP: A03:2021-Injection
    # Measurement: The save_to_db function should use prepared statements (parameterized queries) to prevent SQL injection attacks.
    query = f"INSERT INTO mytable (column1, column2) VALUES ('{data}', 'Another Value')"
    connection = pymysql.connect(**db_config)
    cursor = connection.cursor()
    cursor.execute(query)
    connection.commit()
    cursor.close()
    connection.close()

if __name__ == '__main__':
    # 6
    # Vulnerability: The main function is not secure because it is calling all the functions without any validation or error handling. This can lead to show sensitive information during errors.
    # OWASP: A05:2021-Security Misconfiguration 
    # Measurement: The main function should have proper error handling and validation logic to prevent security vulnerabilities. For example, the main function should have try-except blocks to handle exceptions.
    user_input = get_user_input()
    data = get_data()
    save_to_db(data)
    send_email('admin@example.com', 'User Input', user_input)

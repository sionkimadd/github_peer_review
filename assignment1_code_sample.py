import os
import pymysql
from urllib.request import urlopen


# [OWASP A02:2021 - Cryptographic Failures]
# Hardcoded credentials expose sensitive information.
# Attackers gaining access to source code can retrieve database credentials.
# Fix: Use environment variables or a secure vault for credentials.
db_config = {
    'host': 'mydatabase.com',
    'user': 'admin',
    'password': 'secret123'
}


# [OWASP A05:2021 - Security Misconfiguration]
# No input validation or sanitization, allowing injection attacks.
# Fix: Implement input validation and sanitization.
def get_user_input():
    user_input = input('Enter your name: ')  # Unvalidated input
    return user_input


# [OWASP A03:2021 - Injection]
# Command injection vulnerability: `os.system()` executes shell commands with user-provided input.
# An attacker could manipulate `to` or `body` parameters to execute arbitrary commands.
# Fix: Use `subprocess.run()` with safe input handling.
def send_email(to, subject, body):
    os.system(f'echo {body} | mail -s "{subject}" {to}')  # Shell command injection risk!


# [OWASP A04:2021 - Insecure Design]
# Calls an **unsecured API (HTTP instead of HTTPS)**, exposing sensitive data in transit.
# Fix: Use HTTPS and validate the API response.
def get_data():
    url = 'http://insecure-api.com/get-data'  # Unencrypted API request
    data = urlopen(url).read().decode()  # No error handling, risk of request failures
    return data


# [OWASP A03:2021 - Injection]
# SQL Injection: Data is **directly concatenated into the query**, allowing attackers to execute arbitrary SQL commands.
# Fix: Use **parameterized queries**.
def save_to_db(data):
    query = f"INSERT INTO mytable (column1, column2) VALUES ('{data}', 'Another Value')"  # SQL Injection risk!
    connection = pymysql.connect(**db_config)
    cursor = connection.cursor()
    cursor.execute(query)  # Unsafe execution!
    connection.commit()
    cursor.close()
    connection.close()


if __name__ == '__main__':
    user_input = get_user_input()  # No input validation
    data = get_data()  # Retrieves unvalidated external data
    save_to_db(data)  # SQL Injection risk
    send_email('admin@example.com', 'User Input', user_input)  # Command injection risk

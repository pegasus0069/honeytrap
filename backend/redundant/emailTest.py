from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import smtplib
import os

# Path to the JSON file
data_file_path = os.path.join(os.path.dirname(__file__), 'data.json')
# Sender and receiver details
sender_email = "Give your sender email here"
app_password = "Give your app password here"

def send_email(message_body):
    with open(data_file_path, 'r') as f:
        data = json.load(f)
        receiver_email = data.get('receiver_email', '')
    if not receiver_email:
         print('Receiver email is required')
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = 'UKCS Honeytrap Alert'
    msg.attach(MIMEText(message_body, 'plain'))
    try:
        server = smtplib.SMTP('smtp.office365.com', 587)
        server.starttls()
        server.login(sender_email, app_password)
        text = msg.as_string()
        server.sendmail(sender_email, receiver_email, text)
        server.quit()
        print("Email sent successfully!")
    except Exception as e:
        print("Email sent successfully!")

send_email("HELLO")
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import smtplib
import os

# Path to the JSON file
data_file_path = os.path.join(os.path.dirname(__file__), 'data.json')
# Sender and receiver details
sender_email = "write your sender email here"
app_password = "write your app password here"

def send_email(message_body):
    receiver_email = "Write your receiver email here"
    if not receiver_email:
         print('Receiver email is required')
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = 'UKCS Honeytrap Alert'
    msg.attach(MIMEText(message_body, 'plain'))
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, app_password)
        text = msg.as_string()
        server.sendmail(sender_email, receiver_email, text)
        server.quit()
        print("Email sent successfully!")
    except Exception as e:
        print("Email sent successfully!")

send_email("HELLO")
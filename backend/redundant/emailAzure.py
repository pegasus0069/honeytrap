import msal
import requests
import os
import json

# Path to the JSON file
data_file_path = os.path.join(os.path.dirname(__file__), 'data.json')

# Microsoft App Credentials
CLIENT_ID = "7db9bd2d-a6c2-4de3-9bfb-e9d8a84e57a5"
CLIENT_SECRET = "ylI8Q~XebouTeKkGZ.dbBaCC2drZoVgUKFpfPbNM"
TENANT_ID = "e0d4f0ff-16df-4da2-b17f-3026b80f7a32"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["https://graph.microsoft.com/.default"]
SENDER_EMAIL = "donotreply@ukcybersecurity.co.uk"

# Get Access Token
def get_access_token():
    app = msal.ConfidentialClientApplication(CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET)
    token_response = app.acquire_token_for_client(scopes=SCOPES)
    
    if "access_token" in token_response:
        return token_response["access_token"]
    else:
        raise Exception(f"Failed to get token: {token_response}")

# Send Email using Microsoft Graph API
def send_email():
    token = get_access_token()
    url = "https://graph.microsoft.com/v1.0/users/{}/sendMail".format(SENDER_EMAIL)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    email_data = {
        "message": {
            "subject": "UKCS Honeytrap Alert",
            "body": {
                "contentType": "Text",
                "content": "There is a new event detected in the UKCS Honeytrap system."
            },
            "toRecipients": [
                {"emailAddress": {"address": RECIPIENT_EMAIL}}
            ]
        }
    }
    response = requests.post(url, headers=headers, json=email_data)
    
    if response.status_code == 202:
        print("Email sent successfully!")
    else:
        print(f"Failed to send email: {response.status_code}, {response.text}")

if __name__ == "__main__":
    with open(data_file_path, 'r') as f:
        data = json.load(f)
        RECIPIENT_EMAIL = data.get('receiver_email', '')
        print(RECIPIENT_EMAIL)
    if not RECIPIENT_EMAIL:
        print('Receiver email is required')
    send_email()
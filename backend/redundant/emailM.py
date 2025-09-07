from O365 import Account

credentials = ("your-client-id", "your-client-secret")
account = Account(credentials)

if account.authenticate():
    m = account.new_message()
    m.to.add("hasinmahir@yahoo.com")
    m.subject = "Test Email"
    m.body = "This is a test email sent using O365 library."
    m.send()
    print("Email sent successfully!")
else:
    print("Authentication failed.")
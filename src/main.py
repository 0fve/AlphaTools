from flask import Flask
from flask_mail import Mail, Message
from Website import alpha



alpha = alpha()
app = alpha.create_app()
if __name__ == "__main__":

    # deepcode ignore BindToAllNetworkInterfaces: I need debug for now :)
    app[0].run("0.0.0.0", port=8000, debug=True)


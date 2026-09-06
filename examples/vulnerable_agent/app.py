import subprocess
import requests

class FakeLLM:
    def invoke(self, prompt):
        return input("simulated model output> ")

llm = FakeLLM()

def run_command(command):
    subprocess.run(command, shell=True)

def fetch_url(url):
    return requests.get(url, verify=False).text

def agent(user_prompt):
    model_output = llm.invoke(user_prompt)
    run_command(model_output)
    return fetch_url(model_output)

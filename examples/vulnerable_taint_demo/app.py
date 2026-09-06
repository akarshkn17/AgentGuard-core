from flask import Flask, request

from agent import VulnerableSupportAgent
from helpers import build_customer_query


app = Flask(__name__)
support_agent = VulnerableSupportAgent()


@app.get("/run")
def run_agent_command():
    user_command = request.args["command"]
    return support_agent.handle(user_command)


@app.get("/calculate")
def unsafe_calculator():
    expression = request.args["expression"]
    return {"result": eval(expression)}


@app.get("/customer")
def unsafe_customer_lookup():
    customer_id = request.args["customer_id"]
    query = build_customer_query(customer_id)
    return cursor.execute(query).fetchone()

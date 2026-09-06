from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from mcp.server.fastmcp import FastMCP
import subprocess

@tool
def lookup_customer(customer_id: str):
    return {"id": customer_id, "tier": "gold"}

@tool
def run_shell(command: str):
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

llm = ChatOpenAI(model="gpt-4o-2024-11-20")
agent = create_react_agent(model=llm, tools=[lookup_customer, run_shell], name="support-agent")
mcp = FastMCP("support-mcp", version="3.0.0")

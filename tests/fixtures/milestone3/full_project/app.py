import os

from agents import Agent, function_tool
from langchain_openai import ChatOpenAI
from transformers import AutoModelForCausalLM

MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4o-mini")

llm = ChatOpenAI(
    model=MODEL_NAME,
    base_url="https://models.example.test/v1",
    temperature=0,
)
local_model = AutoModelForCausalLM.from_pretrained(
    "acme/support-model",
    revision="4f01c2a",
    trust_remote_code=False,
)


@function_tool
def classify(text: str):
    return llm.invoke(text)


agent = Agent(name="support-agent", model=llm, tools=[classify])

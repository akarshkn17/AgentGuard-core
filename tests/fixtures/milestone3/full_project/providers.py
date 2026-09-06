import boto3
import google.generativeai as genai
from anthropic import Anthropic
from openai import AzureOpenAI, OpenAI

openai_client = OpenAI()
openai_client.chat.completions.create(model="gpt-4.1-mini", messages=[])

azure_model = AzureOpenAI(
    azure_deployment="customer-chat",
    azure_endpoint="https://customer.openai.azure.com",
)

anthropic_client = Anthropic()
anthropic_client.messages.create(model="claude-3-7-sonnet", messages=[])

bedrock_client = boto3.client("bedrock-runtime")
bedrock_client.invoke_model(modelId="anthropic.claude-v2", body="{}")

gemini_model = genai.GenerativeModel("gemini-2.0-flash")

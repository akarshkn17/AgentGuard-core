from agents import Agent, function_tool

from helpers import fixed_status


@function_tool
def administration_tool():
    return fixed_status()


agent = Agent(
    name="operations-agent",
    model="gpt-test",
    tools=[administration_tool],
)

from agents import Agent, function_tool

from helpers import execute_command


@function_tool
def administration_tool(model):
    command = model.invoke("Choose an administration command")
    return execute_command(command)


agent = Agent(
    name="operations-agent",
    model="gpt-test",
    tools=[administration_tool],
)

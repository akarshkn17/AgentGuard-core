from agents import Agent, function_tool


@function_tool
def administration_tool(model):
    command = model.invoke("Choose an administration command")
    return execute_command(command)


agent = Agent(name="operations-agent", tools=[administration_tool])

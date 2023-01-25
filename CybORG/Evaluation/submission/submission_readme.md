# Example submission
This folder contains an example of a valid submission. It provides examples of the files that you need to submit in your submission. 

## Validation of results

This folder should contain all the files needed to run agents, to enable us to validate the results your submission.
There should be a file called submission.py which has a dictionary called _agents_. 
You should define the blue agent names: blue_agent_0, blue_agent_0, blue_agent_1, ... blue_agent_17, as keys in your _agents_ dictionary and assign your blue agent objects as values for these keys. We will assign the [SleepAgent](../../Agents/SimpleAgents/ConstantAgent.py) to any undefined agent names.
Your blue agent class should inherit from the [BaseAgent class](../../Agents/SimpleAgents/BaseAgent.py) and provide an implementation for the functions in the BaseAgent class.

The example submission.py file in this folder has code that creates a RandomAgent object for each of the blue agents in the environment. The code snippet below illustrates how to instantiate a Python dictionary containing 18 RandomAgent objects. 

```python3
from .RandomAgent import RandomAgent

agents = {f"blue_agent_{agent}": RandomAgent() for agent in range(18)}
```


The submission.py also contains the wrap function, which wraps the CybORG environment to alter the interface. The following example illustrates a wrap function for the PettingZooParallelWrapper. 
```python3
from CybORG.Agents.Wrappers import PettingZooParallelWrapper

def wrap(env):
    return PettingZooParallelWrapper(env=env)
```

Other important aspects of the submission are the full evaluation results and the results summary printout. A summary of the results are printed to terminal and written to a date and time stamped file with the format date_time_summary. The full results are also writen to a file with the format date_time_full. Please include both of these files in your submission.

Finally, please include a Dockerfile that creates a container to run your agents. 
This will help us ensure that your agents run as intended. 
We have included an example [Dockerfile](../../../Dockerfile) in the base of this repo, together with [instructions](docker_instructions.md) on how to use Docker for the purpose of evaluating agents in CybORG.

# Description of approach

As part of your submission, we request that you share a description of the methods/techniques used in developing your agents. 
We will use this information as part of our in-depth analysis and comparison of the various techniques submitted to the challenge. 
In hosting the CAGE challenges, one of our main goals is to understand the techniques that lead to effective autonomous cyber defensive agents, as well as those that are not as effective.
We are planning on publishing the analysis and taxonomy of the different approaches that create autonomous cyber defensive agents. 
To that end, we encourage you to also share details on any unsuccessful approaches taken. Please also feel free to share any interesting discoveries and thoughts regarding future work to help us shape the future of the CAGE Challenges.

We provide a [latex template](submission_template_example/template_readme.md) as a guide for writing your description.
An examplar description can be found [here](https://arxiv.org/pdf/2211.15557.pdf).

# Checklist for submission

Please include the following in your submission:

- All files required to run the agents
- a file named submission.py containing the following:
  - agents dictionary
  - wrap function
  - submission_name string
  - submission_team string
  - submission_technique string
- A Dockerfile that creates the environment required to run your agents
- Description of approach
- Summary of evaluation results
- (optional) Full evaluation results

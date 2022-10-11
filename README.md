# Copyright DST Group. Licensed under the MIT license.

# Cyber Operations Research Gym (CybORG)

A cyber security research environment for training and development of security human and autonomous agents. Contains a common interface for both emulated, using cloud based virtual machines, and simulated network environments.

## Installation

Install CybORG locally using pip from the main directory that contains this readme

```
pip install -e .
```


## Creating the environment
Import the necessary classes:
```
from CybORG import CybORG
from CybORG.Agents import RedMeanderAgent, B_lineAgent, SleepAgent
from CybORG.Agents.Wrappers.OpenAIGymWrapper import OpenAIGymWrapper
from CybORG.Agents.Wrappers.PettingZooParallelWrapper import PettingZooParallelWrapper
from CybORG.Simulator.Scenarios.DroneSwarmScenarioGenerator import DroneSwarmScenarioGenerator
```

Create a CybORG environment with:
```python
sg = DroneSwarmScenarioGenerator()
cyborg = CybORG(sg, 'sim')
```

 


To create an environment where the red agent has preexisting knowledge of the network and attempts to beeline to the Operational Server use:

 

```python
red_agent = B_lineAgent()
cyborg = CybORG(sg, 'sim', agents={'Red': red_agent})
```
To create an environment where the red agent meanders through the network and attempts to take control of all hosts in the network use:

 

```python
red_agent = RedMeanderAgent(
cyborg = CybORG(sg, 'sim', agents={'Red': red_agent})
```
To create an environment where the red agent always takes the sleep action use:
```python
red_agent = SleepAgent()
cyborg = CybORG(sg, 'sim', agents={'Red': red_agent})
```

 

## Wrappers

 

To alter the interface with CybORG, [wrappers](../../PycharmProjects/CybORG/CybORG/Agents/Wrappers) are avaliable.

 

* [OpenAIGymWrapper](../../PycharmProjects/CybORG/CybORG/Agents/Wrappers/OpenAIGymWrapper.py) - alters the interface to conform to the OpenAI Gym specification.
* [FixedFlatWrapper](../../PycharmProjects/CybORG/CybORG/Agents/Wrappers/FixedFlatWrapper.py) - converts the observation from a dictionary format into a fixed size 1-dimensional vector of floats
* [EnumActionWrapper](../../PycharmProjects/CybORG/CybORG/Agents/Wrappers/EnumActionWrapper.py) - converts the action space into a single integer
* [IntListToActionWrapper](../../PycharmProjects/CybORG/CybORG/Agents/Wrappers/IntListToAction.py) - converts the action classes and parameters into a list of integers
* [BlueTableWrapper](../../PycharmProjects/CybORG/CybORG/Agents/Wrappers/BlueTableWrapper.py) - aggregates information from observations and converts into a 1-dimensional vector of integers
* [PettingZooParallelWrapper](../../PycharmProjects/CybORG/CybORG/Agents/Wrappers/PettingZooParallelWrapper.py) - alters the interface to conform to the PettingZoo Parallel specification
    * [ActionsCommsPettingZooParallelWrapper](../../PycharmProjects/CybORG/CybORG/Agents/Wrappers/CommsPettingZooParallelWrapper.py) - Extends the PettingZoo Parallel interface to automatically communicate what action an agent performed to other agents
    * [ObsCommsPettingZooParallelWrapper](../../PycharmProjects/CybORG/CybORG/Agents/Wrappers/CommsPettingZooParallelWrapper.py) - Extends the PettingZoo Parallel interface to automatically communicate elements of an agent's observation to other agents
    * [AgentCommsPettingZooParallelWrapper](../../PycharmProjects/CybORG/CybORG/Agents/Wrappers/CommsPettingZooParallelWrapper.py) - Extends the PettingZoo Parallel interface to allow agents to select what message they want to broadcast to other agents as part of the agent's action space

## How to Use

### OpenAI Gym Wrapper

The OpenAI Gym Wrapper allows interaction with a single external agent. The name of that external agent must be specified at the creation of the OpenAI Gym Wrapper.

```python
sg = DroneSwarmScenarioGenerator()
cyborg = CybORG(sg, 'sim')
agent_name = 'blue_agent_0'
open_ai_wrapped_cyborg = OpenAIGymWrapper(cyborg, agent_name)
observation, reward, done, info = open_ai_wrapped_cyborg.step(0)
```

### PettingZoo Parallel Wrapper

The PettingZoo Parallel Wrapper allows multiple agents to interact with the environment simultaneously.

```python
sg = DroneSwarmScenarioGenerator()
cyborg = CybORG(sg, 'sim')
open_ai_wrapped_cyborg = PettingZooParallelWrapper(cyborg)
observations, rewards, dones, infos = open_ai_wrapped_cyborg.step({'blue_agent_0': 0, 'blue_agent_1': 0})
```

### Ray/RLLib wrapper  
```python
# TODO
```
 


## Evaluating agent performance

 

To evaluate an agent's performance please use the [evaluation script](CybORG/Evaluation/evaluation.py). 

 


The wrap function on line 19 defines what wrappers will be used during evaluation
```
def wrap(env):
    return OpenAIGymWrapper(agent_name, EnumActionWrapper(FixedFlatWrapper(env)))
```
The agent under evaluation is defined on line 35. 
To evaluate an agent, extend the [BaseAgent](../../PycharmProjects/CybORG/CybORG/Agents/SimpleAgents/BaseAgent.py). 
We have included the [BlueLoadAgent](../../PycharmProjects/CybORG/CybORG/Agents/SimpleAgents/BlueLoadAgent.py) as an example of an agent that uses the stable_baselines3 library.
```
# Change this line to load your agent
agent = BlueLoadAgent()
```

## Additional Readings
For further guidance on the CybORG environment please refer to the [tutorial notebook series.](../../PycharmProjects/CybORG/CybORG/Tutorial)

## Citing this project
```
@misc{cage_cyborg_2022, 
  Title = {Cyber Operations Research Gym}, 
  Note = {Created by Maxwell Standen, David Bowman, Son Hoang, Toby Richer, Martin Lucas, Richard Van Tassel, Phillip Vu, Mitchell Kiely, KC C., Natalie Konschnik, Joshua Collyer}, 
  Publisher = {GitHub}, 
  Howpublished = {\url{https://github.com/cage-challenge/CybORG}}, 
  Year = {2022} 
}
```

## DSTG Development team 

* **David Bowman** - david.bowman@dst.defence.gov.au
* **Martin Lucas** - martin.lucas@dst.defence.gov.au
* **Toby Richer** - toby.richer@dst.defence.gov.au
* **Maxwell Standen** - max.standen@dst.defence.gov.au

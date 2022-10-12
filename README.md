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
from CybORG.Agents.Wrappers import OpenAIGymWrapper, FixedFlatWrapper
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
red_agent = RedMeanderAgent()
cyborg = CybORG(sg, 'sim', agents={'Red': red_agent})
```
To create an environment where the red agent always takes the sleep action use:
```python
red_agent = SleepAgent()
cyborg = CybORG(sg, 'sim', agents={'Red': red_agent})
```

 

## Wrappers

 

To alter the interface with CybORG, [wrappers](CybORG/Agents/Wrappers) are avaliable.

 

* [OpenAIGymWrapper](CybORG/Agents/Wrappers/OpenAIGymWrapper.py) - alters the interface to conform to the OpenAI Gym specification.
* [FixedFlatWrapper](CybORG/Agents/Wrappers/FixedFlatWrapper.py) - converts the observation from a dictionary format into a fixed size 1-dimensional vector of floats
* [EnumActionWrapper](CybORG/Agents/Wrappers/EnumActionWrapper.py) - converts the action space into a single integer
* [IntListToActionWrapper](CybORG/Agents/Wrappers/IntListToAction.py) - converts the action classes and parameters into a list of integers
* [BlueTableWrapper](CybORG/Agents/Wrappers/BlueTableWrapper.py) - aggregates information from observations and converts into a 1-dimensional vector of integers
* [PettingZooParallelWrapper](CybORG/Agents/Wrappers/PettingZooParallelWrapper.py) - alters the interface to conform to the PettingZoo Parallel specification
    * [ActionsCommsPettingZooParallelWrapper](CybORG/Agents/Wrappers/CommsPettingZooParallelWrapper.py) - Extends the PettingZoo Parallel interface to automatically communicate what action an agent performed to other agents
    * [ObsCommsPettingZooParallelWrapper](CybORG/Agents/Wrappers/CommsPettingZooParallelWrapper.py) - Extends the PettingZoo Parallel interface to automatically communicate elements of an agent's observation to other agents
    * [AgentCommsPettingZooParallelWrapper](CybORG/Agents/Wrappers/CommsPettingZooParallelWrapper.py) - Extends the PettingZoo Parallel interface to allow agents to select what message they want to broadcast to other agents as part of the agent's action space

## How to Use

### OpenAI Gym Wrapper

The OpenAI Gym Wrapper allows interaction with a single external agent. The name of that external agent must be specified at the creation of the OpenAI Gym Wrapper.

```python
sg = DroneSwarmScenarioGenerator()
cyborg = CybORG(sg, 'sim')
agent_name = 'blue_agent_0'
open_ai_wrapped_cyborg = OpenAIGymWrapper(agent_name=agent_name, env=FixedFlatWrapper(cyborg))
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
    return PettingZooParallelWrapper(env=env)
```
The agent under evaluation is defined on line 35. 
To evaluate an agent, extend the [BaseAgent](CybORG/Agents/SimpleAgents/BaseAgent.py). 
We have included the [BlueLoadAgent](CybORG/Agents/SimpleAgents/BlueLoadAgent.py) as an example of an agent that uses the stable_baselines3 library.
```
# Change this line to load your agent
agent = BlueLoadAgent()
```

## Additional Readings
For further guidance on the CybORG environment please refer to the [tutorial notebook series.](CybORG/Tutorial)

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


# Copyright DST Group. Licensed under the MIT license.

# Cyber Operations Research Gym (CybORG)

A cyber security research environment for training and development of security human and autonomous agents. Contains a common interface for both emulated, using cloud based virtual machines, and simulated network environments.

## Installation

Install CybORG locally using pip

```
# from the cage-challenge-1/CybORG directory
pip install -e .
```


## Creating the environment
Create a CybORG environment with:
```
from CybORG import CybORG
path = str(inspect.getfile(CybORG))
path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
cyborg = CybORG(path, 'sim')
```

 


To create an environment where the red agent has preexisting knowledge of the network and attempts to beeline to the Operational Server use:

 

```
agent = B_lineAgent
cyborg = CybORG(path, 'sim', agents={'Red': red_agent})
```
To create an environment where the red agent meanders through the network and attempts to take control of all hosts in the network use:

 

```
agent = RedMeanderAgent
cyborg = CybORG(path, 'sim', agents={'Red': red_agent})
```
To create an environment where the red agent always takes the sleep action use:
```
agent = SleepAgent
cyborg = CybORG(path, 'sim', agents={'Red': red_agent})
```

 

## Wrappers

 

To alter the interface with CybORG, [wrappers](CybORG/Agents/Wrappers) are avaliable.

 

* [OpenAIGymWrapper](CybORG/Agents/Wrappers/OpenAIGymWrapper.py) - alters the interface to conform to the OpenAI Gym specification.
* [FixedFlatWrapper](CybORG/Agents/Wrappers/FixedFlatWrapper.py) - converts the observation from a dictionary format into a fixed size 1-dimensional vector of floats
* [EnumActionWrapper](CybORG/Agents/Wrappers/EnumActionWrapper.py) - converts the action space into a single integer
* [IntListToActionWrapper](CybORG/Agents/Wrappers/IntListToAction.py) - converts the action classes and parameters into a list of integers
* [ReduceActionSpaceWrapper](CybORG/Agents/Wrappers/ReduceActionSpaceWrapper.py) - removes parameters from the action space that are unused by any of the action classes
* [BlueTableWrapper](CybORG/Agents/Wrappers/BlueTableWrapper.py) - aggregates information from observations and converts into a 1-dimensional vector of integers

 


## Evaluating agent performance

 

To evaluate an agent's performance please use the [evaluation script](CybORG/Evaluation/evaluation.py). 

 


The wrap function on line 19 defines what wrappers will be used during evaluation
```
def wrap(env):
    return OpenAIGymWrapper(agent_name, EnumActionWrapper(FixedFlatWrapper(ReduceActionSpaceWrapper(env))))
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
@misc{cage_challenge_1,
  Title = {Cyber Autonomy Gym for Experimentation Challenge 1},
  Note = {Created by Maxwell Standen, David Bowman, Son Hoang, Toby Richer, Martin Lucas, Richard Van Tassel},
  Publisher = {GitHub},
  Howpublished = {\url{https://github.com/cage-challenge/cage-challenge-1}},
  Year = {2021},
}
```

## DSTG Development team 

* **David Bowman** - david.bowman@dst.defence.gov.au
* **Martin Lucas** - martin.lucas@dst.defence.gov.au
* **Toby Richer** - toby.richer@dst.defence.gov.au
* **Maxwell Standen** - max.standen@dst.defence.gov.au

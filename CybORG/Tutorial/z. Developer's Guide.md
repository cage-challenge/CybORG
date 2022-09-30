# Cyborg Developer's Guide
Version 2.0.0

## Installation Instructions
We recommend using a virtual environment running python 3.8 or later. The code below has been tested using an Anaconda virtual environment running python 3.8.11.

Clone the repo using git.
```
git clone https://github.com/cage-challenge/cage-challenge-1.git
```

Install using pip.

```
pip install -e cage-challenge-1/CybORG
```

Confirm system is installed correctly by running tests.
```
 pytest cage-challenge-1/CybORG/CybORG/Tests/test_sim
```

## CybORG in Context
CybORG is a platform designed to assist with the research and development of autonomous network defenders. It allows for the simulation of several cybersecurity scenarios in which an autonomous adversary attempts to compromise a network, while an autonomous network defender tries to stop them.

Our system is designed to train agents via reinforcement learning. This paradigm sees an agent learn by interacting with an environment and receiving feedback on it's actions. Over time, the agent (hopefully) learns which actions are 'good' and which actions are 'bad' in any given context.

One of the most popular environments for reinforcement learning is OpenAI Gym. This is a collection of environments which all share a common API. CybORG models it's API off OpenAI gym, with some small modifications.

The following code shows how an agent typically interacts with CybORG:

```
import inspect
from CybORG import CybORG
from CybORG.Agents import B_lineAgent

path = str(inspect.getfile(CybORG))
path = path[:-10] + '/Shared/Scenarios/Scenario2.yaml'
cyborg = CybORG(path)

results = env.reset(agent='Red')
agent = B_lineAgent()

for step in range(30):
    action = agent.get_action(results.observation,results.action_space)
    results = cyborg.step(action=action, agent='Red')
    print(results.reward) 

```

In the above code, we instantiate the CybORG class by specifying the path to the desired scenario file. We then call the reset method, which instantiates the scenario and provides the initial data for the agent bundled into a custom Results object. For demonstration purposes we are using a pre-made attacking agent, commonly known as 'red-team' in a cybersecurity context. The agent parameter 'Red' in the reset method thus means we want the initial observation for the red team. We then instantiate the agent class. Some agents require input from the initial results object, so this data could be passed into the agent constructor here.

The scenario begins inside the for-loop, where we have decided it will run for 30 steps. For every step, we get an action from the agent and pass that into CybORG via the step method. Again we need to specify that it is red team who is taking the action. We then get a new results object, which will be passed to the agent in the next iteration of the loop. Just for demonstration purposes, we print the reward attribute of the results object. This number is what is used as feedback for the agent, although it isn't being used here.

# Overview
## The CybORG Class
The CybORG class that we imported in the previous example is defined in the main CybORG directory in the CybORG.py file. The function of this class is to provide an external facing api as well as instantiate the environment controller, which does all of the real work.

CybORG is designed to allow for both simulation and emulation environments under the hood, so one one hand this class acts as a factory choosing which type of environmental controller to instantiate. This is determined by the environment parameter in the class constructor, which defaults to simulation. This guide will focus on the CybORG simulator only, so we will assume the default parameter here always applies.

The key API methods are those called in our example: step and reset. Everything else is some sort of debugging tool to help the researcher see the internal state of the network. Both types of methods delegate everything to the environment controller.

## The Simulation Controller
Because we are assuming we are in simulation mode, the environment controller we want is the SimulationController class found in Simulation/SimulationController.py. However, this class also inherits functionality from the EnvironmentController in Shared/EnvironmentController.py. The SimulationController's main purpose is to manage the internal state as well as the various internal and external agents.

The SimulationController is instantiated by the CybORG class constructor. It passes the scenario file path to the SimulationController class constructor, which parses the file and instantiates a State object to represent the current state of the simulated network. The class constructor also instantiates the internal agents, which are given their own AgentInterface objects. This part of the code is inherited from the Environment Controller.

The two crucial methods, reset and step, are also mostly inherited from the EnvironmentController. The reset method returns the State object and internal Agents to their initial configuration before sending the initial results object to the CybORG class to give to the external agent.

Meanwhile, the workhorse of this class is the step method, which is passed the action provided by the external agent from the CybORG class. The method iterates over each of the agents defined by the scenario (usually Red, Blue and Green). If the agent's action has been provided externally the action is checked to make sure it is valid before it is executed. If the agent's action has not been provided externally, the internal agent is queried instead to provide its action and this is checked and executed instead.

The executed action returns an Observation object, which shall help the agent work out how to next make it's next decision. The Blue agent then executes a special Monitor action to update its observation so it can see what the other agents have been up to. The method then checks to see if the scenario is finished (the done signal), before computing the reward for each agent, which shall be used to evaluate how well each agent is performing. This data is bundled into a results object and returned to the user.

## Scenario Files
The scenario files are found in the Shared/Scenarios folder. Each Scenario file is a .yaml file specifying the network layout and details about the agents in the scenario.

The network in a scenario is comprised of subnets and hosts. The subnet section is at the bottom of the file and specifies which hosts exist on which subnet.

The host section is the middle section of the file and specifies the type of host as well as it's relative importance. CybORG currently uses image files which contain information about the operating system and services running on each host. These are found in the Scenario/images folder. CybORG calculates an agent's reward based on which hosts are compromised and which have been impacted.

The ConfidentialityValue of a host is the punishment the blue agent will recieve if red team has root access on that host. The AvailabilityValue is the punishment blue will receive if red team has used the impact action on this host. The impact action will only work on hosts with the OTService. This is also specified in the scenario file. In Scenario 1b and Scenario 2, the only host with this service is the Operational Server.

The Simulation Controller loads the yaml file as a dictionary, before loading the relevant image files. It then converts the resulting dictionary into a custom Scenario object. The code for this is shared between the SimulationController and EnvironmentController classes.

## The State Object
The State object can be found in Shared/State.py and represents the internal state of the simulated network. This class manages hosts, subnets, ip_addresses and sessions and the interactions between them. Hosts and sessions are custom Host and Session objects, while subnets and ip_addresses are IPv4Network and IPv4Address classes from the ipaddress package in the standard library.

State is instantiated by the SimulationController which passes it a Scenario object. The State then grabs the relevant information from this object and instantiates itself.

The get_true_state method is designed to pull all of the relevant information and create an enormous dictionary which can be given to an external user. It is called by the external-facing CybORG class via the SimulationController. Several other external CybORG methods pull attributes from this class to help see what is going on. The ip_addresses, which maps hostnames to their ip addresses is particularly useful and is called by the get_ip_map method in the CybORG class.

The other methods mostly relate to modifying the underlying state. They are called by the Action objects provided by internal or external agents and executed by the SimulationController.

## The Host Class
The Host class contains all the relevant data for a host along with the relevant methods for modifying that data. It is instantiated by the State object when the scenario is loaded and can be found in Simulator/Host.py.

Hosts have an large __init__ function because they contain most of the data inside specified in the image and scenario files. This includes operating system information, interfaces, users, groups, files, processes, sessions and services. Each of these is it's own custom datatype. These are:

1. Operating System Information: spread across multiple attributes such as type, version, patch, kernel, architecture and distribution. These are custom Enums imported from Shared/Enums.py. The most important is OperatingSystemType, which differentiates between WINDOWS and LINUX.
2. Interfaces: a custom Interface object from Simulator/Interface.py
3. Users: a custom User object from Simulator/User.py
4. Groups: A custom LocalGroup object from Simulator/LocalGroup.py
5. Files: A custom File object from Simulator/File.py
6. Processes: A custom Process object from Simulator/Process.py
7. Sessions: A custom Session object from Simulator/Session.py
8. Services: A custom Service object from Simulator/Service.py

The methods in the Host class are mostly about modifying data. This is where most of the low-level work of CybORG is done as the Action objects call these methods, usually through the State object. An exception to this is the get_ephemeral port method, which generates a random port, which is particularly important when a new session is created. This is usually due to red activity, where an exploit creates a new shell, which needs to listen on a new port.

## Agent Interfaces
Each agent in the scenario is given it's own AgentInterface object. This stores the agent's personal RewardCalculator as well as the agent itself if the agent is internal. It is instantiated by the SimulationController via inheritance from the EnvironmentController. The class can be found in Shared/AgentInterface.py and is instantiated by the SimulationController and receives agents passed into the CybORG class constructor. If no agent is passed in this way, the agent will default to the SleepAgent, which always returns the Sleep Action.

The AgentInterface is responsible for managing each internal agent's interactions with the SimulationController. This includes passing through data, training the agent and resetting the agent. Additionally, all agents have a RewardCalculator object to assist with training, and it is stored here.

By far the most important method in this class is get_action, which is called by the SimulationController step method and is passed an Observation and ActionSpace, before returning an Action obtained from the agent.

The other methods are relatively straightforward, but of particular note is create_reward_calculator, a factory method which selects a class that calculates an agent's reward.

## Reward Calculator
The Reward calculator's job is to evaluate an agent's performance by querying the State object and returning an integer reward, which is passed to the agent via the AgentInterface.

There are various reward calculators all found in the Shared folder. All reward calculators inherit from BaselineRewardCalculator in the BaselineRewardCalculator.py file. They are instantiated by the Agent Interface 

The only method of note in here is calculate_reward, which is passed the State object to query.

## Results
The results object is instantiated at the end of the step method in the SimulationController class, via inheritence from EnvironmentController. It can be found in Shared/Results.py

The results object stores data to return to the agent. If the agent is intern
The important attributes are:

1. observation: The observation dictionary returned from the just-executed action that the agent will use to make it's next decision.
2. reward: A floating point number used to reward the agent. It is the sum of the output of the agent's reward calculator and the cost of the previous action.
3. done: Boolean value representing whether the scenario is finished. Currently will always be set to False.
4. action_space: ActionSpace object containing which parts of the action space are valid to use and which are not.

## Data Flow
To illustrate how the aforementioned classes all work together, we will walkthrough the example code from the top of the document.
### CybORG Instantiation
From above, we instantiated CybORG by passing in a scenario path:

```
path = str(inspect.getfile(CybORG))
path = path[:-10] + '/Shared/Scenarios/Scenario2.yaml'
cyborg = CybORG(path)
```

We now know that CybORG passes the scenario path to the SimulationController, which reads the scenario file which creates a Scenario object via functionality inherited from the EnvironmentController. The Scenario object is used to create the internal State object, which instantiates Host objects among other things.

The SimulationController also creates AgentInterfaces for each Agent in the scenario. In this example, we haven't passed any agents into CyBORG, so the internal agents will all be Sleep. We could pass in B_lineAgent via:

```
cyborg = CybORG(path, agents={'Red': B_lineAgent})
```

### CybORG Reset
The reset method resets the internal state of CybORG and is always called at the beginning of each episode. We called it above as follows:

```
results = env.reset(agent='Red')
```

Here the command is passed though to the SimulationController to the State object, which resets itself to the initial state, partly by passing the command down to the Host objects. The SimulationController also passes this command to the AgentInterfaces, which have all the internal agents perform their own reset procedures.

The SimulationController has the initial observation for each agent stored in a dictionary and passes this to each internal agent via the AgentInterface. It also returns the initial observation for the external agent. Note that above we chose to return the red observation by passing 'Red' into the reset method explicitly. Although this parameter is optional, no observation will be returned by default.

### CybORG Step
Above we called the step function as follows:

```
results = cyborg.step(action=action, agent='Red')
```

This action is passed straight to the SimulationController, which iterates through each Agent Interface and pulls out each internal agent's action. The agent matching that specified in the step method will have its internal action replaced by the external action. The actions are checked for validity before being executed.

We will go into detail as to how actions work in the next section, but they are passed the State object and manipulate that object directly. These manipulations will usually have instructions passed down to individual Host classes. The action then returns an Observation object to be passed back to the respective agent.

Once all actions have been executed, a special action, Monitor, is executed so that the Blue agent has the most up-to-date information about Red agent's activity. The AgentInterfaces are iterated over again and each agent's corresponding RewardCalculator is queried to give each Agent its reward. The results object is then created, bundling the observation, reward and other info together to return to each agent. These are passed to each internal agent via the AgentInterface and returned to the external agent.

# Actions
## Types of Actions
Apart from the two 'basic' actions discussed above, CybORG actions tend to be divided into two main types of action: Concrete and Abstract.

The most important of these are Concrete actions, which simulate the action of specific real-world tools and commands. For example, there are actions here representing ping sweeps, port scans, service exploits and techniques for privilege escalation. Concrete actions all inherit from ConcreteAction in ConcreteActions/ConcreteActions.

Abstract actions allow the AI to focus on higher concepts without worrying about details. For example ExploitRemoteService uses some rudimentary reasoning to work out which services are on a host are exploitable before calling the appropriate concrete actions.

Examining the actions folder we can see a bunch of other folders but these action are mostly deprecated.
## Basic Actions
Actions are one of the most important parts of the CybORG system as they the mechanism by which agents interact with the system. The actions are found in the Shared/Actions folder. This is subdivided into many folders representing the different types of actions. All actions inherit from the abstract Action class which can be found in Actions/Action.py class.

Actions are instantiated by an agent or by a wrapper used by an agent. They are then passed into the step function in the SimulationController either by internal or external agents. Here the sim_execute method is called to perform the action's effects. This method takes in the State object and uses it's api to modify it in place. It then returns an Observation object, which is processed in the step function and bundled into the Results object as a dictionary.

The simplest action is Sleep, which can be found in the Actions/Action.py file. It takes in no parameters and does not affect the state in any way.

Another important action is InvalidAction. This action also does nothing, but punishes the agent which uses it. The purpose of InvalidAction is to replace any action that has not been properly constructed. The EnvironmentController class has the test_valid_action method which is called before the action is executed. This checks that the action and its various parameters are in the agent's action space and that that these parameters are legal for the agent to use.

For example, if red agent's exploit action used an ip-address that was not in the action space, the constructed action would not be valid and be replaced by InvalidAction before it could be executed. Similarly, if red agent's exploit action used a ip-address that was in the scenario, but had not already been discovered by red through other means, then the action would also fail because this parameter is not legal.

The astute observer will note that this second example does not mirror behaviour in a real world network, where if you did correctly blind-guess an ip-address, the exploit may very well succeed. However, the number of possible ip addresses in CybORG is far lower than any real world network and thus reinforcement agents could learn to guess hard-coded parameters based on this artificial constraint, thus eliminating the need to do any reconnaissance. We have thus made the deliberate design decision to force agents to  discover information before they can use it.


## Concrete Actions Walkthrough
### Pingsweep
The Pingsweep action found in ConcreteActions/Pingsweep.py. We can see the class constructor takes in four parameters: session, agent, target_session and subnet. Because Pingsweep is a recon action used by red team, agent should always be set to 'Red'. Meanwhile, session and target_session are technicalities that are conventionally always set to 0. The only substantial input is therefore subnet, which we can see should be an IPv4Network.

The sim_execute method begins with by instantiating the Observation class. This is a builder class that constructs the observation dictionary to be returned to the agent. It can be found in CybORG/Shared/Observation.py. The action then proceeds through a series of guard statements checking to see if the session and target session exist and are active. Failure will see the observation set to failure status and be immediately returned to the user. We then check routability rules using functionality inherited from the ConcreteAction class before finally accessing the State object, extracting the subnet ips from the user and add these interfaces to the observation and return it.

### Eternal Blue
The EternalBlue action is found in ConcreteActions/EternalBlue.py. The class constructor takes in the standard agent, session and target_session parameters, but now the subnet parameter has been replaced with an ip_address. The sim_execute method is nice and short, but only because it outsources all the work to sim_exploit method. This is inherited from the parent class ExploitAction, a subclass of ConcreteActions and can be found in ConcreteActions/ExploitAction.py.

Examining the sim_exploit method in the ExploitAction class, we see it takes in the State object to modify as well as the port and process_type, which are used for identifying the vulnerable process the exploit is targeting. The method see it begins with a series of guard statements checking for active sessions and routing. We then then search for the appropriate vulnerable process and return failure if this is not found.

The next check is to run the test_exploit_works method. This enables us to check for additional prerequisites, such as exploit versions. Returning to EternalBlue, we see this method imposes restrictions on the operating system.

Again, returning to the sim_exploit method in ExploitAction, we see if the exploit works, we perform a final check for any deceptive services, before creating the the reverse session via the __add_reverse_session method and adding the relevant connections to the observation.

### Juicy Potato
Juicy Potato is a privilege escalation action and can be found in ConcreteActions/JuicyPotato.py. It inherits from EscalateAction, which can be found in ConcreteActions/EscalateAction.py. Similar to eternal blue, this action lets the method EscalateAction.sim_escalate() do all the work.

This method is similar to the sim_exploit() method from ExploitAction. It begins with a series of guard statements checking for the usual sessions. We then check that the 'exploit' works, which for JuicyPotato simply checks the operating system is Windows. If successful, the action uses the __upgrade_session method to create the new privileged session before the observation is returned.

## Abstract Actions Walkthrough
### DiscoverRemoteSystems
This action can be found in the AbstractActions/DiscoverRemoteSystems.py file. It is extremely straightforward and simply calls the Pingsweep action described above.

### ExploitRemoteService
This action can be found in AbstractActions/ExploitRemoteService.py Unlike DiscoverRemoteSystems, it actually performs a level of abstraction. It determines which vulnerable services are  on a host by checking for open ports (which is all it needs to do in this simplified scenario). The exploits are ranked according to hard-coded preferences and there is a 75% percent chance the top one is chose, while 25% of the time one of the others is selected randomly. For debugging or agent-making purposes there is also an optional priority parameter to preference a specific action if called.

### PrivilegeEscalate
This action is similar to ExploitRemoteService in that it selects from among a collection of  specific escalate-actions to execute.

## Developing Actions
Actions are some of the most modular aspects of CybORG and are a good starting point for contributors. Here is a rough template for constructing an action.
1. Inherit from the appropriate class. Just like EternalBlue above, the action should utilise pre-existing code as much as possible.
3. Begin the sim_execute method by instantiating the Observation class. You will need this to build the observation.
4. Continue by filtering out failed conditions regarding sessions and routing.
5. Only if the action succeeds interact with the State object.

Here are some additional tips for adding exploit actions:
1. Inherit from ExploitAction
2. Add the vulnerable process to the appropriate images file.
3. Make sure the vulnerable process has the corresponding port used in the exploit.
4. Work out what you want the vulnerable process_type to be and make sure it is in or add it to the ProcessType Enum in Shared/Enums.py.
5. Use the ExploitAction.sim_exploit() method to execute the exploit. See the EternalBlue example above.
6. Overwrite the check_exploit_works method to check for additional prerequisites.

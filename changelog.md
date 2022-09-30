# CybORG Changelog
## Version 3.0
- DroneSwarm Scenario added for CAGE Challenge 3
- Scenarios are now created by a ScenarioGenerator object
- Backwards compatibility with YAML files is enabled by the FileReaderScenarioGenerator
- Parallel actions for multi-agents are supported
- PettingZoo ParallelEnv compatible wrappers are available
- Remote actions now consume bandwidth in the system and may fail if the maximum bandwidth capacity is exceeded
- evaluation.py has been updated to evaluate CAGE Challenge 3
## Version 2.1
- evaluation.py now calls agent.end_episode() at the end of an evaluation episode
## Version 2.0
- Scenario 2 added.
- New exploit actions added for red team.
- New decoy actions added for blue team.
## Version 1.2
- Misinform action added.
## Version 1.1
- Tutorials added to Tutorial folder.
- Bugfixes
## Version 1.0
- Scenarios 1 & 1b added.

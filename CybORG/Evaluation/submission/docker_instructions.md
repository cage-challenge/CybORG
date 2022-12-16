# Docker Instructions

These instructions cover how to build and run a Docker container from a Dockerfile for the purpose of evaluating agents in CybORG.

These instructions assume a basic familiarity with Docker. If you are unfamiliar with Docker, please see https://docs.docker.com/get-started/ for further information.

## Dockerfile

The Dockerfile contains a list of instructions for creating the environment required to run your agent.

```dockerfile
# Set Ubuntu and Python versions from pre-built images
FROM ubuntu:22.10
FROM python:3.7.9

# Set working directory to /cage
WORKDIR /cage

# Copy local package requirements and init script into container's /cage folder
COPY . /cage

# Install packages
RUN pip install -e .

# Example of adding additional instructions
# RUN pip install stable_baselines3

# Run evaluation script
ENTRYPOINT ["python", "/cage/CybORG/Evaluation/validation.py"]
```

We have included this [example Dockerfile](../../../Dockerfile) in the base of the repo. You can use this file as a basis when creating your submission. Edit this file as necessary to create the environment for running your agents. E.g. add additional pip install instructions, change the version of python, or change the operating system.

## Building the container

It is important that the Dockerfile is located at the base of the CybORG repository. From here you can create an image by entering the following into a terminal:

```
docker build -t {IMAGE NAME} {PATH TO THIS DIRECTORY}
```

with the arguments in brackets being entered manually.

For example, if you want to create an image named "cage", and the CybORG repository is located at "/home/username/cyborg", you would use:

```
docker build -t cage /home/username/cyborg/
```

## Running the container
After creating an image, you create a container which will automatically run the evaluation script.

To run the container, enter the following:

```
docker run {IMAGE NAME}
```

For example, using the cage image created earlier, you would use:

```
docker run cage
```

Please check that these instructions work with your Dockerfile before submitting.
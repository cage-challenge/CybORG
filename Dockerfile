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


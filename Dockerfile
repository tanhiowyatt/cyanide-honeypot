# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
# asyncssh and some other libs might require build tools or specific libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /app
COPY . .

# Make sure the bin scripts are executable
RUN chmod +x bin/*

# Set environment variable for PYTHONPATH so imports work correctly
ENV PYTHONPATH=/app/src

# Create necessary directories that might not exist or be excluded
RUN mkdir -p var/log/cyanide var/run var/quarantine

# Expose the SSH port
EXPOSE 2222
# Expose Telnet port if enabled (2223 default in config)
EXPOSE 2223

# Run main.py when the container launches
CMD ["python3", "main.py"]

# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the dependencies file to the working directory
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the content of the local src directory to the working directory
COPY app.py .

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define environment variable for the port (optional, app.py already handles this)
ENV PORT 5000

# Run app.py when the container launches
CMD ["python", "app.py"]

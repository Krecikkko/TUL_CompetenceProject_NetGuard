# Use a lightweight official Python image
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# Copy and install dependencies first to leverage Docker's cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code
COPY . .

# Run the application
CMD ["python", "main.py"]
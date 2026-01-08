FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create necessary directories and sample log file
RUN mkdir -p logs reports backups && \
    echo "2025-01-08 10:15:23 - INFO - System started" > logs/alarm.log && \
    echo "2025-01-08 10:16:45 - WARNING - High water level detected" >> logs/alarm.log && \
    echo "2025-01-08 10:17:12 - CRITICAL - Pump failure detected" >> logs/alarm.log

# Initialize and populate database
RUN python3 init_db.py

# Expose port
EXPOSE 5000

# Run application
CMD ["python", "app.py"]
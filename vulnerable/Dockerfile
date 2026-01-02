FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create necessary directories
RUN mkdir -p logs reports backups

# Initialize and populate database
RUN python3 init_db.py

# Expose port
EXPOSE 5000

# Run application
CMD ["python", "app.py"]

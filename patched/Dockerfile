FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create necessary directories
RUN mkdir -p logs reports backups firmware

# Initialize and populate database
RUN python3 init_db.py

# Expose port (different from vulnerable version)
EXPOSE 5001

# Run application
CMD ["python", "app.py"]

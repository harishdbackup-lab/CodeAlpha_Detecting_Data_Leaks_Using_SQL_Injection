FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY encryption_manager.py .
COPY capability_manager.py .
COPY sql_injection_prevention.py .

# Expose port
EXPOSE 5000

# Set environment variables
ENV ENCRYPTION_KEY=CodeAlpha_Secure_Key_Change_In_Production_2024
ENV CAPABILITY_SECRET=CodeAlpha_Capability_Secret_Change_In_Production
ENV FLASK_ENV=production
ENV FLASK_DEBUG=False

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health')"

# Run application
CMD ["python", "app.py"]

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies (needed for some python libs)
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Hosts such as Railway assign the port at runtime in $PORT; 8000 is the
# local default.
ENV PORT=8000
EXPOSE 8000

# Shell form on purpose: the exec form ["uvicorn", ..., "--port", "8000"]
# ignored $PORT, so on a host that assigns a different port the health check
# never reached the app. Railway is built from this file rather than Nixpacks
# (see railway.json): Nixpacks picks one language and checks Node before
# Python, so the root package.json (Playwright, for tests) made it build a
# Node image that has no uvicorn. `exec` lets uvicorn receive SIGTERM directly.
CMD exec uvicorn web.app:app --host 0.0.0.0 --port "${PORT:-8000}"

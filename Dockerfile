# Stage 1: Build dependencies
FROM python:3.10-slim-buster as builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Final image
FROM python:3.10-slim-buster

WORKDIR /app

# Create a non-root user
RUN useradd -m netsentinel && chown -R netsentinel:netsentinel /app
USER netsentinel

# Copy installed packages from builder
COPY --from=builder /root/.local /home/netsentinel/.local
ENV PATH=/home/netsentinel/.local/bin:$PATH

# Copy application code
COPY --chown=netsentinel:netsentinel . .

EXPOSE 8501

HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

CMD ["streamlit", "run", "dashboard/streamlit_app.py", "--server.port=8501", "--server.address=0.0.0.0"]

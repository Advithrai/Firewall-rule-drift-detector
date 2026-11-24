# Hugging Face Spaces (Docker) - also works on any Docker host.
# Python 3.13 = the version on the laptop that trained the model (set by export_artifacts.py).
FROM python:3.13-slim

RUN useradd -m -u 1000 user
USER user
ENV PATH=/home/user/.local/bin:$PATH \
    PYTHONUNBUFFERED=1
WORKDIR /home/user/app

COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=user . .

EXPOSE 7860
# One worker so uploaded reports stay in the same process; threads for concurrency
CMD [CMD gunicorn -w 1 --threads 4 --timeout 180 -b 0.0.0.0:${PORT:-7860} app:app]

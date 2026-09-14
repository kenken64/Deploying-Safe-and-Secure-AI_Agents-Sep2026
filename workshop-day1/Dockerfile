# For laptops where installing Python is a fight. Same lab, one command.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python -c "from agent import db; db.reset()"
EXPOSE 8000
# Shell form, so $PORT expands. Railway (and most PaaS) inject it; locally it
# falls back to 8000. 0.0.0.0 is required inside a container - the password
# gate in store/gate.py is what keeps a deployed lab from being wide open.
CMD ["sh", "-c", "python -m uvicorn store.app:app --host 0.0.0.0 --port ${PORT:-8000}"]

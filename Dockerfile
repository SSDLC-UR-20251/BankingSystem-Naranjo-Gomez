FROM python:3.11-alpine
WORKDIR /app
COPY . .
RUN pip install -r requeriments.txt
CMD ["python", "run.py"]
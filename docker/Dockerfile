FROM python:3.12-slim

WORKDIR /opt/vault-client-demo

COPY python ./

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT [ "python", "./main.py" ]
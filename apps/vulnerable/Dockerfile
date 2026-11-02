FROM python:3.8-slim
USER root
ADD . /app
WORKDIR /app
RUN apt-get update && apt-get install -y curl
RUN pip install -r requirements.txt
EXPOSE 8000
CMD python app.py

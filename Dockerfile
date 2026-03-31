FROM python:3

RUN pip install flask gunicorn
COPY . /application
WORKDIR /application

CMD gunicorn main:app -b 0.0.0.0:5000

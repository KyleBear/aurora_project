FROM python:3.8.10

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH /app/django_aurora/aurora_back

WORKDIR /app/django_aurora/aurora_back
COPY ./django_aurora/aurora_back/* ./

# upgrade pip #botocore 
RUN pip install --upgrade pip
RUN pip install --upgrade python-dateutil
RUN pip install -r requirements.txt

COPY . /app/

CMD ["python3", "manage.py", "runserver", "0.0.0.0:8000"]
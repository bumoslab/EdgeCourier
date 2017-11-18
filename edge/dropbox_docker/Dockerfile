FROM python:3.5
MAINTAINER Pengzhan Hao <haopengzhan@gmail.com>


RUN mkdir -p /app
WORKDIR /app

ADD requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
ADD cmp.py cmp.py
ADD main.py main.py

EXPOSE 10001
ENTRYPOINT ["python3"]
CMD ["main.py", "0", "10001"]

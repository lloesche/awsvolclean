FROM python:3-alpine
WORKDIR /
RUN apk add --no-cache dumb-init
COPY . /usr/src/awsvolclean
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN cd /usr/src/awsvolclean \
    && pip install -r requirements.txt \
    && mv volclean.py /usr/local/bin/volclean.py \
    && chmod +x /usr/local/bin/volclean.py \
    && cd / \
    && rm -rf /usr/src/awsvolclean
ENTRYPOINT ["/usr/bin/dumb-init", "--",  "volclean.py"]

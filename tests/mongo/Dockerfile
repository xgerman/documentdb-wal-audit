FROM debian:bookworm-slim
WORKDIR /test
COPY tests/mongo/requirements.txt /test/requirements.txt
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends python3 python3-pymongo=3.11.0-1+deb12u1 \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -c 'import pymongo; assert open("requirements.txt").read().strip() == "pymongo==" + pymongo.version'
COPY tests/mongo/test.py /test/test.py
ENTRYPOINT ["python3", "/test/test.py"]

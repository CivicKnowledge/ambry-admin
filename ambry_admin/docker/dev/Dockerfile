# Like the Ambry dockerfile, but this one installs several
# python packages from git hub, so you don't have to push them
# to PyPi and wait to get them installed via the requirement.txt file
FROM civicknowledge/ambry-base

MAINTAINER Eric Busboom "eric@civicknowledge.org"

ENV AMBRY_IS_REMOTE 1

RUN pip install git+https://github.com/CivicKnowledge/ambry_sources.git && \
    pip install git+https://github.com/CivicKnowledge/geoid.git

COPY . /tmp
WORKDIR /opt/ambry/
RUN cd /tmp/ambry-* && cp -r * /opt/ambry/ # The context tar file includes the version number

# The cd ambry-* parts are because we don't know what the file name is; it includes a version number
RUN python setup.py install
RUN ambry config install

# Ambry must be installed first
RUN pip install git+https://github.com/CivicKnowledge/censuslib.git

RUN pip install git+https://github.com/CivicKnowledge/ambry-admin.git

RUN ambry config installcli ambry_admin

WORKDIR /var/ambry

VOLUME /var/ambry

RUN mkdir -p /var/ambry/source

RUN mkdir /etc/ambry
RUN cp /opt/ambry/ambry/support/ambry-docker.yaml /etc/ambry/config.yaml
RUN echo 'source /usr/local/bin/ambry-aliases.sh' >> /root/.bashrc

ADD ambry-init.sh /opt/ambry/ambry-init.sh

CMD bash /opt/ambry/ambry-init.sh
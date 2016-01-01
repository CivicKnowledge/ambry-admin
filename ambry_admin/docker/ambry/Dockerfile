
FROM civicknowledge/ambry-base

MAINTAINER Eric Busboom "eric@civicknowledge.org"

ENV AMBRY_IS_REMOTE 1

COPY . /tmp
WORKDIR /opt/ambry/
RUN cd /tmp/ambry-* && cp -r * /opt/ambry/ # The context tar file includes the version number

RUN python setup.py install
RUN ambry config install

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
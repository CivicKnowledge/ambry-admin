
FROM civicknowledge/ambry-base

MAINTAINER Eric Busboom "eric@civicknowledge.com"


WORKDIR /tmp
#
# Get a late version of Sqlite, so apsw will build
RUN wget https://www.sqlite.org/2016/sqlite-autoconf-3100200.tar.gz
RUN tar -xzvf sqlite-autoconf-3100200.tar.gz
RUN cd sqlite-autoconf-3100200 && ./configure && make && make install

COPY . /tmp
WORKDIR /opt/ambry/
RUN cd /tmp/ambry-* && cp -r * /opt/ambry/ # The context tar file includes the version number

# Install pacakges for the ambry_sources extras. I don't know how to spec these
# otherwise.
RUN pip install apsw==3.8.8.2-post1 psycopg2==2.6 Fiona==1.6.1 Shapely==1.5.12

RUN python setup.py install
RUN ambry config install

RUN pip install git+https://github.com/CivicKnowledge/ambry-admin.git
RUN ambry config installcli ambry_admin

RUN pip install git+https://github.com/CivicKnowledge/ambry-ui.git
RUN ambry config installcli ambry_ui

WORKDIR /var/ambry

VOLUME /var/ambry

RUN mkdir -p /var/ambry/source
RUN mkdir -p /etc/ambry
RUN cp /opt/ambry/ambry/support/ambry-docker.yaml /etc/ambry/config.yaml
RUN echo 'source /usr/local/bin/ambry-aliases.sh' >> /root/.bashrc

ADD ambry-init.sh /opt/ambry/ambry-init.sh

CMD bash /opt/ambry/ambry-init.sh
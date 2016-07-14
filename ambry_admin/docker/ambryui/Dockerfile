
FROM civicknowledge/ambry

MAINTAINER Eric Busboom "eric@civicknowledge.com"

RUN pip install git+https://github.com/CivicKnowledge/ambry-ui.git
RUN ambry config installcli ambry_ui

# Method for setting up a service in phusion/baseimage
RUN mkdir /etc/service/ambryui
ADD run /etc/service/ambryui/run

EXPOSE 80

# Use baseimage-docker's init system.
CMD ["/sbin/my_init"]
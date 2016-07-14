
FROM civicknowledge/ambry

MAINTAINER Eric Busboom "eric@civicknowledge.com"

RUN pip install git+https://github.com/CivicKnowledge/ambry-ui.git
RUN ambry config installcli ambry_ui

EXPOSE 80


CMD ["ambry", "ui", "start", "-d", "-N", "-H", "0.0.0.0", "-p", "80"]
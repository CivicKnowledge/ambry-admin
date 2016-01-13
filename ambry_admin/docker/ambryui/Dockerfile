
FROM civicknowledge/ambry

MAINTAINER Eric Busboom "eric@civicknowledge.org"

RUN pip install git+https://github.com/CivicKnowledge/ambry-ui.git
RUN ambry config installcli ambry_ui

EXPOSE 80

CMD ["run-ambryui-gunicorn", "-H0.0.0.0", "-p80" ]
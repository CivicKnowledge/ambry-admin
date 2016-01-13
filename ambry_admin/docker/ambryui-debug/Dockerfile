
FROM civicknowledge/ambry

MAINTAINER Eric Busboom "eric@civicknowledge.org"

RUN pip install git+https://github.com/CivicKnowledge/ambry-ui.git

EXPOSE 80

# gunicorn -w 4 -b 0.0.0.0:80 ambry.ui:app
# THe --max-requests isn't really necessary, but does help with reducing number of
# idle, open connections.
CMD ["ambry", "ui", "-d", "-N", "-H", "0.0.0.0", "-p", "80"]
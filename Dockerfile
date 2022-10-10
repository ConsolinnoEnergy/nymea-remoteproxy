FROM debian:buster-slim
VOLUME [ "/config" ]
VOLUME [ "/ssl" ]
RUN apt update && apt install gnupg2 wget -y
RUN echo "deb https://packages.services.consolinno.de/debian-buster buster dev" > /etc/apt/sources.list.d/consolinno.list
RUN wget -qO - https://packages.services.consolinno.de/repo_signing.key | apt-key add - 
RUN apt update && apt install -y nymea-remoteproxy libqt5websockets5
COPY ./start-script.sh /

CMD [ "/start-script.sh" ]

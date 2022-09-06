FROM debian:buster AS builder
RUN apt update && apt install -y qt5-default libqt5websockets5-dev ncurses-dev git g++ make build-essential debhelper pkg-config
WORKDIR /nymea-remoteproxy/
COPY . .
# WORKDIR /nymea-remoteproxy/build
# RUN qmake ../
# RUN make
RUN dpkg-buildpackage -uc -us

FROM debian:stable-slim
VOLUME [ "/config" ]
VOLUME [ "/ssl" ]
WORKDIR /
COPY --from=builder /libnymea-remoteproxy_*_amd64.deb /
COPY --from=builder /nymea-remoteproxy_*_amd64.deb /
RUN apt update && apt install -y libqt5websockets5
RUN dpkg -i --force-depends *.deb
RUN rm *.deb
COPY ./start-script.sh /

CMD [ "/start-script.sh" ]

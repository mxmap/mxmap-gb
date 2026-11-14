FROM eclipse-temurin:17-jdk

ENV OPENSSL_CONF=/etc/ssl/

# Ermöglicht pip die Installation in der Systemumgebung
ENV PIP_BREAK_SYSTEM_PACKAGES=1


RUN apt-get update
RUN apt-get install -y bsdmainutils dnsutils locales unzip python3 python3-pip

# install golang
COPY --from=golang:1.21 /usr/local/go /usr/local/go
ENV GOROOT=/usr/local/go
ENV PATH=$PATH:$GOROOT/bin

# install gradle
RUN wget -q -P /tmp https://services.gradle.org/distributions/gradle-7.6.3-bin.zip
RUN unzip -q -d /opt/gradle /tmp/gradle-7.6.3-bin.zip
RUN chmod +x /opt/gradle/gradle-7.6.3/bin/gradle
RUN ln -s /opt/gradle/gradle-7.6.3/bin/gradle /usr/bin/gradle

# build gotls
WORKDIR /app/gotls
RUN go mod init module
RUN go get github.com/miekg/dns
RUN go build github.com/miekg/dns

RUN go get github.com/shuque/dane
RUN go build github.com/shuque/dane

RUN go get github.com/shuque/gotls
RUN go build github.com/shuque/gotls

RUN localedef -i en_US -f UTF-8 en_US.UTF-8


# Python-Abhängigkeiten installieren
RUN pip3 install --no-cache-dir pyleri checkdmarc dataclasses-json


# install testssl
WORKDIR /app
COPY testssl.sh/ testssl/
COPY testssl.sh/bin/openssl.Linux.x86_64 /usr/bin/openssl
RUN chmod +x /usr/bin/openssl
RUN chmod +x /app/testssl/testssl.sh

# Behebe Windows-Zeilenumbrüche (CRLF zu LF)
RUN sed -i 's/\r$//' /app/testssl/testssl.sh
RUN sed -i 's/\r$//' /app/testssl/etc/tls_data.txt

# Neue DMARC und SPF-Skriptdateien
COPY SPF_DMARC_Scripts/dmarcSyntaxCheck.py /app/SPF_DMARC_Scripts/dmarcSyntaxCheck.py
COPY SPF_DMARC_Scripts/spfTest.py /app/SPF_DMARC_Scripts/spfTest.py
RUN chmod +x /app/SPF_DMARC_Scripts/
RUN chmod +x /app/SPF_DMARC_Scripts/dmarcSyntaxCheck.py
RUN chmod +x /app/SPF_DMARC_Scripts/spfTest.py

COPY dss /usr/bin/dss
RUN chmod +x /usr/bin/dss

WORKDIR /build
COPY build.gradle.kts /build/build.gradle.kts
COPY settings.gradle.kts /build/settings.gradle.kts
RUN gradle dependencies

COPY src/ /build/src
RUN gradle installDist
RUN cp -r ./build/install/scanner/* /app/

WORKDIR /app
CMD ["./bin/scanner"]

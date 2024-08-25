#ARG APACHE_VERSION=""
#FROM httpd:${APACHE_VERSION:+${APACHE_VERSION}-}alpine
#FROM ubuntu:18.04
# Set timezone:
#RUN ln -snf /usr/share/zoneinfo/$CONTAINER_TIMEZONE /etc/localtime && echo $CONTAINER_TIMEZONE > /etc/timezone

# Install dependencies:
#RUN apt-get update && apt-get install -y tzdata
#RUN apt-get install -y apache2 
#RUN apt-get install -y apache2-utils 
#RUN apt-get clean 



# Copy apache vhost file to proxy php requests to php-fpm container
#COPY demo.apache.conf /usr/local/apache2/conf/demo.apache.conf
#COPY html/ /var/www/html/
#COPY attackgraph.conf /etc/apache2/sites-available/000-default.conf
#COPY demo.apache.conf /etc/httpd/sites-available/your_domain.conf
#COPY ports.conf /etc/apache2/conf/ports.conf
#COPY httpd.conf /usr/local/apache2/httpd.conf
#COPY httpd.conf /etc/httpd/conf/httpd.conf
#RUN echo "Include /usr/local/apache2/conf/demo.apache.conf" \
#    >> /usr/local/apache2/conf/httpd.conf

FROM ubuntu:20.04
LABEL maintainer="egidio.docile@linuxconfig.org"

COPY apache/XSB/ /home/XSB/
COPY apache/mulval/ /home/mulval/
COPY confluent/ /var/www/html/confluent/
RUN ln -snf /usr/share/zoneinfo/$CONTAINER_TIMEZONE /etc/localtime && echo $CONTAINER_TIMEZONE > /etc/timezone
RUN apt-get update && apt-get -y upgrade && apt-get -y install sudo && sudo adduser keren && su keren && apt-get -y install g++ \
   && apt-get update \
   && apt-get install -y docker.io \
   && apt-get -y install curl \
   && apt-get -y install python \
   && apt-get -y install pip \
   && pip install confluent-kafka==1.3.0 \
   && pip install kafka-python \
   && pip install owlready2 \
   && pip install rdflib \
   && apt-get -y install php-curl \
   && apt-get -y install make \
   && apt-get -y install nano \
   && apt-get -y install php7.4 \
   && apt-get -y install default-jdk \
   && apt-get -y install bison flex \
   && cd /home/XSB/build \
   && sudo chmod 777 -R * \
   && ./configure \
   && ./makexsb \
   && cd ../.. \
   && export MULVALROOT=/home/mulval \
   && export XSBHOME=/home/XSB \
   && export PATH=$PATH:$XSBHOME/bin && export PATH=$PATH:$MULVALROOT/utils && export PATH=$PATH:$MULVALROOT/bin \
   && cd /home/mulval \
   && make

RUN apt-get update && apt-get -y install apache2 \
   && cd /var/www/html && sudo chmod 777 -R * \
   && cd ../../../ && sudo chgrp -R www-data /var/www && sudo chmod -R g+w /var/www && sudo chmod g+s /var/www
ENTRYPOINT ["/usr/sbin/apachectl"]
CMD ["-D", "FOREGROUND"]
COPY apache/attackgraph.conf /etc/apache2/sites-available/000-default.conf
COPY apache/ports.conf /etc/apache2/ports.conf
#COPY envvars /etc/apache2/envvars
#COPY html/ /var/www/html/
#VOLUME /var/www/html

 

# Use the official Ubuntu image as a base
FROM ubuntu:20.04

# Prevent prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install necessary packages
COPY dashapp/ADG/ /var/www/html/ADG/
RUN ln -snf /usr/share/zoneinfo/$CONTAINER_TIMEZONE /etc/localtime && echo $CONTAINER_TIMEZONE > /etc/timezone
RUN apt-get update && apt-get -y upgrade && apt-get -y install sudo && sudo adduser keren && su keren && apt-get -y install g++ \
   && apt-get -y install curl \
   && apt-get -y install python3 \
   && apt-get -y install python3-pip \
   && pip3 install owlready2 \
   && pip3 install rdflib \
   && pip3 install matplotlib \
   && pip3 install pandas \
   && pip3 install numpy \
   && pip3 install dash \
   && pip3 install dash-core-components \
   && pip3 install scipy \
   && pip3 install gensim \
   && pip3 install pyrdf2vec \
   && pip3 install nltk \
   && pip3 install beautifulsoup4 \
   && pip3 install elasticsearch==7.13 \
   && pip3 install openpyxl \
   && pip3 install paretoset \
   && pip3 install scikit-learn \
   && pip3 install aiohttp \
   && pip3 install dash-cytoscape
EXPOSE 8050
CMD ["python3", "/var/www/html/ADG/AGD.py"]



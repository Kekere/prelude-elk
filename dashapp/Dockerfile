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
   && pip3 install owlready2==0.46 \
   && pip3 install rdflib==7.0.0 \
   && pip3 install matplotlib==3.7.5 \
   && pip3 install networkx==2.8.8 \
   && pip3 install pandas==2.0.3 \
   && pip3 install numpy==1.24.4 \
   && pip3 install dash==2.17.0 \
   && pip3 install dash_core_components==2.0.0 \
   && pip3 install dash_html_components==2.0.0 \
   && pip3 install scipy==1.13.1 \
   && pip3 install Requests==2.32.3 \
   && pip3 install scikit_learn==1.3.2 \
   && pip3 install gensim==4.3.2 \
   && pip3 install pyrdf2vec==0.2.3 \
   && pip3 install nltk==3.8.1 \
   && pip3 install spacy==3.7.5 \
   && pip3 install elasticsearch==7.13.4 \
   && pip3 install openpyxl==3.1.2 \
   && pip3 install paretoset==1.2.3 \
   && pip3 install plotly==5.22.0 \
   && pip3 install aiohttp==3.9.5 \
   && pip3 install dash_cytoscape==1.0.1 \
   && pip3 install lxml==5.2.1 \
   && pip3 install beautifulsoup4==4.12.3 \
   && python3 -m nltk.downloader punkt
EXPOSE 8050
CMD ["python3", "/var/www/html/ADG/AGD.py"]


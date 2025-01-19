# Use Ubuntu as the base image
FROM ubuntu:20.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install required system packages, including Firefox via APT
RUN apt-get update && apt-get install -y \
    xfce4 \
    xfce4-terminal \
    supervisor \
    x11vnc \
    xvfb \
    net-tools \
    curl \
    git \
    wget \
    python3 \
    python3-pip \
    python3-venv \
    firefox \
    build-essential \
    python3-dev \
    dnsutils \
    bind9 \
    bind9utils \
    netcat \
    tcpdump \
    iptables \
    network-manager \
    python3-tk \
    python3-pil \
    python3-pil.imagetk \
    curl \
    nano\
    vim \
    sudo \
    net-tools \
    iputils-ping \
    iptables \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# installing sudo
RUN apt-get update && apt-get install -y \
sudo 

# Install Python packages for DNS manipulation and GUI
RUN pip3 install --no-cache-dir \
    dnspython \
    requests \
    flask \
    scapy \
    python-whois \
    shodan \
    customtkinter \
    pandas \
    matplotlib \
    pydig

# Install noVNC
RUN mkdir -p /opt/novnc \
    && git clone https://github.com/novnc/noVNC.git /opt/novnc \
    && git clone https://github.com/novnc/websockify /opt/novnc/utils/websockify \
    && ln -s /opt/novnc/vnc.html /opt/novnc/index.html

# Create working directory for the application
RUN mkdir -p /app/dns_security
WORKDIR /app/dns_security

# Set up supervisor configuration
RUN mkdir -p /var/log/supervisor

# Create the supervisord.conf file
RUN echo '[supervisord]' > /etc/supervisor/conf.d/supervisord.conf \
    && echo 'nodaemon=true' >> /etc/supervisor/conf.d/supervisord.conf \
    && echo '' >> /etc/supervisor/conf.d/supervisord.conf \
    && echo '[program:xvfb]' >> /etc/supervisor/conf.d/supervisord.conf \
    && echo 'command=/usr/bin/Xvfb :1 -screen 0 1920x1080x24' >> /etc/supervisor/conf.d/supervisord.conf \
    && echo '' >> /etc/supervisor/conf.d/supervisord.conf \
    && echo '[program:x11vnc]' >> /etc/supervisor/conf.d/supervisord.conf \
    && echo 'command=/usr/bin/x11vnc -display :1 -xkb -forever -shared -repeat' >> /etc/supervisor/conf.d/supervisord.conf \
    && echo '' >> /etc/supervisor/conf.d/supervisord.conf \
    && echo '[program:xfce4]' >> /etc/supervisor/conf.d/supervisord.conf \
    && echo 'command=/usr/bin/startxfce4' >> /etc/supervisor/conf.d/supervisord.conf \
    && echo 'environment=DISPLAY=:1' >> /etc/supervisor/conf.d/supervisord.conf \
    && echo '' >> /etc/supervisor/conf.d/supervisord.conf \
    && echo '[program:novnc]' >> /etc/supervisor/conf.d/supervisord.conf \
    && echo 'command=/opt/novnc/utils/novnc_proxy --vnc localhost:5900 --listen 8080' >> /etc/supervisor/conf.d/supervisord.conf \
    && echo '' >> /etc/supervisor/conf.d/supervisord.conf \
    && echo '[program:dns_security]' >> /etc/supervisor/conf.d/supervisord.conf \
    && echo 'command=python3 /app/dns_security/main.py' >> /etc/supervisor/conf.d/supervisord.conf \
    && echo 'environment=DISPLAY=:1' >> /etc/supervisor/conf.d/supervisord.conf

    
# Set environment variables
ENV DISPLAY=:1

# Expose noVNC port and DNS ports
EXPOSE 8080 53/udp 53/tcp

# Add the setup script to the container
COPY dnsmasq/setup_dns.sh /root/Desktop/setup_dns.sh
RUN chmod +x /root/Desktop/setup_dns.sh

# Add the firefox telemetry disabler script to the container and run it
COPY dnsmasq/firefox_telemetry_disable.sh /root/Desktop/firefox_telemetry_disable.sh
RUN chmod +x /root/Desktop/firefox_telemetry_disable.sh


# copy app
COPY service/dns-spoof-detector.py /usr/local/bin/dns-spoof-detector.py
RUN chmod +x /usr/local/bin/dns-spoof-detector.py

#copy slert site html:
COPY alert.html /usr/local/bin/alert.html

# Copy script to run app
COPY service/run_python.sh /root/Desktop/run_python.sh


# Add necessary capabilities for DNS manipulation
CMD ["bash", "-c", "setcap 'cap_net_bind_service=+ep' /usr/sbin/named && /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf"]

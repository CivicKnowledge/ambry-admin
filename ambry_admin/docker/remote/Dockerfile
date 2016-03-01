# For SFTP remotes

# To get IP of running container: docker inspect -f "{{ .NetworkSettings.IPAddress }}" <ID>

FROM phusion/baseimage:0.9.18

EXPOSE 22

# Allow passwords
RUN sed -i "s/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/g" /etc/ssh/sshd_config

RUN useradd ambry -p $1$6LRxdhvh$swdS69bqjN0wHg93YZk0U0

# Start the SSHD service and create a server key
RUN rm -f /etc/service/sshd/down
RUN /etc/my_init.d/00_regen_ssh_host_keys.sh
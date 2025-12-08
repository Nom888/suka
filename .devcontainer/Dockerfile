FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y python3
EXPOSE 8080
CMD ["python3", "-m", "http.server", "8080"]

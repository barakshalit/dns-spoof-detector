# dns-spoof-detector

to run this tool:
1. build and run the docker container:
   ```
   docker build -t dns-security .
   docker run -d --privileged -p 8080:8080 -p 8081:8081 dns-security
   ```



3. enter the container GUI from browser:
http://localhost:8080/vnc.html

4. in the container, run the following scripts from Desktop:
 run the "setup_dns.sh" script to mock a dns spoofing attack (this will change wikipedia.org domain to 7.7.7.7 ip)
 run the tool with the "run_python.sh" script

finds bad site access:
![image](https://github.com/user-attachments/assets/64da9da0-70db-42f8-87d4-1d52f3f8c27e)

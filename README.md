# dns-spoof-detector

## Tool objective:
The DSN Spoof detector tool's main objective is to protect users from a DNS spoofing attack, in which the user’s machine local DNS was compromised and a domain name is now pointing to an IP address that leads to a malicious site made by the attacker.
This kind of attack is causing the user to visit a completely different site then the one he intended to.
By that, the user is vulnerable to several attacks and data theft that he is not aware of.


## Example run for the tool:
(Watching in full screen is reccomanded)


https://github.com/user-attachments/assets/fbe3cb32-767b-4392-b5e3-b635c54bb14b


## Prerequisite:
1. Docker: https://www.docker.com/




## How to run this tool
1. Clone the repo:
   ```
   git clone https://github.com/barakshalit/dns-spoof-detector.git
   ```

2. build and run the docker container:
   ```
   docker build -t dns-security .
   docker run -d --privileged -p 8080:8080 -p 8081:8081 dns-security
   ```

3. Open the container GUI from your browser from the following link:
http://localhost:8080/vnc.html

   **Troubleshhot**:
   - If you encountered with a black screen when opening the link (can't see the desktop) - please try to run the container on a different port (change 8080 port to something else) and change the url port accordingly to the new port aswell, and try to enter the containter again.
  
4. Inside the container, run the following scripts from Desktop:
   
    run the **setup_dns.sh** script - **this script will mock a dns spoofing attack** (this will change **amazon.com** domain to retrieve a "non-valid" ip **7.7.7.7** from the machine local DNS)
      ```
      ./setup_dns.sh
      ```
   To run the tool, click on the following app in the desktop:
   
    <img width="107" alt="image" src="https://github.com/user-attachments/assets/05bad4f2-cb4f-458d-8ba4-38f4be6e70c2" />



   Alternatively, you can run the script from the terminal by:
   
    run the tool with the "run_python.sh" script
      ```
      ./run_python.sh
      ```
      
6. The tool will now start to scan all the requests from the user's machine to the web and will validate every one of them with several trusted APIs.
7. In a case of an invalid request with potential risk for DNS spoofing attack, the tool will log the request and tag it as invalid, and will prompt an alert with instructions on how to deal with this kind of attacks:
   
   ![image](https://github.com/user-attachments/assets/2a8690f5-490b-4c62-b602-75f27ad6e8bc)


   ![image](https://github.com/user-attachments/assets/33397fa8-2324-4d15-ab8b-5424bac0a3e6)










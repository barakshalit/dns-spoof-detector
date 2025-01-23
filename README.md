# dns-spoof-detector

**Prerequisite:**
1. Docker: https://www.docker.com/




**To run this tool:**
1. build and run the docker container:
   ```
   docker build -t dns-security .
   docker run -d --privileged -p 8080:8080 -p 8081:8081 dns-security
   ```

3. Open the container GUI from browser:
http://localhost:8080/vnc.html

   **Troubleshhot**:
   - If you are encounter with a black screen (can't see the desktop) - please try to run the container on a different port (change 8080 port to something else) and also edit the url to use the new port aswell, and try to enter thr containter again.
  
4. Inside the container, run the following scripts from Desktop:
   
    run the **setup_dns.sh** script - **this script will mock a dns spoofing attack** (this will change **amazon.com** domain to retrieve ip **7.7.7.7** - not valid)
      ```
      ./setup_dns.sh
      ```
    run the tool with the "run_python.sh" script
      ```
      ./run_python.sh
      ```
      
5. The tool will now start to scan all the requests from the user machine to the web and will validate every one of them with several APIs.
6. In a case of an invalid request, the tool log this, and will prompt an alert with instructions on how to deal with this kind of attacks:
   ![image](https://github.com/user-attachments/assets/2a8690f5-490b-4c62-b602-75f27ad6e8bc)


   ![image](https://github.com/user-attachments/assets/33397fa8-2324-4d15-ab8b-5424bac0a3e6)


# Example run for the tool:
(Watching in full screen is reccomanded)

https://github.com/user-attachments/assets/dc46c121-6304-428a-bfb3-e7bd595551c1







TraceX is a monitoring software developed for enterprise companies to prevent internal threats. It collects logs that contain anything from normal OS processes to suspicious behavior.
The aim of this project is to prevent internal threats before it happens, and keep the company away from internal destruction.
The project contains 3 parts:
1. Client code: This code is to be installed on all employee devices for grabbing logs
2. Server code: This code only exists on an admin computer, collects the logs from employee's computers
3. React code: This code turns these logs into readable data, can be installed on the admin computer

The software works by collecting logs live from all employee computers, filters unnecessary logs and takes measures against internal threats.
Internal threats can include anything from system destruction to installing malware.
TraceX was designed with a database that contains malicious commands, where it reads each logs and tries to match it with the database, once a suspicious behavior was found, the client code force closes the terminal or application that caused the alert.
Then it sends a notification to the admin informing them of who did it, and how they did it.
Any disruption to the company will be recorded and sent to a specific logs section that is categorized from "All alerts" to each alert type "Unautherized access, Malware detection, Malicious commands etc..)
Trying to tamper with the client code results in a computer shutdown and email alert to admin
The software also tracks uptime and downtime for each computer on it's dashboard
A heartbeat is sent continuously (every 1 second) between the client and server to check uptime and downtime.
If a suspicious uptime is detected, an email alert will be sent to the admin.

The project is not a final work, its just a university project.

Future improvements:

Implement AI for better log customization and noise reduction

Connect the server with a database that is constantly getting updated to prevent any new internal threats

Better UI/UX design and more


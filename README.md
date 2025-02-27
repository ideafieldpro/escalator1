# Escalator1 CTF Challenge Writeup

## Problem
Help! We need someone to climb from the bottom to the top. Can you find the way?  
Escalate privileges to the root user and read the flag file in `/flag.txt`.

### Access the environment via SSH:

ssh -p 7000 ctf-41bd06030f59@ssh.dyn.mctf.i

## Challenge Description
The challenge requires escalating privileges to root user to read a protected flag file located at `/flag.txt`.

## Initial Access
We began by connecting to the target system via SSH on port 7000. This provided us with initial access as the unprivileged user "hackerman".

![Notion_Z0JoQiP1X6](https://github.com/user-attachments/assets/06e829de-75b5-47e3-96fb-c79d5a51d123)

## System Enumeration
Our first step was gathering system information to understand the environment:
- **Operating System:** Ubuntu 22.04.1 LTS (Jammy Jellyfish)
- **Kernel Version:** 5.15.0-1068-aws
![Notion_yih5Mh19xu](https://github.com/user-attachments/assets/d9071edc-6259-4974-91f8-2e181e4319d3)

## Privilege Escalation Enumeration
We systematically checked various privilege escalation vectors:

- **User Permissions:** Confirmed we were running as user "hackerman" with basic user privileges.
- **Sudo Access:** The sudo command was not available on the system.

### Find setuid binaries, which run with elevated privileges:

find / -perm -4000 2>/dev/null


#### Reasoning:
- **Objective:** Identify binaries that can execute with root privileges.
- **Approach:** Setuid binaries run with elevated privileges, regardless of who executes them. If these binaries have vulnerabilities or can be misused, they might allow privilege escalation.

#### Command Breakdown:
- `find /`: Searches the entire filesystem.
- `perm -4000`: Looks for files with the setuid permission bit set.
- `2>/dev/null`: Suppresses error messages, such as permission denied errors, by redirecting them to `/dev/null`.
  
  ![Notion_Sjdb6yZpdt](https://github.com/user-attachments/assets/a6572c89-f7c0-4f87-a9d9-42a171ec7471)

## Exploitation
We identified that the find command had SUID permissions, which means it runs with root privileges. After an initial unsuccessful attempt using `/bin/sh`, we successfully exploited this using:

/usr/bin/find . -exec /bin/bash -p \; -quit

The `-p` flag was crucial as it preserves the privileged status when spawning the shell.

![Notion_z13QXTojaQ](https://github.com/user-attachments/assets/9a8c83ec-3c18-46c4-bb9f-6fcb7b2ecb7e)

## Flag Capture
After gaining root access, we were able to read the flag file and obtain the flag:

MetaCTF{bc2536631c6d285111bf3e7ed5db2c31}

   ![Notion_Di2ND278nQ](https://github.com/user-attachments/assets/1efe81cc-94a1-4dbc-8fbb-9e7bfb7b4138)

## Key Lessons
1. Always perform systematic enumeration of privilege escalation vectors.
2. SUID binaries can be powerful privilege escalation tools when misconfigured.
3. The `-p` flag in bash is crucial for maintaining privileges when exploiting SUID binaries.


## Prevention Strategies
To prevent privilege escalation, individuals and companies can implement several strategies and best practices:

1. **Principle of Least Privilege**  
   Ensure users have only the permissions necessary to perform their jobs. Regularly review and adjust permissions based on changing roles.

2. **Regular Software Updates**  
   Keep the operating system and all applications up to date to patch known vulnerabilities that could be exploited for privilege escalation.

3. **SUID and SGID Management**  
   Audit setuid and setgid binaries regularly. Limit their use and ensure they are only assigned to trusted binaries. Remove unnecessary setuid/sgid permissions.

4. **Access Control Policies**  
   Implement strong access control policies that restrict access to sensitive resources based on the user’s role.

5. **Use of Security Tools**  
   Employ security tools such as intrusion detection systems (IDS) and endpoint protection platforms to monitor for suspicious activities.

6. **Security Audits and Penetration Testing**  
   Conduct regular security audits and penetration testing to identify vulnerabilities in the system that could lead to privilege escalation.

7. **User Education and Awareness**  
   Train employees on security best practices, including recognizing phishing attempts and understanding the importance of maintaining strong passwords.

8. **Logging and Monitoring**  
   Implement logging and monitoring solutions to track user activity, especially actions involving privilege changes or access to sensitive files.

9. **Implement Multi-Factor Authentication (MFA)**  
   Use MFA for accessing critical systems, adding an additional layer of security beyond just passwords.

10. **Incident Response Plan**  
    Develop a robust incident response plan that includes steps for addressing privilege escalation attempts, ensuring rapid containment and mitigation.

11. **Containerization and Virtualization**  
    Use containers or virtual machines to isolate applications, reducing the risk of privilege escalation across different environments.

## Conclusion
By applying these strategies and best practices, organizations can significantly reduce the risk of privilege escalation attacks and enhance their overall security posture. Regular reviews and updates are essential to adapt to evolving threats.

# Token Elevation

This code enables the SeImpersonatePrivilege, which allows the program to impersonate a logged-on user. 
It then opens the token of a target process specified by its PID and duplicates the token. 
Finally, it creates a new process with the duplicated token, effectively spawning a new process with the same privileges as the target process.

If you have local Administrator access on a host computer in an Active Directory environment, 
you can impersonate the SYSTEM privileges on that machine or assume the identity of an authorized domain user if available.

Tested on: Windows 10 and Windows 11

Usage: ```TokenElevation.exe <target_PID>```

![image](https://github.com/termanix/TokenElevation/assets/50464194/e822eee9-9325-44d5-a7fb-e3e08d14d218)

The main steps of the code are as follows:
- Check the command-line arguments to ensure a PID is provided.
- Open the current process token to adjust privileges.
- Enable the SeImpersonatePrivilege to impersonate the logged-on user.
- Open the token of the target process identified by the specified PID.
- Impersonate the logged-on user with the target process token.
- Duplicate the token to create a new token with the same privileges.
- Create a new process using the duplicated token, in this case, launching the "cmd.exe" command.
- Close the handles to release system resources.

By executing this code, you can elevate privileges and spawn a new process under the context of a target process, 
which can be useful in various scenarios, such as performing administrative tasks or debugging processes with elevated privileges.

Note: It's important to exercise caution when using privilege elevation and ensure that it is done for legitimate purposes and with appropriate permissions.

This code is designed to be used in a lawful and ethical manner. It is recommended to use it in the following usage scenarios:

1. Administration and debugging: During system administration or debugging tasks, it may be useful to elevate privileges and initiate a process with higher privileges. This may be necessary to perform tasks such as modifying system configuration, debugging, or troubleshooting.

2. Security analysis: It can be used by information security professionals or ethical hackers to detect and assess security vulnerabilities within a system. It can be helpful in identifying issues like unauthorized access or phishing attacks.

When using this code, it is important to consider the following points:

- Do not use for illegal activities: Using this code for illegal or malicious purposes is strictly prohibited. Only use it within the bounds of legal permissions and authorities.

- Responsibility and authorization: Before executing the code, ensure that your usage purposes and permissions are appropriate. Unauthorized access or unauthorized actions may result in legal consequences.

- Do not use for exploitation or attack: Do not use this code for gaining unauthorized access to systems or conducting attacks. Only use it for legitimate and ethical purposes.

By observing the legal and appropriate usage of this code, it can be used for security testing, debugging, or system administration purposes, among others.

# Most-secure-password-checker
It will check your password was hacked or not and if is it so then it will suggest password that can be remembered easily and also provide option to generate random password

# Contributors :

Backend developers :

DhairyaPatel2210 (Team leader, Confirmation of password whether hacked or not,  User credential related Password generation)

DP8801(Password Strength Checking, Python to executable conversion, Documentation and video preparation)

smit977( Random secured password generation)

Frontend developers :

DGamer007 (Software GUI, Tkinter developer)

Pns00911 (Software GUI, Tkinter developer, Software Design(using Adobe XD))


# Why use Password Checker?


=>Users get easy-to-remember, user-related and uncompromised passwords.

=>We ensure the privacy of user passwords and details.

=>Users’ details will not be sent to any server, it will be kept completely local.


# Technical Description 

The Password Checker will check your password whether it is hacked or not, without sending it to any servers. So basically, it will check your password locally. To understand the process just follow this documentation;
First of all, we will convert your password to SHA-1 encryption (160-bit encryption), Then we will extract the first 5 characters from the encryption and will send it to API. 

Now, this API will send us back the passwords which are matching to our first 5 characters, and then we will compare the rest of the characters with our SHA-1 encryption, and eventually, we will find our password encryption from the list we have received from API. We will get the number value for how many times the password has been compromised.

Now that we have got the value then we will ask the user if he/she wants to get a System-Generated password or not. And if the user wants to avail System-Generated password then he/she needs to give some information(which we don’t store) to software and software will generate a  password according to the user-provided information, and of course, the password will be easy to remember. 
Also during this process of System-Generated Password, we will create certain different patterns of passwords and will give random password from that list to user
Also, those passwords are ensured to be safe and uncompromised.

If System-Generated passwords are also compromised then we will provide a System-Generated password that is completely secure but this password will have nothing to do with the information provided by the user. And of course, we have provided a copy button for System-Generated password in case if you want to copy that password to your system Clipboard.

And There you go, with a complete Technical Description of the Password Checker.

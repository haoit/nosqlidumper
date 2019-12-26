# Nosql injection username and password enumeration script
Using this script, we can enumerate Usernames and passwords of Nosql(mongodb) injecion vulnerable web applications.
<br /><br />
Exploit Title: Nosql injection username/password enumeration.<br />
This project fixed error and update from project of Kalana Sankalpa (Anon LK) in git url : https://github.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration

# Change
- Dump correct all entry in columns
- Add multi threads to enumerate user and password
## How to run 

### Usage

```
nosqli-user-pass-enum.py [-h] [-u URL] [-up parameter] [-pp parameter] [-op parameters] [-ep parameter] [-sc character] [-m Method] [-t Threads]
```

### Example

```
python nosqli-user-pass-enum.py -u http://example.com/index.php -up username -pp password -ep username -op login:login,submit:submit
```

### Arguments

| Arguments        | Description           |
| ------------- |:-------------:|
| -h, --h      | show this help message and exit |
| -u URL      | Form submission url. Eg: http://example.com/index.php      |
| -up parameter | Parameter name of the username. Eg: username, user      |
| -pp parameter | Parameter name of the password. Eg: password, pass      |
| -op parameters | Other paramters with the values. Separate each parameter with a comma(,). <br />Eg: login:Login, submit:Submit      |
| -ep parameter | Parameter that need to enumarate. Eg: username, password      |
| -t threads |set max thread. Default: 100      |
| -m Method | Method of the form. Eg: GET/POST      |

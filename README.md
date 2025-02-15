# getcat
A lightweight and simple headless http klient for using in testing debug akin to bruno or postman

## Install
No installation required. Just download/copy src/getcat.js and require it

## Examples
### Basic usage
Create an empty file i.e myscript.js in a location where the script can reference getcat.js
```
#!/usr/bin/env node

const getcat = require('../src/getcat.js');

(async () => {
  const response = await getcat.requests.GET('http://www.google.no')
  console.log(response)
})()

```
If you want to run the script directly from commandline, allow exection i.e chmod +x ./myscript.js

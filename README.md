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

### Usage with node version > 20
If having issues with require not being available due to ESM scope when trying to include getcat.js, indicate commonJs interpretation of your script either by renaming your script file to *.cjs for commonJs, when not having a package.json file, or set package type commonjs in your package.json

Or thirdly, apply the following workaround directly in your script before requiring getcat:
```
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const getcat = require('../src/getcat.js');
```

## Tests
In order to self test getcat, do npm install and run npm test

TODO: Examples and description of tests

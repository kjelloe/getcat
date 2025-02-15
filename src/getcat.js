#!/usr/bin/env node
const process = require('process')
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const readline = require('node:readline');
// Set up configuiration handling first load file, then override with environment variables
const VERSION = '0.9.2' // getCAT version
const CONFIG = {} // In memory config object
const CONFIG_FIELDS = { ROOTCAPATH: null, NODETLSIGNORE: false, AUTHSYSTEMNAME: null, AUTHUSERNAME: null, AUTHTOKENFILE: null, AUTHTOKENSTRING: null, REQUESTAUTHURL: null, REQUESTTOKENURL: null} // Allowed config fields

// Define class variables
let tokenForSystem = null
let tokenForIdent = null
let tokenBase64 = null

// Update the derivied values from config
function updateConfigDerivedValues() {
  // Set class variables
  tokenForSystem = CONFIG['AUTHSYSTEMNAME'] // If set, system name in a session key
  tokenForIdent = CONFIG['AUTHUSERNAME'] // If set, userID in a session key
  // If TLS ignore enabled, employ TLS node workaorund
  process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = (CONFIG['NODETLSIGNORE']===true? 0 : 1 ) // Enforce or disable TLS check
  // If debugging, display config object after derivied values
  if (process.env['DEBUG']=='1' || process.env['DEBUG']=='true') { console.log(CONFIG) }
}
// Load the configuration for getcat connection
function loadConfig() {
  // Read getcat.config if it exists and use as basis
  const configFilePathIfAny = path.join(__dirname, 'getcat.config')
  let configfiledata = {}
  if (fs.existsSync(configFilePathIfAny)) { configfiledata = JSON.parse(fs.readFileSync(configFilePathIfAny, 'utf-8').toString()) }

  // Help set value that are boolean in nature
  function setValueOfType(value, valueType) {
    if (valueType!==null) {
      return (value==1 || value==true || value.toUpperCase()=='YES')
    }
    return value
  }
  // Move through allowed config fields and set values in order
  for (const key in CONFIG_FIELDS) {
    const definitionValue = CONFIG_FIELDS[key]
    const defaultValueType = (definitionValue!==null? (definitionValue==1? true : false) : null)
    CONFIG[key] = (process.env[key]? setValueOfType(process.env[key], defaultValueType) : (configfiledata[key]? setValueOfType(configfiledata[key], defaultValueType) : defaultValueType))
  }
  updateConfigDerivedValues()
}
// Now load config
loadConfig()

// Storing debugging information
let lastResponse = null
// Handle extra headers as default
const defaultHeaders = new Array()

function addDefaultHeader(key, value) {
  defaultHeaders.push({ key, value })
}
function removeDefaultHeader(key) {
  const newArray = removeDefaultHeader.filter( h => (h.key !== key))
  defaultHeaders = newArray
}

// NOTE: Disabling TLS check for all certificates to allow for self signed ones used in test.
function checkForCertificateError(errorMessage) {
  if (errorMessage && errorMessage.toString().includes('self-signed certificate in certificate chain') || errorMessage.toString().includes('SELF_SIGNED_CERT_IN_CHAIN')) {
    if (fs.existsSync(CONFIG.ROOTCAPATH)) {
      console.warn(`WARNING: Cannot run node requests due to TLS issue. Before running command again please set env: export NODE_EXTRA_CA_CERTS='${rootCertCaPath}'`)
    }
    else {
      console.warn('WARNING: Tests cannot run due to TLS issue. Please make sure env "NODE_EXTRA_CA_CERTS" points to a valid root CA')
    }
    console.warn('\tAlternatively disable TLS checking by setting env NODE_TLS_REJECT_UNAUTHORIZED to 0 or getcat CONFIG.NODETLSIGNORE to true')
  }
}

// Mimic bash style command line help
function processCommandlineArguments(processArguments) {
  // Process getcat command line arguments // First argument is node, second is script. Third onwards are positional arguments from command line
  if (processArguments[1] && processArguments[1].toLowerCase().endsWith('getcat.js')){
    const args = processArguments.slice(2)
    const firstArgument = (args[0]? args[0] : '--help') // Default
    console.log(`getCAT-${VERSION} command line input: ${firstArgument.substring(('--').length)}`)
    switch(firstArgument)  {
      case '--help':
        console.log('Quick usage: import getcat directly into your nodejs scripts to do getcat.requests.GET,POST,PUT and DELETE in quick and easy fashion')
        console.log('Valid command line options: \n--help\n--usage\n--config\n\--configsave\n--install\n--authorize')
        break;
      case '--usage':
      case '--examples':
        console.log('Examples of usage: \nconst getcat = require("./getcat.js")\nconst jsonResponseData = await getcat.requests.GET("my-url.com/mypath")')
        break;
      case '--install':
        console.log('No installation needed, just copy/clone/download from https://github.com/kjelloe/getcat/blob/main/src/getcat.js and go!')
        break;
      case '--config':
        console.log('Config will be read getcat.config first, then the same fields will be read from ENV i.e "export NODETLSIGNORE=true" will override value in config file')
        console.log('Current config:\n',CONFIG)
        const envFieldsFound = Object.keys(CONFIG_FIELDS).filter( key => process.env[key])
        console.log('The following ENVIRONMENT variables were found and their values will be applied after current config:\n', envFieldsFound.join('\n '))
        if (envFieldsFound.length==0) { console.log(' -- NONE -- ') }
        break;
      case '--save':
      case '--saveconfig':
      case '--configsave':
        const savefilepath = processArguments[1].replace('.js', '.config')
        console.log('Current config:\n', CONFIG)
        console.log('Will be saved to file: '+ savefilepath)
        getcat.file.writeJsonToFile(CONFIG, savefilepath)
        break;
      case '--auth':
      case '--authorize':
          const readUser = (args[1]? args[1].trim() : process.env.USER) // Get from command line or use linux en variable
          console.log(`getCAT will try to authorize and obtain key using "CONFIG.REQUESTTOKENURL" :`, CONFIG.REQUESTAUTHURL)
          if (!CONFIG.REQUESTAUTHURL) throw new Error(`Cannot authorize, missing "CONFIG.REQUESTTOKENURL"`)
          // Create local handler to read input of password
          const readlineHandler = readline.createInterface({
            input: process.stdin,
            output: process.stdout,
          })

          readlineHandler.question(`getCAT will send request using base64 encoded username \"${readUser}\" and password provided. Please enter now:`, readPass => {
            console.log(`\nSending authorization request...`)
            readlineHandler.close() // Input ended
            readlineHandler.history = readlineHandler.history.slice(1) // Clear history
            // NOTE: All special chars are encoded https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent
            const authHashBase64 = getcat.misc.base64Encode(unescape(encodeURIComponent(readUser)) + ':' + unescape(encodeURIComponent(readPass)))
            // DEBUG: console.log(authHashBase64)
            getcat.auth.getAuthorizeToken(authHashBase64).then( authorizeToken => {
                if (authorizeToken===false) throw new Error(`Authorization failed. Please check url, username and password`)
                if (CONFIG.AUTHTOKENSTRING) {
                  console.log(`Retrieved authorization token. Setting it to ENV variable \"AUTHTOKENSTRING\" allowing getCAT to use it for subsequent requests"`)
                  process.env['AUTHTOKENSTRING'] = authorizeToken
                }
                else if (CONFIG.AUTHTOKENFILE) {
                  console.log(`Retrieved authorization token. Writing it to file stated in ENV variable \"AUTHTOKENFILE\" allowing getCAT to use it for subsequent requests"`)
                  getcat.file.writeStringToFile(authorizeToken, CONFIG.AUTHTOKENFILE, true)
                }
                else {
                  console.log(`Retrieved authorization token. No \"AUTHTOKENFILE\" nor \"AUTHTOKENSTRING\" configured, writing key on next line:`)
                  console.log(authorizeToken)
                }
                console.log('Authorization request completed. ')
            })
          })

          // Override function to hide password entered
          readlineHandler._writeToOutput = function _writeToOutput(stringToWrite) { readlineHandler.output.write("*") } 


          // Write to file? getcat.file.writeJsonToFile(CONFIG, savefilepath)
          // Or use env ? AUTHTOKENSTRING
          break;
      default:
        console.log(`Unknown option "${firstArgument}". Try --help`)
    }
  }
}
// If needing a a handler for any uncaught exceptions:
// process.on('uncaughtException', function (globalError) { exceptionHandlerFunction(globalError) })

// Define getcat - main class
const getcat = {

  /* CONFIG methods */
  config : {
    keys : function() {
      return Object.keys(CONFIG)
    },
    values : function() {
      return Object.values(CONFIG)
    },
    get: function(key) {
      return CONFIG[key]
    },
    set: function(key, value) {
      if (Object.keys(CONFIG_FIELDS).includes(key)===false) getcat.log.warn(`config.set key provided "${key}" is not part of default CONFIG_FIELDS`)
      CONFIG[key] = value
      updateConfigDerivedValues()
    },
    reload: function() {
      loadConfig()
    }
  },
  /* REQUESTS */
  requests : {
    POST: async function(systemUrl, postJsonObject, klientId, acceptType, contentType) {
      return getcat.requests._inner.requestPostAndWaitForResponse('POST', systemUrl, postJsonObject, klientId, acceptType, contentType)
    },
    PUT: async function(systemUrl, postJsonObject, klientId, acceptType, contentType) {
      return getcat.requests._inner.requestPostAndWaitForResponse('PUT', systemUrl, postJsonObject, klientId, acceptType, contentType)
    },
    DELETE: async function(systemUrl, klientId) {
      return getcat.requests._inner.requestPostAndWaitForResponse('DELETE', systemUrl, null, klientId)
    },
    GET: async function(systemUrl, klientId, acceptType) {
      return getcat.requests._inner.requestPostAndWaitForResponse('GET', systemUrl, null, klientId, acceptType, null)
    },
    headers : {
      addDefault: function(key, value) { addDefaultHeader(key, value) },
      removeDefault: function(key) { removeDefaultHeader(key) }
    },
    // TODO: Make a lastresponse that handles concurrency better or returns status with response body
    getLastResponse: function() {
      return lastResponse
    },
    _inner : {
      requestPostAndWaitForResponse: async function(method, systemUrl, postJsonObject, klientId, acceptType, contentType) {
        const envSTokenPath = (CONFIG.AUTHTOKENSTRING? CONFIG.AUTHTOKENSTRING : CONFIG.AUTHTOKENFILE)  // if tokenstring is enabled, use it instead of file
        if (tokenBase64!==null && tokenBase64.length>0) {   // If basic auth is used, apply base64 string
          return getcat.requests._inner.requestPostAndWaitForResponseWithToken(method, tokenBase64, systemUrl, postJsonObject, klientId, acceptType, contentType)
        }
        if (envSTokenPath===false) { // If tokenfile is disabled, skip and do request
          return getcat.requests._inner.requestPostAndWaitForResponseWithToken(method, false, systemUrl, postJsonObject, klientId, acceptType, contentType)
        }
        // Proceed to using auth token file or auth string
        if (envSTokenPath==null) throw new Error(`CONFIG.AUTHTOKENFILE ${(envSTokenPath==null? 'er ikke satt. Gjøres i config eller med environment variabel f.eks export AUTHTOKENFILE="/home/m12345/.stinkytoken.key". ' : `"${envSTokenPath}" finnes ikke.`)}`)
        if (CONFIG.AUTHTOKENSTRING==null && !getcat.auth.isValidAccessToken(envSTokenPath, 24)) throw new Error(`CONFIG.AUTHTOKENFILE hentet fra "${envSTokenPath}" har gått ut og må fornyes.`)

        return getcat.auth.getAccessToken(envSTokenPath, tokenForSystem, tokenForIdent).then( (authToken) => {
          return getcat.requests._inner.requestPostAndWaitForResponseWithToken(method, authToken, systemUrl, postJsonObject, klientId, acceptType, contentType)
        })
      },
      requestPostAndWaitForResponseWithToken: async function(method, authTokenString, systemUrl, postJsonObject, klientId='getcat-'+VERSION, acceptType='application/json', contentType='application/json') {
        let options = {
          'method': method,
          'url': systemUrl,
          'headers': {
            'Klientid': klientId,
            'Korrelasjonsid': getcat.misc.uuid(), // Eksempel: 'f49fb193-4cb6-4bb8-a3da-71797eb7d6da',
            'Meldingsid': getcat.misc.uuid(), // Eksempel: 'e7f28c16-bb3b-4125-9886-d8b1de9f5201',
            'Content-Type': contentType,
            'Accept': acceptType,
            'Authorization': authTokenString
          },
          body: (typeof(postJsonObject)==='string'? postJsonObject : JSON.stringify(postJsonObject)) // Stringify only if not string
        }

        // If GET method and empty body, as it should be according to spec, remove body key
        if(method=='GET' && postJsonObject=='') {
          options = getcat.misc.removeProperty(options, 'body')
        }
        // If no auth header, remove it
        if(authTokenString===false) {
          options = getcat.misc.removeProperty(options, 'Authorization')
        }

        // If option set to null, remove it
        if (options.headers['Content-Type']==null) {
          options.headers = getcat.misc.removeProperty(options.headers, 'Content-Type')
        }

        // Legg på ekstra headers påkrevet
        defaultHeaders.forEach( ({ key, value }) => {
          options.headers[key] = value
        })

        // console.log(`----DEBUG: ${fetchUrl} | ${token} | ${bodyString} `)
        const reqStart = new Date()
        try {
          const fetchOptions = { method: options.method, headers: options.headers }
          if (options.method.toUpperCase()!=='GET') { fetchOptions.body = options.body } // Set request BODY for all methods but GET
          const response = await fetch(options.url, fetchOptions)
          lastResponse = { 'statusCode': response.status } // For assertions
          if (response.status > 299) {
            getcat.log.warn(`"${options.method} towards "${options.url}" failed with statusCode "${(response? response.status : error.status)}" failed with error`)
          }

          const reqDurationMs = getcat.datetime.getDurationMs(reqStart, new Date())
          getcat.log.timings(`(${response.status}) - durationMs : ${reqDurationMs} ms`) // TODO: Proper optional statistics for requests
          if (response.headers.get('content-type') && response.headers.get('content-type').includes('json')) { return  response.json() }
          return response.text()
        }
        catch(resError) {
          getcat.log.error(`Request failed. Error:`, resError)
          throw resError
        }
      },
      retrieveAuth: async function (fetchUrl, basicAuthBase64string) {
        // console.log(`----DEBUG: ${fetchUrl} | ${basicAuthBase64string} `)
        try {
          const response = await fetch(fetchUrl, { method: 'GET', headers: { 'Authorization' : 'Basic '+basicAuthBase64string, 'Accept' : '*/*', 'X-CSRF' : 1 } })
          if (response.status != 200) { throw new Error('Non-successful http status code:' + response.status) }
          return response.text()
        }
        catch(resError) {
          console.error('Authorize request failed: ', (resError.response.error? resError.response.error : resError))
          checkForCertificateError((resError.cause?resError.cause.code : resError))
          throw resError
        }
      },
      retrieveUrl: async function (fetchUrl, token, bodyString) {
        // console.log(`----DEBUG: ${fetchUrl} | ${token} | ${bodyString} `)
        try {
          const response = await fetch(fetchUrl, { method: "POST", body: bodyString, headers: { 'Authorization' : 'Bearer '+token, 'Content-Type' : 'application/x-www-form-urlencoded' } })
          if (response.status > 299) { throw new Error('Non-successful http status code:' + response.status) }
          return response.json()
        }
        catch(resError) {
          checkForCertificateError((resError.cause?resError.cause.code : resError))
          throw resError
        }
      }
    }
  },
  /* AUTHORIZATION */
  auth : {
    setSystemName: function(systemNameForToken=null) {
      tokenForSystem = systemNameForToken
    },
    setUserName: function(userNameForToken=null) {
      tokenForIdent = userNameForToken
    },
    setBasicAuth: function(base64hashString) {
      tokenBase64 = base64hashString
    },
    setBasicAuthLogin: function(username, pass) {
      getcat.auth.setBasicAuth(getcat.misc.base64Encode(username+':'+pass))
    },
    isValidAccessToken: function(tokenFilePath, validPeriodeHours=24) {
      if (fs.existsSync(tokenFilePath)===false) return false
      const fileStats = fs.statSync(tokenFilePath)
      const lastModifiedDateObject = (fileStats? new Date(fileStats.mtimeMs) : new Date(0) )
      const expiredTimeDataObject = getcat.datetime.addDays(lastModifiedDateObject, (validPeriodeHours/24)) // FIX: Add hours
      return getcat.datetime.firstDateIsMoreRecent(expiredTimeDataObject, new Date())
    },
    getAccessToken: async function(tokenFilePath, systemName, userIdent=null) {
      if (!tokenFilePath && CONFIG.AUTHTOKENSTRING==null) throw new Error('Missing AUTHTOKENFILE and no AUTHTOKENSTRING specified either')
      if (!systemName) throw new Error('Missing CONFIG.AUTHSYSTEMNAME. Please set using config or auth.setSystemName')
      const bearerToken = (CONFIG.AUTHTOKENSTRING!==null? CONFIG.AUTHTOKENSTRING : fs.readFileSync(path.resolve(tokenFilePath), 'utf-8'))
      const accessRequestBody = (userIdent==null? systemName : `${systemName}&${userIdent}`) // NOTE: Ref curl multiple -data parameters:
      const tokenRequestEndpoint = CONFIG['REQUESTTOKENURL']
      const resJsonBody = await getcat.requests._inner.retrieveUrl(tokenRequestEndpoint, bearerToken, accessRequestBody)
      return `${resJsonBody.token_type} ${resJsonBody.access_token}`
    },
    getAuthorizeToken: async function(basicAuthBase64string) {
      const authRequestEndpoint = CONFIG['REQUESTAUTHURL']
      let authToken = false
      try {
        authToken = await getcat.requests._inner.retrieveAuth(authRequestEndpoint, basicAuthBase64string)
      }
      catch(authFailed) {
        getcat.log.error(`Authorization request failed for url: "${authRequestEndpoint}"`)
      }
      return authToken
    }
  },
  /* DATETIME */
  datetime : {
    addMilliSeconds(dateObject, numberOfMs) {
      return new Date(dateObject.getTime() + numberOfMs)
    },
    addDays(dateObject, numberOfDays) {
      return new Date(dateObject.getTime() + (parseInt(numberOfDays, 10)*1000*3600*24))
    },
    firstDateIsMoreRecent(date1, date2) {
      if (!date1 || !date2) throw new Error('Two date arguments must be provided')
      return date1.getTime()>date2.getTime()
    },
    // Calculate the duration in ms
    getDurationMs : function(fromDate, toDate) {
      return (toDate.getTime() - fromDate.getTime())
    }
  },
  /* MISC supporting methods */
  misc : {
    uuid : function() {
      return crypto.randomUUID()
    },
    removeProperty : function(targetObject, property) {
      const { [property]: unused, ...rest } = targetObject
      return rest
    },
    base64Encode : function(str) {
      return Buffer.from(str).toString('base64')
    },
    base64Decode : function(strCoded) {
      return Buffer.from(strCoded).toString('utf8')
    }
  },
  /* FILE */
  file : {
    readFileAsJson: function(filepath) {
      return JSON.parse(getcat.file.readFileAsString(filepath))
    },
    readFileAsString: function(filepath) {
      return fs.readFileSync(filepath, 'utf-8').toString()
    },
    writeStringToFile: function(contentString, filepath, override=false) {
      return fs.writeFileSync(filepath, contentString, {encoding:'utf8',flag: (override? 'w': 'a')})
    },
    writeJsonToFile: function(jsonStringOrObject, filepath) {
      const jsonString = ((typeof(jsonStringOrObject)=='string')? jsonStringOrObject : JSON.stringify(jsonStringOrObject))
      return fs.writeFileSync(filepath, jsonString, 'utf-8')
    }
  },
  /* LOGS */
  log : {
    prettyOutput : function(someObject, objectType='json') {
      if (objectType=='map') {
        keys = [ ...someObject.keys() ]
        return `[ ${keys} ]`
      }
      // Default to json
      return JSON.stringify(someObject, null, 2)
    },
    prettyPrint : function(jsonObject, objectType='json') {
      console.log(getcat.log.prettyOutput(jsonObject, objectType))
    },
    info : function(logMessage, logObject) {
      getcat.log.withType(logMessage, 'INFO', logObject)
    },
    warn : function(logMessage, logObject) {
      getcat.log.withType(logMessage, 'WARN', logObject)
    },
    debug : function(logMessage, logObject) {
      getcat.log.withType(logMessage, 'DEBUG', logObject)
    },
    error : function(logMessage, logObject) {
      getcat.log.withType(logMessage, 'ERROR', logObject)
    },
    timings : function(logMessage, logObject) {
      getcat.log.withType(logMessage, 'TIMINGS', logObject)
    },
    withType : function(message, type, obj) {
      console.log(new Date().toISOString() + ': ' + (type!==undefined? '['+type+'] ' : '') + JSON.stringify(message).replace(/\\"/g,'"'), (obj!==undefined? obj : ''))
    }
  }
}

// Export to outside script usage
module.exports = getcat
// Enable command line argument handling
processCommandlineArguments(process.argv)
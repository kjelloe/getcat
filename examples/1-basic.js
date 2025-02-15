#!/usr/bin/env node

const getcat = require('../src/getcat.js');

(async () => {
  const response = await getcat.requests.GET('http://www.google.no')
  console.log(response)
})()

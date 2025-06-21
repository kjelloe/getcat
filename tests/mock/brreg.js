#!/usr/bin/env node
const express = require('express')
const fs = require('fs')
const app = express()
const port = 3000

function readFileToJson(filePath) {
	return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

app.get('/*', (req, res) => {
  res.json(readFileToJson('./enheter.json'))
})
app.get('/enhetsregisteret/api/underenheter*', (req, res) => {
  res.json(readFileToJson('./underenheter.json'))
})
app.get('/enhetsregisteret/api/organisasjonsformer*', (req, res) => {
  res.json(readFileToJson('./orgformer.json'))
})

app.get('/test', (req, res) => {
  res.json('{ "status": "Ok" }')
})


app.listen(port, () => console.log(`BRREG mock is listening on port ${port}`))

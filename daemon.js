#!/usr/bin/env node

import { exec } from 'child_process'
import { createServer } from 'http'
import { createHmac } from 'crypto'
import { readFileSync, writeFileSync, mkdirSync, rmSync } from 'fs'
import { cwd } from 'process'
import { join as joinPath, resolve as resolvePath } from 'path'
import copyFiles from 'recursive-copy'

import * as Static from '@flaki/node-static'


// Debugging helpers
const debug = process.env.DEBUG ? console.log.bind(console, '[DEBUG] ') : () => {}
const VERBOSE = (process.env.DEBUG === 'verbose')

console.log('Starting Dǣmon...')

// If a config file is specified, read it and merge it with process.env values
// Note that env values take precedence (config values do not override existing values in the env)
const configFile = process.argv[process.argv.length-1]
let configLoaded = false
if (configFile?.endsWith('.conf')) {
  console.log('Reading configuration from: ', configFile)

  try {
    const configs = readFileSync(configFile).toString()
    const fileConfigs = configs.split('\n')
      .filter(ln => ln.startsWith('#') === false)
      .map(c => c.match(/^(\w+)=(.*)/) ?? [])

    for (const [,k,v] of fileConfigs) {
      if (k) {
        if (process.env[k] === undefined || process.env[k] === '') {
          process.env[k] = v
          if (VERBOSE) debug(`Env from config: `, k, ` = `, v)
        }
      }
    }

    configLoaded = true
  }
  catch (e) {
    debug(`Couldn't load config file '${configFile}':`, e)
  }
}

// Double-check for a loaded configuration
if (!configLoaded && configFile !== '-') {
  console.log(`Usage: daemon (<filename>.conf|-)`)
  console.error(`Please specify a configuration file, or '-' if you would like Dǣmon to use ENV vars for configuration.`)
  process.exit(1)
}

// Various configuration options
const PORT = process.env.PORT || 9999
const HMAC_KEY = process.env.HMAC_KEY

if (!HMAC_KEY) {
  console.log('Warning! No HMAC_KEY specified, webhook authenticity checking disabled!')
} else {
  debug('HMAC secret: ', HMAC_KEY.substring(0,6)+'...')
}

// Choose a specific working dir for repo operations
const WORKDIR = process.env.WORKDIR
if (WORKDIR) {
  cwd(WORKDIR)
  debug('Switched to working dir: ', WORKDIR)
}

// Build/deploy-related defaults
const OUTDIR = process.env.OUTDIR ?? '_deploy'
const PREBUILDCMD = process.env.PREBUILDCMD ?? 'npm ci'
const BUILDCMD = process.env.BUILDCMD ?? 'npm run build'
const BUILDFILES = process.env.BUILDFILES

// Log incoming webhook bodies to the given folder (default: no logging)
const LOGSDIR = process.env.LOGSDIR

// Ensure the path for logging incoming webhook payloads exists
if (LOGSDIR) {
  mkdirSync(LOGSDIR, { recursive: true })
}

// Enables the GitHub component:
// Designate a repo and environments (branches) to operate on
const GITHUB_REPO = process.env.GITHUB_REPO ?? process.env.REPO // deprecated
const GITHUB = !!GITHUB_REPO
if (GITHUB) debug('GitHub repository: ', GITHUB_REPO)

// TODO: move this into a proper helper
const ENVS = (process.env.ENVS?.split(',') ?? [])
  .map(env => env.split(':'))
  .map(([name,port]) => (name && port ? { name: name.trim(), port: parseInt(port, 10) } : undefined))
  .filter(r => !!r)


// Enables the Strapi component:
const STRAPI = process.env.STRAPI
if (STRAPI) debug('Strapi webhook processing enabled.')

// Display environments
debug('Envs: ', ENVS.map(e => `${e.name} (:${e.port})`).join(', ') || '<none>')



// Expandable collection of signature verifiers
const sigVerifiers = []

// GitHub-style SHA-256 HMAC signatures:
// 'x-hub-signature-256': 'sha256=af09...',
sigVerifiers.push((headers, body, key) => {
  // Try finding the appropriate header
  const sig = Object.entries(headers)
    .filter(([k,v]) => k.includes('signature') && typeof v=='string' && v.startsWith('sha256='))
    .map(([,v]) => v.replace('sha256=',''))

  const sigstr = sig[0]

  // No signature found, bail without serving a verdict
  if (!sigstr) return

  // Hash the HMAC-SHA-256 of the payload
  const hmac = createHmac('sha256', key)
  hmac.update(body)
  const hmacstr = hmac.digest('hex')

  // We have found a signature so now it is either correct or not
  return sigstr === hmacstr ? sigstr : false
})

// Tries to verify the payload with any verifiers we have
// - returns true on finding a valid signature
// - returns false if found a signature but it did not match the payload
// - returns undefined when it couldn't find a verifiable signature
function checkSigs(headers, body, key) {
  for (const verif of sigVerifiers) {
    const verdict = verif(headers, body, key)
    if (verdict === false) return false
    if (verdict) return verdict
  }
}

async function handler(req, res) {
  // Parse the webhook & check signature
  const payload = await receiveWebhook(req, res)

  if (typeof payload != 'object') {
    return console.log('Error processing payload: JSON expected')
  }

  // Environment to update
  let changedEnv

  // GitHub component
  if (GITHUB) {
    // Make sure the hook is intended for this handler
    const repoName = payload.repository?.full_name
    if (repoName) {
      if (repoName !== GITHUB_REPO) {
        debug(`Not processed: untracked repository "${payload.repository?.full_name}"`)

      } else {
        // Information about the pushed ref/branch
        const pushedEnv = payload.ref?.split('/').pop()
        if (!pushedEnv) {
          debug(`Could not determine pushed env.`)

        } else {
          debug(`${pusher.name} <${payload.pusher?.email ?? 'Someone'}> pushed new commits to: ${pushedEnv} @ ${repoName}`)

          // Ensure we are supposed to handle this branch/environment
          changedEnv = ENVS.find(env => env.name == pushedEnv)

          if (!changedEnv) {
            debug(`Untracked GitHub environment "${pushedEnv}"`)
          }

          const payloadTime = payload.repository.pushed_at ?? Date.now()
          const payloadEnv = pushedEnv ?? 'unknown'
          const payloadHmac = payload._hmac ?? 'unknown'
      
          payload._filename = `${payloadTime}-github-${payloadEnv}-${payloadHmac}.json`
      
        }
      }
    }
  }

  // Strapi component
  if (STRAPI) {
    // The header will contain the environment this change is intended for
    const envName = req.headers['x-daemon-rebuild']
    
    if (envName) {
      const strapiEvent = req.headers['x-strapi-event'] ?? 'none'
      debug(`Strapi event "${strapiEvent} received for ${envName}`)

      changedEnv = ENVS.find(env => env.name == envName)

      if (!changedEnv) {
        debug(`Untracked Strapi environment "${envName}"`)
      }

      payload._filename = `${Date.now()}-strapi-${envName}_${strapiEvent}.json`
    }
  }

  // Log the payload JSON for later debugging
  if (LOGSDIR) {
    let filename = payload._filename
    if (!filename) {
      filename = `${Date.now()}-unprocessed.json`
      debug(`Warning: no component picked up "${filename}"`)
    }

    // Store headers in payload for further debugging
    payload._headers = Object.assign({}, req.headers)
    writeFileSync(joinPath(LOGSDIR, filename), JSON.stringify(payload, null, 2))  
  }

  // No further processing needed
  if (!changedEnv) {
    debug('No environment was updated.')
    return
  }

  // Pull & reload matching repository
  changedEnv._last = payload

  await updateEnv(changedEnv.name)
}

async function receiveWebhook(req, res) {
  
  const { method, url, headers } = req
  const ip = headers['x-forwarded-for'] ?? req.socket.remoteAddress ?? 'Unknown IP'
  debug(method, url, `(${ip})`)

  // Payload size
  const contentLen = parseInt(headers['content-length'], 10)
  debug('| Content-Length: ', contentLen, 'bytes')

  // Collect incoming payload
  const body = await new Promise(resolve => {
    const chunks = []

    req.on('data', c => {
      chunks.push(c)

      // Calculate total amount of data received so far
      const bodySize = chunks.reduce((total, chunk) => total+=chunk.length, 0)
      debug('| >> ', (VERBOSE ? c : c.slice(0, Math.min(100, c.length))).toString())
      debug('| >> RCV: ', bodySize, 'bytes')

      // If we got Content-Length amount of data already, move on
      if (bodySize >= contentLen) return resolve(Buffer.concat(chunks))
    })
  })

  // Payload received, close the request
  res.writeHead(200, 'OK', { 'Content-Type': 'application/json' })
  res.end(JSON.stringify({ ok: true }))

  // Save last incoming raw webhook headers and content
  if (LOGSDIR) {
    const ts = new Date().toUTCString()
    const metadata = Object.entries(headers).map(e => e.join(': ')).join('\n');
    writeFileSync(joinPath(LOGSDIR, '_last'), method+' '+ts+'\n'+metadata+'\n\n'+body.toString());
  }

  // Check payload signature and process it
  let sigCheck
  if (HMAC_KEY) {
    sigCheck = checkSigs(headers, body, HMAC_KEY)
    debug('| Signature check: ', !!sigCheck)

    if (!sigCheck) return false
  }

  // JSON payload
  if (headers['content-type'].includes('json')) {
    debug ('| Attempting parse as JSON content type...')

    let json

    try {
      json = JSON.parse(body)

      debug(VERBOSE ? json : '| JSON parse successful!')

      // Store the signature on the body
      json._hmac = sigCheck

      return json
    }
    catch (e) {
      debug('JSON parse failed: ', e)
    }
  }
  
  return body
}

async function setupEnv(env) {
  try {
    // Server not running
    if (!env._server) {
      const server = createServer()
      server.listen(env.port)
      env._server = server
      debug(`Server started for Env "${env.name}" on port ${env.port}`)
    }

    // Server already running, we swap out the static instance with
    // a newly created one to ensure caches etc. are cleared
    if (env._static) {
      // Remove the incoming request event listener from the server
      env._server.off('request', env._static)
      // There is no "destroy" on node-static objects so we let the GC do its job
      env._static = null
      debug(`Old static service removed`)
    }

    // Create a new instance for the static file server and attach it to our service
    // Note: this should always be true but it gets us a block scope so why not make it explicit
    if (!env._static) {
      const envPath = resolvePath(WORKDIR, OUTDIR, env.name)
      const fileServer = new Static.Server(envPath, { cache: 60, defaultExtension: "html" })

      env._static = (req, res) => fileServer.serve(req, res)
      env._server.on('request', env._static)
      debug(`Static files on :${env.port} are now served from: `, envPath)
    }

    console.log(`Service ready: ${env.name}:${env.port}`)
  }
  catch(e) {
    console.error(`Failed to create service for ${env.name}:${env.port}`, e)
    
  }
}

// TODO: locking, prevent operating simultaneously on the same environment
async function updateEnv(envName = 'preview') {
  const env = ENVS.find(e => e.name == envName)
  if (!env) {
    return console.error(`Tried to update non-existent env "${envName}"!`, envName)
  }

  if (env.locked) {
    debug(`Waiting for active build process to finish on: `+envName)
    env.again = true
    return
  }

  env.locked = true
  debug(`Updating: ${envName}`)

  // Path to the build target
  const buildTarget = joinPath(OUTDIR, envName)

  // On force push we delete the local branch and re-pull from origin
  //let cleanCommand = `git reset --hard && git clean -fxd .`
  let cleanCommand = `git clean -fxd . && git restore .`
  if (env._last?.forced) {
    const main = env._last.repository.default_branch
    cleanCommand = `git checkout ${main} && git branch -D ${envName}`
    debug('Force push detected')
  }

  // Allow embedding env-specific parameters in BUILDCMD
  const buildCommand = BUILDCMD
    .replace(/%env%/g, envName)
    .replace(/%outdir%/g, buildTarget)

  const command = [
    // Switch to working dir
    `cd "${WORKDIR}"`,
    // Clean the repo folder (build artifacts etc.)
    process.env.CLEANCMD || cleanCommand,
    // Pull in changes for the target envName
    `git fetch && git checkout -f remotes/origin/${envName} && git switch -C ${envName} && git restore .`,
    // TODO: what if the remote is not 'origin'?
    // TODO: git pull sometimes wants to do a merge, we need to catch this
    // and simply blow away the local repo if it cannot be fast-forwarded &
    // re-fetch the origin version
    // Install dependencies
    PREBUILDCMD,
    // Run build/deploy
    `OUTPUT_DIR="${buildTarget}" BUILD_ENV="${envName}" ${buildCommand}`,
  ]

  // Measure build time
  const timing = Date.now()

  try {
    // Run the commands to update the workspace
    const execResult = await new Promise((resolve, reject) => {
      const commandline = command.filter(c => !!c).join(' && ')
      const proc = exec(commandline, {},
        function (err, stdout, stderr) {
          if (err) {
            console.log(stdout)
            console.error(stderr)
            return reject(err)
          }
        
          return resolve({ stdout, stderr })
        })
        // Debugging output from process
        if (process.env.DEBUG) {
          proc.stdout.pipe(process.stdout);
          proc.stderr.pipe(process.stderr);
        }
    })

    // Show command output
    debug(`Completed in: ${((Date.now()-timing)/1000).toFixed(1)}s`)
    if (VERBOSE) {
      command.forEach(cmd => debug( '$> '+cmd ))

      debug('Command output:')
      execResult?.stdout.trim().split('\n').forEach(ln => debug('| '+ln))
    }

    // Copy the build result if we need to
    // TODO: maybe always build to tmpdir and not yank the existing files
    // until we are finished, then delete & replace the old one on success?
    if (BUILDFILES) {
      const buildSource = BUILDFILES
      debug(`Copying build artifacts: ${buildSource}`)
      rmSync(buildTarget, { force: true, recursive: true })
      const { length: copied } = await copyFiles(buildSource, buildTarget)
      debug(`→ ${buildTarget} - ${copied} files copied`)
    }
    
    // Update the service
    await setupEnv(env)
  }
  catch(e) {
    console.error(`Failed to update ${env.name}:`, e)
  }

  // Unlock env
  env.locked = false

  if (env.again) {
    env.again = false

    const DEFAULT_TIMEOUT = 10 *1000
    await new Promise(r => setTimeout(r,DEFAULT_TIMEOUT))
    // TODO: check if we have been rebuilding too often in the past ~minutes
    // and throttle the build (lots of edits in the CMS)
    // TODO: potential issue if hitting recursion limit
    debug('Resuming delayed build: '+envName)
    await updateEnv(envName)
  }
}

// Launch services for the local environments
(async () => {
  if (!ENVS.length) {
    return console.log(`No environments defined!`)
  }

  console.log(`Initializing ${ENVS.length} environments...`)

  // Note: this has to run sequentially because the git commands in the same repository
  // will interfere with each other if ran concurrently
  for (const e of ENVS) {
    await updateEnv(e.name)
  }
  
  // Launch the daemon to manage the envs
  // TODO: https://www.npmjs.com/package/es-main (matches module filename to argv[])
  if (/* no clue what's the ESM-lingo for this?? => require.main === module */ true) {
    createServer(handler).listen(PORT, (err) => {
      if (err) return console.error(err)
  
      console.log(`Webhook server listening on ${PORT}`)
    })
  
  } else {
    // please run as a server
  }
  
})().catch(e => console.error(e))

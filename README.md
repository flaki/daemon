# Dǣmon

For a hot second I really wanted to call this "Me-tlify", but I would rather not unleash the wrath of trademark rights lawyers, however it does illustrate pretty well what this tool is for.

Dǣmon lets you create self-hosted (for now, static) site deployments that react and respond to code repository changes. You can have multiple static sites deployed under various *"environments"*, which react automatically to repo changes (e.g. pushes).

Currently only GitHub webhooks supported, but anything else should be fairly easy to implement (Gitlab is on the roadmap). Well, there's no actuall roadmap, but I'm thinking about it anyway.


## Installation & use

Dǣmon requires `node.js` and `npm`. There is no need to install anything, just create a [configuration file](#configuration) and run Dǣmon with npx:

`npx @flaki/daemon <configfile.conf>`

Make sure that Dǣmon has write permissions for the working directory and all other configured paths.

Use `npx @flaki/daemon@next` for pre-release versions. You can also `npm install -g @flaki/daemon[@next]` and use daemon globally: `daemon <configfile.conf>`

Note: Dǣmon currently uses shell operations, and thus only works on Linux systems. It has been tested on Debian/Ubuntu 20.04 with bash and all necessary packages installed (git, nodejs, npm etc.).


### Configuration

The configuration file follows the `.env` file format, uppercase alphanumeric keys followed by `=` and the value, one value one row.

The following keys may be used in the configfile:

Key        | Value
-----------|----------------------
`PORT`     | Port to listen on for incoming webhooks, default: `9999`
`HMAC_KEY` | The HMAC-SHA-256 digest secret used for signing incoming webhook payloads
`WORKDIR`  | The path where the checked out git repository resides, Dǣmon will pull & run commands in this directory
`REPO`     | The repository name to operate on, needed so that Dǣmon does not get confused by noise from other webhooks referencing events in other repositories
`ENVS`     | The branches Dǣmon should handle, comma separated list of `branchname:port` values, where `port` is the port number where the generated site for this branch will be served from
`OUTDIR`   | Defaults to `$WORKDIR/_deploy/`. Dǣmon passes this and the branch in the environment variable `OUTPUT_DIR` to the build command, e.g.: `OUTPUT_DIR=$WORKDIR/_deploy/mybranch npm run build`
`BUILDCMD` | The command to execute after a successful pull, defaults to `npm run build`. The output directory and environment name are exposed to the build script as the env vars `OUTPUT_DIR` & `BUILD_ENV`. The `%outdir%` and `%env%` strings can be used to embed these values into the command itself.
`PREBUILDCMD`| The command to run after checkout to prepare the build, defaults to `npm ci`
`BUILDFILES`| When it's not possible/convenient to set the build process to output into a given directory, use `BUILDFILES` to specify where the artifacts end up and Dǣmon will copy them to the deployment location
`LOGSDIR`  | Enable logging incoming webhook payloads in the given folder, ideal for debugging and feature development (default: no logging)

Lines starting with a `#` character are ignored.

Note that all configuration file parameters can also be passed as regular ENV vars. If you need to launch Dǣmon without a configfile, you may specify a dash instead: `daemon -`. Please further note that environmental variable values take precedence and will override the config entries.


### Development

Run Dǣmon setting the `DEBUG=1` environment to get more debugging information logged into the console. You can also use `DEBUG=verbose` to get even more information/full incoming payloads logged.

It is also possible to log all incoming webhook payloads in a JSON format, see the `LOGSDIR` configuration options above.


## Q & A

### Is this Serverless™?!

Au contraire, this is Server-YES! Dǣmon runs as a Node.js application, listens to incoming webhooks, and serves the generated websites (branches) on different ports as a static server, so it requires to be run, somewhat unsurprisingly, as a [daemon](https://en.wikipedia.org/wiki/Daemon_%28computing%29).

### Only works with static sites?

Yes, albeit this might change in the future. In all practicality you can already make Dǣmon do your bidding through the configuration options, but the currently intended primary use case is static sites.

### npm keeps screaming about critical vulnerabilities

Dǣmon has (intentionally) few dependencies, `node-static` is currently the only one. I am currently waiting for a [maintainer change](https://github.com/cloudhead/node-static/issues/224) to realize, at which point these issues shall be fixed. If that doesn't happen in due time I'll look into replacing the dependency with a fork or in its entirety.

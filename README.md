# Bouncer client erlang

Erlang client for [bouncer][1] service

## Building

To build the project, run the following command:

```bash
$ make compile
```

## Running

To enter the [Erlang shell][2] with the project running, run the following command:

```bash
$ make rebar-shell
```

## Development environment

### Run in a docker container

You can run any of the tasks defined in the Makefile from inside of a docker container (defined in `Dockerfile.dev`) by prefixing the task name with `wc-`. To successfully build the dev container you need `Docker BuildKit` enabled. This can be accomplished by either installing [docker-buildx](https://docs.docker.com/buildx/working-with-buildx/) locally, or exporting the `DOCKER_BUILDKIT=1` environment variable.

#### Example

* This command will run the `compile` task in a docker container:
```bash
$ make wc-compile
```
#### Example

* This command will run the `compile` task in a docker container:
```bash
$ make wc-compile
```

## Documentation

@TODO More documentation.

This library utilizes [woody][3] to provide a client for [bouncer][1] service using its [protocol][4]. Some generic helper functions are also provided in `bouncer_context_helpers` module.

[1]: https://github.com/valitydev/bouncer
[2]: http://erlang.org/doc/man/shell.html
[3]: https://github.com/valitydev/woody_erlang
[4]: https://github.com/valitydev/bouncer-proto

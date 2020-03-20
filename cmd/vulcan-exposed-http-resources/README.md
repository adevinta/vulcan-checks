## Usage

This check tests if a given web address exposes sensitive resources. The check tests a list of paths by performing an HTTP request with the GET method. There are two ways for specifying the list of resources to be tested:

1. By default it will check if the resources listed in the `resources.yaml` file are exposed.

2. If resources are specified through options, the check will instead look for those resources.

The expected format for the options is:

```
{"resources":[
	{"paths":["/one", "/two"], "status":200, "regex":"danger(ous)?", "severity":8.9},
	{"paths":["/three"], "regex":"error.*found", "description":"Exposed error file."}
]}
```

## Behaviour

For each resource to check for, a set of possible paths are specified, along with a status code and a regex to look for in the response.

- The check will test each path for any given resource and report each one that is found.

- If a status code is specified, the check will consider the resource to be exposed if the response to the request has the specified status code.

- If a regular expression is specified, the check will consider the resource to be exposed if the whole HTTP response matches the regular expression. The regular expression must follow the syntax used by the Go `regexp` package.

- If both conditions are specified, the check will consider the resource to be exposed if both of them are met.

- If no conditions are specified the check will consider the resource to be exposed if the request returns any response.

## Testing

In order to test the detection of specific resources, you may use the following method.

1. Add any resources that should be detected inside the `_testdata/www_ko/` root.
2. Add any resources that should **not** be detected inside the `_testdata/www_ok/` root.
3. Create a copy of the `local.toml.example` file.
```
cp local.toml.example local.toml
```
4. Run a web server to serve files from the desired root directory, for example:
```
go run _testdata/server.go _testdata/www_ko/ &
```
5. While the web server is running, execute the check to run locally.
```
vulcan-exposed-http-resources -t
```

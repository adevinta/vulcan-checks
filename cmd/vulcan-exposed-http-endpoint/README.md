This check tests if a given Web Address has any of given list of paths exposed.
The check tests a path performing an http request with a GET method.
There are two ways for specifying the paths:

1.  Explicitly using the options of the check:
    The expected format for the options is:
    ```
    {
    "paths":[
                 {"path":"/one", "status":200 , "resp_regex": "(?s)Transfer.*Alt"},
                 {"path":"/other","reg_exp": "found"}
              ]
     }
    ```
    So you can specify a set of paths and, for each path, a status code and a regexp.

    * If a status code is specified the check will consider the path exposed if the response of the GET request contains the specified status code.

    * If regexp is specified the check will consider the path as exposed if whole http response, including headers, matches
      the regular expression. The regexp must follow the syntax used by the go package [regexp](https://golang.org/pkg/regexp/syntax/).

    * If both conditions are specified the check will consider the path to be exposed when both of them are met.

    * If no conditions are specified the check will consider the path to be exposed if the GET request returns any HTTP response.



 2. Implicitly where no options ares provided.

    In this case the check will use an internal list of paths.
    Those lists are defined inside the _paths directory of the check as json files.
    Also a small tool in the directory vulcan-exposed-path-encoder is provided in order to transform text files
    with paths in json files with the format required by the check.

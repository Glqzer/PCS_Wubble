# Running the JMessage Server

The JMessage server is a Python Flask application. The TAs will run an instance for the whole class, but you can run a copy locally as well. To build the application, you will need python3.

## Installing the necessary packages

You will need `flask`, `sqlite3`, `passlib`, `datetime`. Install these using pip:

```bash
$ pip3 install -r requirements.txt # Recommended to use the requirement doc
$ pip3 install flask sqlite3 passlib datetime # only if you used a very old version of python.
```

## Run the server

You can run the server directly from the command line. 
PS: Please ensure that you correctly configured the pip3 path and used the matched python3 application. 

```bash
$ python3 jmessage_server.py
```

By default, the server will run on port 8080 using the Flask "Development" server. It will create a database file called 
`sqldb` and a folder called `JMESSAGE_FILES`. By default, the server will generate a self-signed certificate and use TLS.

The server has several options. You can see these by adding the `-h` flag.

* `-r`: Delete and reset the database, erasing all stored attachments.
* `-t`: Test mode, adds three dummy users.
* `-notls`: Run the server using basic HTTP with no TLS.
* `-tlscert`: Run the server using TLS with certificate `./local.crt` and key file `./local.key` (in the same directory)
* `port <port>`: Optionally specify a different server port, default is 8080.
* `dbfile <filename>`: Optionally specifies an SQLite file (default is `./sqlite`.)

## Common Issues 

> If the server outputs error information about the index error, it may be caused by that you did not register

You can first use the command to register a new user. 

```
$ go run . --reg --username alice --password abc 
```

or alternatively, you can also try to run the server with option -t​, which will register two different users: `user: alice, password: abc` and `user: bob, password: def`
```
(venv)$ python server.py -t 
```


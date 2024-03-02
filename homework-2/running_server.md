# Running the JMessage Server

The JMessage server is a Python Flask application. The TAs will run an instance for the whole class, but you can run
a copy locally as well. To build the application, you will need python3.

## Installing the necessary packages

You will need `flask`, `sqlite3`, `passlib`, `datetime`. Install these using pip:

```
pip3 install flask sqlite3 passlib datetime
```

## Run the server

You can run the server directly from the command line:

```
python3 jmessage_server.py
```

By default the server will run on port 8080 using the Flask "Development" server. It will create a database file called 
`sqldb` and a folder called `JMESSAGE_FILES`. By default the server will generate a self-signed certificate and use TLS.

The server has several options. You can see these by adding the `-h` flag.

* `-r`: Delete and reset the database, erasing all stored attachments.
* `-t`: Test mode, adds three dummy users.
* `-notls`: Run the server using basic HTTP with no TLS.
* `-tlscert`: Run the server using TLS with certificate `./local.crt` and keyfile `./local.key` (in same directory)
* `port <port>`: Optionally specify a different server port, default is 8080.
* `dbfile <filename>`: Optionally specify a SQLite file (default is `./sqlite`.)

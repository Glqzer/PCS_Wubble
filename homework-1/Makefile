# Makefile

.PHONY: all clean

all: encrypt decrypt keylength cryptanalyze

encrypt: encrypt.go
	go build -o encrypt encrypt.go

keylength: keylength.go
	go build -o keylength keylength.go

decrypt: decrypt.go
	go build -o decrypt decrypt.go

cryptanalyze: cryptanalyze.go
	go build -o cryptanalyze cryptanalyze.go

clean:
	rm -f encrypt decrypt keylength cryptanalyze
all: clean serve

.PHONY: serve
serve: www/listing.json www/db.tar.gz server.crt
	python3 serve.py


.PHONY: govulners-test-fail
govulners-test-fail: clean-dbdir dbdir
	GOVULNERS_DB_CACHE_DIR=$(shell pwd)/dbdir \
	GOVULNERS_DB_UPDATE_URL=https://$(shell hostname).local/listing.json \
		go run ../../../../main.go -vv alpine:latest

.PHONY: govulners-test-pass
govulners-test-pass: clean-dbdir dbdir
	GOVULNERS_DB_CA_CERT=$(shell pwd)/server.crt \
	GOVULNERS_DB_CACHE_DIR=$(shell pwd)/dbdir \
	GOVULNERS_DB_UPDATE_URL=https://$(shell hostname).local/listing.json \
		go run ../../../../main.go -vv alpine:latest

dbdir:
	mkdir -p dbdir

server.crt server.key:
	./generate-x509-cert-pair.sh

www:
	mkdir -p www

listing.json:
	curl -L -O https://toolbox-data.nextlinux.io/govulners/databases/listing.json

www/listing.json www/db.tar.gz: www listing.json
	$(eval location=$(shell python3 listing.py))
	curl -L -o www/db.tar.gz $(location)

.PHONY: clean
clean: clean-dbdir
	rm -rf www
	rm -f server.crt
	rm -f server.key

.PHONY: clean-dbdir
clean-dbdir:
	rm -rf dbdir/
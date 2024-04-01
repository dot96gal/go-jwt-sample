.PHONY: dev
dev:
	go run ./...

.PHONY: generate-ecdsa-key
generate-ecdsa-key:
	ssh-keygen -t ecdsa -b 256 -m PEM -f secret/id_ecdsa
	
.PHONY: generate-ecdsa-pkcs8
generate-ecdsa-pkcs8:
	openssl pkey -in secret/id_ecdsa -pubout > secret/id_ecdsa.pub.pkcs8
	
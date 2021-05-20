#!/bin/bash
mongoimport --db psidomaincheck --collection domains --file /fixtures/blinded_domains.json
mongoimport --db psidomaincheck --collection users --file /fixtures/users.json --jsonArray

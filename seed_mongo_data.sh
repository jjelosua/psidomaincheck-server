#!/bin/bash
mongoimport --db kako --collection domains --file /fixtures/blinded_domains.json
mongoimport --db kako --collection users --file /fixtures/users.json --jsonArray

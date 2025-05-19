#!/bin/bash

sudo docker compose -f postchain-single-node.yml down
sudo docker volume rm blockchain_postgres
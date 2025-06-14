#!/bin/bash

# Get the list of namespaces
namespaces=$(kubectl get ns -o jsonpath='{.items[*].metadata.name}')

for ns in $namespaces; do
    echo "Checking secrets in namespace: $ns"

    # Get the list of secrets
    secrets=$(kubectl get secrets -n $ns -o jsonpath='{.items[*].metadata.name}')
    
    for secret in $secrets; do
        echo "  - Checking secret: $secret"

        # Get secret data keys
        keys=$(kubectl get secret $secret -n $ns -o jsonpath='{.data.keys[*]}')

        for key in $keys; do
            if [[ "$key" == *".crt" ]] || [[ "$key" == *".pem" ]] || [[ "$key" == *".jks" ]]; then
                echo "    ✔ Found certificate/JKS file: $key"
            fi
        done
    done
done

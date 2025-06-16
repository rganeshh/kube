#!/bin/bash

# Get all configmaps in all namespaces
configmaps=$(kubectl get configmaps --all-namespaces -o json)

# Check each configmap's data for "testadmin"
echo "Searching for username 'testadmin' in ConfigMaps..."
echo "--------------------------------------------"

echo "$configmaps" | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name)"' | while read -r cm; do
    namespace=$(echo "$cm" | cut -d '/' -f1)
    name=$(echo "$cm" | cut -d '/' -f2)

    data=$(kubectl get configmap "$name" -n "$namespace" -o json | jq -r '.data | to_entries[] | .key + ": " + .value')

    if echo "$data" | grep -q "testadmin"; then
        echo "Found in ConfigMap: $namespace/$name"
        
        # Check for password key
        password=$(echo "$data" | grep "^password:" | cut -d ':' -f2- | xargs)
        
        if [ -n "$password" ]; then
            echo "Password found: $password"
        else
            echo "No password key found in this ConfigMap."
        fi
    fi
done

echo "Search completed."
```

### Read me
#- The script now extracts both the keys and values from each ConfigMap.
#- If `testadmin` is found, it searches for a key named `password` and prints its value if present.
#- Uses `xargs` to trim extra spaces from the extracted password.

#Make sure you handle any printed passwords securely! Want to fine-tune this further? I’m here to help.

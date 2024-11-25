# f5-bola-task

## how to run:
- run `go run main.go <access-log-file>`

## summary
To detect potentail BOLA attacks:
- first i looked for requests that have both ID and token because if both ID and token are in the request then probably a restricted resource is being accessed.
- after finding requests with both token and id, i looked if theres another request with the same ID but with a different token - this shows me that two different users are trying to access the same resource which is potentaliy a BOLA attack.
- finally if I found two requests that have the same ID and different tokens i checked if both have the same *positive* (2xx) response with the same body size. that shows me the server gave both requests the same response, which means that in case the resource is realy restricted to one specific user, then another unauthourized user was able to access it - BOLA.

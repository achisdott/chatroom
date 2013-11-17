# chatroom

Socket Programming Practice

## Usage

1. Compile server: `gcc chat_serv.c -o chat_serv`
2. Compile client: `gcc chat_cli.c -o chat_cli`
3. Server side: `./chat_serv <Port>`
4. Client side: `./chat_cli <IP> <Port>`

## Spec

1. Broadcast Message: `<Message>`
2. Private Message: `/private <Nick> <Message>`
3. Change Nickname: `/nick <Nick>`
4. Who: `/who`
5. Quit: `/quit`

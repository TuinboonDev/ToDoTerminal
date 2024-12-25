# ToDoTerminal

A CLI for interacting with a remote server to manage TODOs!

# What is this?
Its a CLI written in Rust connecting to an API written in Python. I went all out on the auth so it uses tokens to verify stuff after a user has logged in. It features todo creation, completion, deletion, and more! Some examples below!

# Getting started
Starting is as simple as a `git clone https://github.com/TuinboonDev/ToDoTerminal.git` and adding it to path.<br>
After this you can use `todoterminal <command> [arguments]` a list of commands is down <a href="#commands">here</a>.<br><br>

Encountering any issues? DM tuinboon on discord (or submit a PR!)

# Commands
`todoterminal account login | logout | create`<br>
`todoterminal 2fa <code>`<br>
`todoterminal todos complete | uncomplete | delete <id>`<br>
`todoterminal todos import <fs|git> <path|github url> [clone dest]`<br>
`todoterminal todos create "<text>"`<br>
`todoterminal todos list`<br>

# Examples/ demos
`Account Creation:`
<img src="https://github.com/TuinboonDev/ToDoTerminal/blob/main/account.gif?raw=true">

`Importing TODOs from git:`
<img src="https://github.com/TuinboonDev/ToDoTerminal/blob/main/import.gif?raw=true">

`Creating and updating TODOs:`
<img src="https://github.com/TuinboonDev/ToDoTerminal/blob/main/todos.gif?raw=true">
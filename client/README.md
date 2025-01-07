# ToDoTerminal

A CLI for interacting with a remote server to manage TODOs!

# What is this?
Its a CLI written in Rust connecting to an API written in Python. I went all out on the auth so it uses tokens to verify stuff after a user has logged in. It features todo creation, completion, deletion, and more! <a href="#examples-demos">Some examples below!</a>

# Getting started
Starting is as simple as 

1. Installing todoterminal: `cargo install todoterminal`
2. Running the specific commands for your platform below!

<br>

<details>
<summary>Running on windows</summary>
<br>
Setup the env file:
<pre>
echo HOST="https://api.thijmens.nl" > "%USERPROFILE%/todoterminal.env"
</pre>
Run todoterminal:
<pre>
set "CREDS=%USERPROFILE%/todoterminal.env" && todoterminal ...
</pre>
</details>
<br>
<details>
<summary>Running on Linux</summary>
<br>
Setup the env file:
<pre>
echo HOST="https://api.thijmens.nl" > "$HOME/todoterminal.env"
</pre>
Run todoterminal:
<pre>
CREDS="$HOME/todoterminal.env" todoterminal ...
</pre>
</details>

<br>

You can use todoterminal as follows: `todoterminal <command> [arguments]`, you can find a list of commands <a href="#commands">here</a>.<br>
NOTE: Not passing a "CREDS" env variable will result in todoterminal using "./.env" as the path.

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
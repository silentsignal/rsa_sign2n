# JWT Forgery Tool
This tool is designed to recover a public key from signed JWTs to facilitate a **JWT Algorithm Confusion** attack. 

It automates the process of identifying the potential public key used by the server, allowing you to re-sign tokens using the HMAC (HS256) algorithm.

You can run it using **Docker** or **UV**.

----

# Option 1: Using Docker
Best for keeping your system clean of dependencies.

## 1. Build the image

~~~bash
sudo docker compose build
~~~

## 2. Run the container 

Basic run:
~~~bash
sudo docker run --rm -it sig2n 
~~~

With volume mapping (to persist generated .pem files in your host):
~~~bash
sudo docker run --rm -it -v "$(pwd):/app" sig2n
~~~

## 3. Inside the container:
uv will handle the environment and dependencies automatically on the first run:
~~~bash
uv run jwt_forgery.py jwt_token_1 jwt_token_2
~~~

----

# Option 2: Using uv (Standalone)
Ideal for fast execution without the overhead of containers.

## 1. Prerequisites
Install uv and system dependencies:

~~~bash
curl -LsSf https://astral.sh/uv/install.sh | sh

    # source $HOME/.local/bin/env (sh, bash, zsh)
    # source $HOME/.local/bin/env.fish (fish)

sudo apt install build-essential libffi-dev libgmp-dev libmpfr-dev libmpc-dev
~~~

## 2. Usage
uv will handle the environment and dependencies automatically on the first run:
~~~bash
uv run jwt_forgery.py jwt_token_1 jwt_token_2
~~~

Cleanup: To remove all created files
~~~bash
rm -rf *.pem .venv/
~~~

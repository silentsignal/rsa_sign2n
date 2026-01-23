# Alternative Setup (uv)
If you prefer not to use Docker, this repository has been adapted to work with uv.

## Prerequisites
Install uv and system dependencies:

~~~bash
curl -LsSf https://astral.sh/uv/install.sh | sh

    # source $HOME/.local/bin/env (sh, bash, zsh)
    # source $HOME/.local/bin/env.fish (fish)

sudo apt install libffi-dev build-essential
~~~

## Installation & Usage
Simply use uv run to execute the script. It will install all dependencies in a temporary isolated environment on the first run:
~~~bash
uv run jwt_forgery.py jwt_token_1 jwt_token_2
~~~

## Cleanup
To remove generated PEM files:
~~~bash
rm *.pem
~~~

To remove all created files
~~~bash
rm -rf *.pem uv.lock .venv/
~~~
#!/bin/bash

pip3 install markdown pygments pyyaml docopt tabulate mdv requests python-dotenv
pip3 install --upgrade --force-reinstall git+http://github.com/axiros/terminal_markdown_viewer
chmod +x "$(pwd)/hackerone.py"
sudo ln -s "$(pwd)/hackerone.py" /usr/local/bin/hackerone
echo
echo "DONE!"
echo
echo "Usage: hackerone help"
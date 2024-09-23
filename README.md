# TP-OOB-Interaction
_Get OOB interactions from Interactsh and send to Discord, Telegram, Slack_

<p align="center">
    <a href="https://github.com/truocphan/TP-OOB-Interaction/releases/"><img src="https://img.shields.io/github/release/truocphan/TP-OOB-Interaction" height=30></a>
  <a href="#"><img src="https://img.shields.io/github/downloads/truocphan/TP-OOB-Interaction/total" height=30></a>
  <a href="#"><img src="https://img.shields.io/github/stars/truocphan/TP-OOB-Interaction" height=30></a>
  <a href="#"><img src="https://img.shields.io/github/forks/truocphan/TP-OOB-Interaction" height=30></a>
  <a href="https://github.com/truocphan/TP-OOB-Interaction/issues?q=is%3Aopen+is%3Aissue"><img src="https://img.shields.io/github/issues/truocphan/TP-OOB-Interaction" height=30></a>
  <a href="https://github.com/truocphan/TP-OOB-Interaction/issues?q=is%3Aissue+is%3Aclosed"><img src="https://img.shields.io/github/issues-closed/truocphan/TP-OOB-Interaction" height=30></a>
</p>

## Installation
#### From PyPI:
```console
pip install TP-OOB-Interaction
```
#### From Source:
```console
git clone https://github.com/truocphan/TP-OOB-Interaction.git --branch <Branch/Tag>
cd TP-OOB-Interaction
python setup.py build
python setup.py install
```
---

## Basic Usage
To send notifications successfully, please refer to the [sendNotify.json](https://github.com/truocphan/TP-sendNotify?tab=readme-ov-file#basic-usage) configuration file
```
> TP-OOB-Interaction --help

  _____ ____     ___   ___  ____       ___       _                      _   _
 |_   _|  _ \   / _ \ / _ \| __ )     |_ _|_ __ | |_ ___ _ __ __ _  ___| |_(_) ___  _ __
   | | | |_) | | | | | | | |  _ \ _____| || '_ \| __/ _ \ '__/ _\`|/ __| __| |/ _ \| '_ \
   | | |  __/  | |_| | |_| | |_) |_____| || | | | ||  __/ | | (_| | (__| |_| | (_) | | | |
   |_| |_|      \___/ \___/|____/     |___|_| |_|\__\___|_|  \__,_|\___|\__|_|\___/|_| |_|

                                v2024.9.23 by TP Cyber Security (@TPCyberSec)

usage: TP-OOB-Interaction [-h] [--discord-bot BOT_NAME] [--telegram-bot BOT_NAME] [--slack-bot BOT_NAME] [--update]

options:
  -h, --help            show this help message and exit
  --discord-bot BOT_NAME
                        Use the BOT "BOT_NAME" to send OOB interactions to Discord
  --telegram-bot BOT_NAME
                        Use the BOT "BOT_NAME" to send OOB interactions to Telegram
  --slack-bot BOT_NAME  Use the BOT "BOT_NAME" to send OOB interactions to Slack
  --update              Update TP-OOB-Interaction to the latest version

```

---

## CHANGELOG
#### [TP-OOB-Interaction v2024.9.23](https://github.com/truocphan/TP-OOB-Interaction/tree/2024.9.23)
- **New**:  Get OOB interactions from Interactsh and send to Discord, Telegram, Slack.
# Cyrating2TH: Cyrating case Feeder for TheHive
[Cyrating](https://www.cyrating.com/) is a commercial cyber rating company.
It allows businesses to be rated regarding their cyber exposure and compare themselves with their peers.

Cyrating2TH is a free, open source Cyrating case feeder for TheHive.
It is used to track the reputation problem and track them as case.
Because the scan occurs weekly, we choose to create directly the case and avoiding using alerts.

Cyrating2TH is written in Python 3.

## Overview
Cyrating2TH is made of several parts:

 - `config.py.template` : a configuration template which contains all the 
necessary information to connect to the APIs of Cyrating and TheHive. 
All information is required.
- `cyrating2TH.py` : the main program. It gets Cyrating reputation problem and feed them to 
TheHive with a description containing all relevant information, and observables if any.

## Prerequisites
You'll need Python 3, the `cyrating` and `arrow` libraries as well as 
[TheHive4py](https://github.com/CERT-BDF/TheHive4py), a Python client for TheHive.

Clone the repository then copy the `config.py.template` file as `config.py` 
and fill in the blanks: proxies if applicable, API keys, URLs, accounts 
pertaining to your Cyrating subscription and your instance of TheHive.

**Note**: you need a valid API subscription to the Cyrating platform as 
well as TheHive 2.13 or better and an account with the ability to create alerts.

Then install the Python requirements:

`$ pip3 install -r requirements.txt`


## Usage
Once your configuration file `config.py` is ready, use the main program to 
fetch or find Cyrating alerts:


```
./cyrating2th.py -h
usage: cyrating2th.py [-h] [-d] {alerts} ...

Retrieve Cyrating alerts and nd feed them to TheHive

positional arguments:
  {api,alerts,find}  subcommand help
    alerts           fetch reputation problem

optional arguments:
  -h, --help         show this help message and exit
  -d, --debug        generate a log file and active debug logging
```

The program has 3 options:
- `alerts` to process Cyrating reputation problems.

If you need debugging information, add the `d`switch and the program will 
create a file called `cyrating2th.log`. It will be created in the same folder as the 
main program.

### Get the API key
The first step consist of retrieving the Cyrating API key associated with your
 account.

Now update your `config.py` file with the `key`.


### Retrieve alerts specified by their ID

```
./cyrating2th.py alerts -h
usage: cyrating2th.py alerts [-h]

optional arguments:
  -h, --help  show this help message and exit
```

- `./cyrating2th.py alerts` : fetch alerts .


### Use cases

- Add a cron job to check for newly published reputation problem every week:

```
0 8 * * 1 /opt/Cyrating2TH/cyrating2th.py alerts >/dev/null 2>&1
```

When enabled, logs are written in the program's folder, in a file named `cyrating2th.log`.

# License
Cyrating2TH is an open source and free software released under the 
[AGPL](LICENSE) 
(Affero General Public License). We are committed to ensure
that Cyrating2TH will remain a free and open source project on the 
long-run.


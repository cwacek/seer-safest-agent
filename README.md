# SEER SAFEST Agent #

This is designed to be an agent that facilitates running a modified version of Tor on DETER.

## Setting up an experiment ## 

Configure the topology however you want. Include a standalone node called 'control'. If you are going to use ExperimentRunner, then you 
should name relays 'router#', clients 'client#', and directory servers 'directory#', where
'#' is an index for each type of node.

The start command for each node should be set to:

    sudo python /share/seer/v160/experiment-setup.py Basic -d <path to this repository>/agent TorAgent -d <path to this repository>/agent SockHTTPAgent -d <path to this repository>/agent SocksAppAgent LogReader LogProcessor

Log into *control.<exp_name>.<group_name>*. Copy your modified Tor binary locally, and compile it. Then copy just the compiled binary to somewhere on the NFS share (/groups is a good place to start). 

### Running an experiment ###
This can be done one of two ways. Either use [the SEER GUI](http://seer.deterlab.net/v1.6/user/howto.html#running-the-experiment-and-the-seer-software), or the provided ExperimentRunner script.

When using the SEER GUI, simply create a control group for the tor relays, and start relays using it. Clients must be started separately, which the SocksAgent groups can do. 

When using ExperimentRunner, create an experiment configuration file. See experiment.config for an example. Then run code(python ExperimentRunner.py), and enter '?' at the prompt to see options.


